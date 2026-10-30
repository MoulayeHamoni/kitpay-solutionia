import { NextRequest, NextResponse } from 'next/server';
import { promises as dns } from 'dns';
import { isIP, isIPv4 } from 'net';
import { supabaseAdmin } from '@/lib/supabase';
import { computeSignature } from '@/lib/hmac';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Retry schedule (in seconds) between attempts. After the last one, the
// delivery is marked 'failed' and never retried automatically. A merchant
// can still trigger a manual retry from the dashboard.
const RETRY_SCHEDULE_SECONDS = [60, 300, 1800, 7200, 43200]; // 1m, 5m, 30m, 2h, 12h
const MAX_ATTEMPTS = RETRY_SCHEDULE_SECONDS.length;
const BATCH_SIZE = 50;
const REQUEST_TIMEOUT_MS = 10_000;

// Reject IPs that belong to private, loopback, link-local, multicast, or
// CGNAT ranges. Any IP that fails isIP() is also treated as private to fail
// closed on unexpected input.
function ipIsPrivate(ip: string): boolean {
  if (!isIP(ip)) return true;
  if (isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT — some clouds route metadata here
    if (a === 0) return true;
    if (a >= 224) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::' || lower === '::0') return true;
  if (lower.startsWith('fe80:')) return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('ff')) return true;
  if (lower.startsWith('::ffff:')) return ipIsPrivate(lower.slice(7));
  return false;
}

type UrlCheckOk = { ok: true; url: string; headers: Record<string, string> };
type UrlCheckFail = { ok: false; reason: string };

// Resolves the hostname and pins the fetch URL to a concrete public IP (http only).
// This defeats two SSRF vectors:
//   1. Redirect chain: we pass redirect:'manual' to fetch, so 3xx never followed.
//   2. DNS rebinding: for http we substitute the resolved IP so the OS does not
//      re-resolve on the actual TCP connect (which could return a private IP).
//
// For https we cannot substitute the IP because doing so would break TLS: the
// certificate is validated against the hostname, not the IP. Instead we pass the
// original URL with redirect:'manual'. DNS rebinding on https also requires the
// attacker to hold a valid TLS certificate for the private target host — a much
// higher bar. If that threat model ever needs addressing, an egress proxy with
// a fixed allow-list is the right control, not application-layer DNS pinning.
async function resolveAndPinUrl(rawUrl: string): Promise<UrlCheckOk | UrlCheckFail> {
  let u: URL;
  try { u = new URL(rawUrl); } catch { return { ok: false, reason: 'invalid_url' }; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { ok: false, reason: 'bad_protocol' };
  const host = u.hostname;
  if (!host) return { ok: false, reason: 'no_host' };

  // Literal IP in URL — validate directly without DNS.
  if (isIP(host)) {
    if (ipIsPrivate(host)) return { ok: false, reason: 'private_ip' };
    return { ok: true, url: rawUrl, headers: {} };
  }

  const lower = host.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower.endsWith('.internal') || lower.endsWith('.local')) {
    return { ok: false, reason: 'local_hostname' };
  }

  let records: import('dns').LookupAddress[];
  try {
    records = await dns.lookup(host, { all: true, verbatim: true });
  } catch {
    return { ok: false, reason: 'dns_failed' };
  }

  const publicIps = records.filter((r) => !ipIsPrivate(r.address));
  if (publicIps.length === 0) return { ok: false, reason: 'no_public_ip' };
  // Reject split-horizon configs where some records are private — could indicate
  // a partial DNS rebinding setup.
  if (publicIps.length < records.length) return { ok: false, reason: 'mixed_private_public_ips' };

  if (u.protocol === 'http:') {
    // Pin to first resolved public IP so Node does not re-resolve on connect.
    const ip = publicIps[0].address;
    const pinned = new URL(rawUrl);
    pinned.hostname = publicIps[0].family === 6 ? `[${ip}]` : ip;
    // Preserve original Host header so the target server routes the vhost correctly.
    return { ok: true, url: pinned.toString(), headers: { Host: host } };
  }

  // https: use original URL; TLS cert validation against hostname provides rebinding resistance.
  return { ok: true, url: rawUrl, headers: {} };
}

type PendingDelivery = {
  id: string;
  webhook_id: string;
  merchant_id: string;
  event_type: string;
  payload: unknown;
  attempt: number;
  webhooks: { url: string; secret: string; enabled: boolean } | null;
};

async function postWithTimeout(
  url: string,
  body: string,
  signature: string,
  extraHeaders: Record<string, string>
) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-KitPay-Signature': signature,
        'User-Agent': 'KitPay-Webhook/1.0',
        ...extraHeaders,
      },
      body,
      signal: controller.signal,
      redirect: 'manual', // never follow redirects — 3xx is a hard failure
    });
    // fetch with redirect:'manual' returns an opaque redirect response (type
    // 'opaqueredirect', status 0) for 3xx on cross-origin requests. On same-
    // origin or in some Node runtimes it may still return the 3xx status code
    // directly. Handle both.
    if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
      const location = res.headers.get('location') ?? '<unknown>';
      return { httpStatus: 0, responseBody: `redirect_blocked: ${location}`.slice(0, 2000) };
    }
    const text = await res.text().catch(() => '');
    return { httpStatus: res.status, responseBody: text.slice(0, 2000) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { httpStatus: 0, responseBody: `network_error: ${message}`.slice(0, 2000) };
  } finally {
    clearTimeout(timer);
  }
}

async function handle(req: NextRequest) {
  const secret =
    req.headers.get('x-cron-secret') ??
    new URL(req.url).searchParams.get('secret');
  if (!process.env.CRON_SECRET || secret !== process.env.CRON_SECRET) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  const sb = supabaseAdmin();

  const { data: rows, error } = await sb
    .from('webhook_deliveries')
    .select(
      'id, webhook_id, merchant_id, event_type, payload, attempt, webhooks!inner(url, secret, enabled)'
    )
    .eq('status', 'pending')
    .lte('next_retry_at', new Date().toISOString())
    .order('created_at', { ascending: true })
    .limit(BATCH_SIZE);

  if (error) {
    console.error('[deliver-webhooks] fetch error', error);
    return NextResponse.json({ error: 'fetch_failed' }, { status: 500 });
  }

  const deliveries = (rows ?? []) as unknown as PendingDelivery[];
  if (deliveries.length === 0) {
    return NextResponse.json({ ok: true, processed: 0 });
  }

  let delivered = 0;
  let retried = 0;
  let failed = 0;
  let skipped = 0;

  for (const d of deliveries) {
    const w = d.webhooks;
    if (!w || !w.enabled) {
      await sb
        .from('webhook_deliveries')
        .update({
          status: 'failed',
          response_body: 'webhook disabled or missing',
          delivered_at: new Date().toISOString(),
        })
        .eq('id', d.id);
      skipped++;
      continue;
    }

    const urlCheck = await resolveAndPinUrl(w.url);
    if (!urlCheck.ok) {
      await sb
        .from('webhook_deliveries')
        .update({
          status: 'failed',
          response_body: `url_rejected: ${urlCheck.reason}`,
          delivered_at: new Date().toISOString(),
        })
        .eq('id', d.id);
      skipped++;
      continue;
    }

    const body = JSON.stringify(d.payload);
    const signature = computeSignature(w.secret, body);
    const { httpStatus, responseBody } = await postWithTimeout(urlCheck.url, body, signature, urlCheck.headers);
    const success = httpStatus >= 200 && httpStatus < 300;

    if (success) {
      await sb
        .from('webhook_deliveries')
        .update({
          status: 'delivered',
          http_status: httpStatus,
          response_body: responseBody,
          delivered_at: new Date().toISOString(),
        })
        .eq('id', d.id);
      await sb
        .from('webhooks')
        .update({ last_delivered_at: new Date().toISOString(), failure_count: 0 })
        .eq('id', d.webhook_id);
      delivered++;
      continue;
    }

    const nextAttempt = d.attempt + 1;
    if (nextAttempt > MAX_ATTEMPTS) {
      await sb
        .from('webhook_deliveries')
        .update({
          status: 'failed',
          attempt: d.attempt,
          http_status: httpStatus,
          response_body: responseBody,
          delivered_at: new Date().toISOString(),
        })
        .eq('id', d.id);
      await sb
        .from('webhooks')
        .update({ last_failed_at: new Date().toISOString(), failure_count: nextAttempt })
        .eq('id', d.webhook_id);
      failed++;
      continue;
    }

    const delaySec = RETRY_SCHEDULE_SECONDS[nextAttempt - 1];
    const nextRetryAt = new Date(Date.now() + delaySec * 1000).toISOString();
    await sb
      .from('webhook_deliveries')
      .update({
        attempt: nextAttempt,
        next_retry_at: nextRetryAt,
        http_status: httpStatus,
        response_body: responseBody,
      })
      .eq('id', d.id);
    await sb
      .from('webhooks')
      .update({ last_failed_at: new Date().toISOString(), failure_count: nextAttempt })
      .eq('id', d.webhook_id);
    retried++;
  }

  return NextResponse.json({
    ok: true,
    processed: deliveries.length,
    delivered,
    retried,
    failed,
    skipped,
  });
}

export async function GET(req: NextRequest) {
  return handle(req);
}

export async function POST(req: NextRequest) {
  return handle(req);
}
