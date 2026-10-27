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

// Reject merchant URLs that resolve to private networks or metadata endpoints.
// Without this, a merchant can configure http://169.254.169.254/... as their
// webhook URL and the delivery worker would reach the cloud metadata service.
function ipIsPrivate(ip: string): boolean {
  if (!isIP(ip)) return true;
  if (isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
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

async function assertPublicUrl(rawUrl: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  let u: URL;
  try { u = new URL(rawUrl); } catch { return { ok: false, reason: 'invalid_url' }; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { ok: false, reason: 'bad_protocol' };
  const host = u.hostname;
  if (!host) return { ok: false, reason: 'no_host' };
  if (isIP(host)) {
    return ipIsPrivate(host) ? { ok: false, reason: 'private_ip' } : { ok: true };
  }
  const lower = host.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower.endsWith('.internal') || lower.endsWith('.local')) {
    return { ok: false, reason: 'local_hostname' };
  }
  try {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    for (const r of records) {
      if (ipIsPrivate(r.address)) return { ok: false, reason: `private_ip_resolved:${r.address}` };
    }
  } catch {
    return { ok: false, reason: 'dns_failed' };
  }
  return { ok: true };
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

async function postWithTimeout(url: string, body: string, signature: string) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-KitPay-Signature': signature,
        'User-Agent': 'KitPay-Webhook/1.0',
      },
      body,
      signal: controller.signal,
    });
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

    const urlCheck = await assertPublicUrl(w.url);
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
    const { httpStatus, responseBody } = await postWithTimeout(w.url, body, signature);
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
