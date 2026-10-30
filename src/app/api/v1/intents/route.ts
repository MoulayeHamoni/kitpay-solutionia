import { NextRequest, NextResponse } from 'next/server';
import { createSupabaseAdminClient } from '@/lib/supabase/server';
import { authenticateApi, ensureKycForLive } from '@/lib/api/auth';
import { hashBody, lookupIdempotency, saveIdempotency } from '@/lib/api/idempotency';
import { checkRateLimit } from '@/lib/api/rate-limit';
import { logApiCall } from '@/lib/api/audit';
import { generateRef, generateClientSecret, validateInput, serializeIntent, type IntentRecord } from '@/lib/api/intents';
import { canonicalMauritanianPhone } from '@/lib/phone';
import {
  errBadRequest, errUnauthorized, errForbidden, errConflict, errUnprocessable,
  errRateLimit, errInternal, errorResponse,
} from '@/lib/api/errors';

export async function POST(request: NextRequest) {
  const auth = await authenticateApi(request);
  if (!auth.ok) {
    logApiCall({ request, merchantId: null, apiKeyId: null, endpoint: '/v1/intents', method: 'POST', statusCode: 401 });
    return errUnauthorized();
  }
  const ctx = auth.ctx;

  // KYC gate for live mode
  const kyc = await ensureKycForLive(ctx);
  if (!kyc.ok) {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 403 });
    return errForbidden('kyc_required', 'Live mode requires KYC validation. Use kp_test_ keys until your KYC is approved.');
  }

  // Rate limit
  const rl = await checkRateLimit(ctx.apiKeyId, ctx.merchantId, ctx.mode);
  if (!rl.ok) {
    if (rl.serviceError) {
      logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 503 });
      return errInternal('rate_limit_unavailable');
    }
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 429 });
    return errRateLimit(rl.resetIn);
  }

  // Read body once (we hash it for idempotency)
  const rawBody = await request.text();
  let body: Record<string, unknown> = {};
  try {
    body = rawBody.trim() ? JSON.parse(rawBody) : {};
  } catch {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 400, body: rawBody });
    return errBadRequest('invalid_param', 'Body must be valid JSON');
  }

  // Idempotency
  const idemKey = request.headers.get('idempotency-key');
  if (idemKey) {
    const bh = hashBody(rawBody);
    const lookup = await lookupIdempotency(ctx.merchantId, idemKey, bh);
    if (lookup.kind === 'conflict') {
      logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 409, body: rawBody });
      return errConflict('idempotency_conflict', 'Idempotency-Key was reused with a different body');
    }
    if (lookup.kind === 'hit') {
      logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: lookup.payload.status });
      return NextResponse.json(lookup.payload.body, { status: lookup.payload.status });
    }
  }

  // Validate input
  const valid = validateInput(body);
  if (!valid.ok) {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 422, body: rawBody });
    return errUnprocessable(valid.code as any, valid.message, valid.param);
  }
  const input = valid.input;

  const admin = createSupabaseAdminClient();

  // Resolve merchant_operator_id
  let operatorId = input.merchant_operator_id ?? null;
  let operatorPhone: string | null = null;
  let operatorCode: string | null = null;
  if (operatorId) {
    const { data } = await admin
      .from('merchant_operators')
      .select('id, expected_phone, merchant_code, method, enabled')
      .eq('id', operatorId)
      .eq('merchant_id', ctx.merchantId)
      .maybeSingle();
    if (!data || !data.enabled || data.method !== input.method) {
      logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 422, body: rawBody });
      return errUnprocessable('invalid_param', `merchant_operator_id is invalid or does not match method ${input.method}`, 'merchant_operator_id');
    }
    operatorPhone = data.expected_phone;
    operatorCode = data.merchant_code ?? null;
  } else {
    const { data: ops } = await admin
      .from('merchant_operators')
      .select('id, expected_phone, merchant_code')
      .eq('merchant_id', ctx.merchantId)
      .eq('method', input.method)
      .eq('enabled', true);
    if (!ops || ops.length === 0) {
      logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 422, body: rawBody });
      return errUnprocessable('no_operator_for_method', `No active operator configured for method ${input.method}. Add one in your dashboard.`, 'method');
    }
    if (ops.length > 1) {
      logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 422, body: rawBody });
      return errUnprocessable('multiple_operators_specify_id', `Multiple operators configured for ${input.method}. Specify merchant_operator_id.`);
    }
    operatorId = ops[0].id;
    operatorPhone = ops[0].expected_phone;
    operatorCode = ops[0].merchant_code ?? null;
  }

  const ref = generateRef();
  const clientSecret = generateClientSecret();
  const expiresIn = input.expires_in ?? 900;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresIn * 1000);

  // Insert
  const { data: insertedRow, error: insertErr } = await admin
    .from('payment_intents')
    .insert({
      ref,
      merchant_id: ctx.merchantId,
      amount: input.amount,
      method: input.method,
      mode: ctx.mode,
      status: 'pending',
      expected_phone: input.customer_phone ? canonicalMauritanianPhone(input.customer_phone) : (operatorPhone ?? ''),
      customer_phone: input.customer_phone ? canonicalMauritanianPhone(input.customer_phone) : null,
      description: input.description ?? null,
      success_url: input.success_url ?? null,
      cancel_url: input.cancel_url ?? null,
      metadata: input.metadata ?? {},
      product_id: 'api',
      product_name: input.description ?? 'API intent',
      expires_at: expiresAt.toISOString(),
      idempotency_key: idemKey ?? null,
      merchant_operator_id: operatorId,
      client_secret: clientSecret,
    })
    .select('*')
    .single();

  if (insertErr || !insertedRow) {
    console.error('[v1/intents POST] insert failed', insertErr);
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 500, body: rawBody });
    return errInternal();
  }

  const origin = new URL(request.url).origin;
  const responseBody = serializeIntent(insertedRow as IntentRecord, operatorPhone, operatorCode, origin, ctx.mode === 'test');

  // Save idempotency
  if (idemKey) {
    await saveIdempotency(ctx.merchantId, idemKey, hashBody(rawBody), 201, responseBody);
  }

  logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'POST', statusCode: 201, body: rawBody });

  const res = NextResponse.json(responseBody, { status: 201 });
  res.headers.set('X-RateLimit-Limit', String(rl.limit));
  res.headers.set('X-RateLimit-Remaining', String(rl.remaining));
  res.headers.set('X-RateLimit-Reset', String(rl.resetIn));
  return res;
}

export async function GET(request: NextRequest) {
  const auth = await authenticateApi(request);
  if (!auth.ok) return errUnauthorized();
  const ctx = auth.ctx;

  const rl = await checkRateLimit(ctx.apiKeyId, ctx.merchantId, ctx.mode);
  if (!rl.ok) return rl.serviceError ? errInternal('rate_limit_unavailable') : errRateLimit(rl.resetIn);

  const sp = new URL(request.url).searchParams;
  const limit = Math.min(100, Math.max(1, parseInt(sp.get('limit') ?? '25', 10)));
  const status = sp.get('status');
  const method = sp.get('method');
  const startingAfter = sp.get('starting_after');

  const admin = createSupabaseAdminClient();

  let query = admin
    .from('payment_intents')
    .select('*')
    .eq('merchant_id', ctx.merchantId)
    .eq('mode', ctx.mode)
    .order('created_at', { ascending: false })
    .limit(limit + 1);

  if (status) query = query.eq('status', status);
  if (method) query = query.eq('method', method);
  if (startingAfter) {
    const { data: cursor } = await admin
      .from('payment_intents')
      .select('created_at')
      .eq('ref', startingAfter)
      .eq('merchant_id', ctx.merchantId)
      .maybeSingle();
    if (cursor?.created_at) {
      query = query.lt('created_at', cursor.created_at);
    }
  }

  const { data, error } = await query;
  if (error) return errInternal();

  const rows = data ?? [];
  const hasMore = rows.length > limit;
  const slice = rows.slice(0, limit) as IntentRecord[];
  const origin = new URL(request.url).origin;

  // Resolve merchant phones and codes in batch
  const opIds = slice.map(r => r.merchant_operator_id).filter(Boolean) as string[];
  const phoneMap = new Map<string, string>();
  const codeMap = new Map<string, string | null>();
  if (opIds.length > 0) {
    const { data: ops } = await admin
      .from('merchant_operators')
      .select('id, expected_phone, merchant_code')
      .in('id', opIds);
    (ops ?? []).forEach(o => {
      phoneMap.set(o.id, o.expected_phone);
      codeMap.set(o.id, o.merchant_code ?? null);
    });
  }

  const list = slice.map(r => serializeIntent(
    r,
    phoneMap.get(r.merchant_operator_id ?? '') ?? null,
    codeMap.get(r.merchant_operator_id ?? '') ?? null,
    origin,
    ctx.mode === 'test'
  ));

  logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: '/v1/intents', method: 'GET', statusCode: 200 });

  const res = NextResponse.json({
    data: list,
    has_more: hasMore,
    next_cursor: hasMore ? slice[slice.length - 1].ref : null,
  });
  res.headers.set('X-RateLimit-Limit', String(rl.limit));
  res.headers.set('X-RateLimit-Remaining', String(rl.remaining));
  return res;
}
