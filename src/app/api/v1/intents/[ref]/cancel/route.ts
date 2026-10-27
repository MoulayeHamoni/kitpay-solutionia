import { NextRequest, NextResponse } from 'next/server';
import * as crypto from 'crypto';
import { createSupabaseAdminClient } from '@/lib/supabase/server';
import { authenticateApi } from '@/lib/api/auth';
import { checkRateLimit } from '@/lib/api/rate-limit';
import { logApiCall } from '@/lib/api/audit';
import { serializeIntent, type IntentRecord } from '@/lib/api/intents';
import { errUnauthorized, errNotFound, errConflict, errRateLimit, errInternal } from '@/lib/api/errors';

export async function POST(request: NextRequest, { params }: { params: { ref: string } }) {
  const auth = await authenticateApi(request);
  if (!auth.ok) return errUnauthorized();
  const ctx = auth.ctx;

  const rl = await checkRateLimit(ctx.apiKeyId, ctx.merchantId, ctx.mode);
  if (!rl.ok) return rl.serviceError ? errInternal('rate_limit_unavailable') : errRateLimit(rl.resetIn);

  const admin = createSupabaseAdminClient();
  const { data: existing } = await admin
    .from('payment_intents')
    .select('*')
    .eq('ref', params.ref)
    .eq('merchant_id', ctx.merchantId)
    .eq('mode', ctx.mode)
    .maybeSingle();

  if (!existing) {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: `/v1/intents/${params.ref}/cancel`, method: 'POST', statusCode: 404 });
    return errNotFound('Intent');
  }

  if (existing.status !== 'pending') {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: `/v1/intents/${params.ref}/cancel`, method: 'POST', statusCode: 409 });
    return errConflict('intent_not_pending', `Intent is in status \`${existing.status}\` and cannot be cancelled.`);
  }

  const { data: updated, error: updateErr } = await admin
    .from('payment_intents')
    .update({ status: 'cancelled' })
    .eq('ref', params.ref)
    .eq('merchant_id', ctx.merchantId)
    .eq('mode', ctx.mode)
    .eq('status', 'pending')
    .select('*')
    .single();

  if (updateErr || !updated) {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: `/v1/intents/${params.ref}/cancel`, method: 'POST', statusCode: 500 });
    return errInternal();
  }

  let phone: string | null = null;
  if (updated.merchant_operator_id) {
    const { data: op } = await admin
      .from('merchant_operators')
      .select('expected_phone')
      .eq('id', updated.merchant_operator_id)
      .maybeSingle();
    phone = op?.expected_phone ?? null;
  }

  const origin = new URL(request.url).origin;
  const body = serializeIntent(updated as IntentRecord, phone, null, origin, ctx.mode === 'test');

  // Enqueue webhook
  await admin.rpc('enqueue_webhook_delivery', {
    p_merchant_id: ctx.merchantId,
    p_event_type: 'payment.cancelled',
    p_payload: {
      id: `evt_${crypto.randomBytes(12).toString('hex')}`,
      type: 'payment.cancelled',
      created: Math.floor(Date.now() / 1000),
      livemode: updated.mode === 'live',
      data: { object: body },
    },
  });

  logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: `/v1/intents/${params.ref}/cancel`, method: 'POST', statusCode: 200 });
  return NextResponse.json(body);
}
