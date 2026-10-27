import { NextRequest, NextResponse } from 'next/server';
import { createSupabaseAdminClient } from '@/lib/supabase/server';
import { authenticateApi } from '@/lib/api/auth';
import { checkRateLimit } from '@/lib/api/rate-limit';
import { logApiCall } from '@/lib/api/audit';
import { serializeIntent, type IntentRecord } from '@/lib/api/intents';
import { errUnauthorized, errNotFound, errRateLimit, errInternal } from '@/lib/api/errors';

export async function GET(request: NextRequest, { params }: { params: { ref: string } }) {
  const auth = await authenticateApi(request);
  if (!auth.ok) return errUnauthorized();
  const ctx = auth.ctx;

  const rl = await checkRateLimit(ctx.apiKeyId, ctx.merchantId, ctx.mode);
  if (!rl.ok) return rl.serviceError ? errInternal('rate_limit_unavailable') : errRateLimit(rl.resetIn);

  const admin = createSupabaseAdminClient();
  const { data, error } = await admin
    .from('payment_intents')
    .select('*')
    .eq('ref', params.ref)
    .eq('merchant_id', ctx.merchantId)
    .eq('mode', ctx.mode)
    .maybeSingle();

  if (error) {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: `/v1/intents/${params.ref}`, method: 'GET', statusCode: 500 });
    return errInternal();
  }
  if (!data) {
    logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: `/v1/intents/${params.ref}`, method: 'GET', statusCode: 404 });
    return errNotFound('Intent');
  }

  // Resolve merchant operator phone and code for serialization
  let phone: string | null = null;
  let code: string | null = null;
  if (data.merchant_operator_id) {
    const { data: op } = await admin
      .from('merchant_operators')
      .select('expected_phone, merchant_code')
      .eq('id', data.merchant_operator_id)
      .maybeSingle();
    phone = op?.expected_phone ?? null;
    code = op?.merchant_code ?? null;
  }

  const origin = new URL(request.url).origin;
  const body = serializeIntent(data as IntentRecord, phone, code, origin, ctx.mode === 'test');

  logApiCall({ request, merchantId: ctx.merchantId, apiKeyId: ctx.apiKeyId, endpoint: `/v1/intents/${params.ref}`, method: 'GET', statusCode: 200 });
  return NextResponse.json(body);
}
