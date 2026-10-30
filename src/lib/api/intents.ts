import { randomBytes } from 'crypto';

// 10 chars from base64url, stripped of -/_, uppercased, retried if shorter than 10.
// ~59 bits of entropy — matches the implementation in src/lib/format.ts.
export function generateRef(): string {
  let rand = '';
  while (rand.length < 10) {
    rand += randomBytes(8).toString('base64url').replace(/[-_]/g, '').toUpperCase();
  }
  return 'KP-' + rand.slice(0, 10);
}

export function generateClientSecret(): string {
  return `kpcs_${randomBytes(16).toString('hex')}`;
}

export const VALID_METHODS = ['Bankily', 'Masrvi', 'Sedad', 'BIM', 'Click', 'BCIPAY'] as const;
export type Method = typeof VALID_METHODS[number];

export type IntentInput = {
  amount: number;
  method: Method;
  merchant_operator_id?: string;
  customer_phone?: string;
  description?: string;
  success_url?: string;
  cancel_url?: string;
  metadata?: Record<string, unknown>;
  expires_in?: number;
};

export type IntentRecord = {
  ref: string;
  merchant_id: string;
  amount: number;
  method: string;
  status: string;
  mode: string;
  matched_tier: number | null;
  expected_phone: string | null;
  customer_phone: string | null;
  description: string | null;
  success_url: string | null;
  cancel_url: string | null;
  metadata: Record<string, unknown> | null;
  created_at: string;
  expires_at: string;
  paid_at: string | null;
  client_secret: string;
  merchant_operator_id: string | null;
  sms_received?: string | null;
};

export function serializeIntent(
  row: IntentRecord,
  merchantPhone: string | null,
  merchantCode: string | null,
  origin: string,
  exposeSms = false
) {
  return {
    ref: row.ref,
    amount: row.amount,
    method: row.method,
    status: row.status,
    mode: row.mode,
    matched_tier: row.matched_tier,
    merchant_phone: merchantPhone,
    merchant_code: merchantCode,
    customer_phone: row.customer_phone,
    description: row.description,
    success_url: row.success_url,
    cancel_url: row.cancel_url,
    metadata: row.metadata ?? {},
    expires_at: row.expires_at,
    paid_at: row.paid_at,
    hosted_url: `${origin}/pay/${row.ref}`,
    client_secret: row.client_secret,
    created_at: row.created_at,
    ...(exposeSms ? { sms_received: row.sms_received ?? null } : {}),
  };
}

export function validateInput(body: Partial<IntentInput>): { ok: true; input: IntentInput } | { ok: false; code: string; message: string; param?: string } {
  if (!body.amount || typeof body.amount !== 'number' || !Number.isInteger(body.amount)) {
    return { ok: false, code: 'missing_param', message: '`amount` is required (positive integer in MRU)', param: 'amount' };
  }
  if (body.amount < 1) {
    return { ok: false, code: 'amount_too_low', message: 'Amount must be >= 1 MRU', param: 'amount' };
  }
  if (body.amount > 1_000_000) {
    return { ok: false, code: 'amount_too_high', message: 'Amount must be <= 1,000,000 MRU', param: 'amount' };
  }
  if (!body.method || !VALID_METHODS.includes(body.method as Method)) {
    return { ok: false, code: 'unknown_method', message: `\`method\` must be one of: ${VALID_METHODS.join(', ')}`, param: 'method' };
  }
  if (body.success_url && !isHttpsUrl(body.success_url, true)) {
    return { ok: false, code: 'invalid_url', message: '`success_url` must be a valid http(s) URL', param: 'success_url' };
  }
  if (body.cancel_url && !isHttpsUrl(body.cancel_url, true)) {
    return { ok: false, code: 'invalid_url', message: '`cancel_url` must be a valid http(s) URL', param: 'cancel_url' };
  }
  if (body.expires_in && (typeof body.expires_in !== 'number' || body.expires_in < 60 || body.expires_in > 3600)) {
    return { ok: false, code: 'invalid_param', message: '`expires_in` must be between 60 and 3600 seconds', param: 'expires_in' };
  }
  return {
    ok: true,
    input: {
      amount: body.amount,
      method: body.method as Method,
      merchant_operator_id: body.merchant_operator_id,
      customer_phone: body.customer_phone,
      description: body.description,
      success_url: body.success_url,
      cancel_url: body.cancel_url,
      metadata: body.metadata,
      expires_in: body.expires_in,
    },
  };
}

function isHttpsUrl(s: string, allowHttp = false): boolean {
  try {
    const u = new URL(s);
    return u.protocol === 'https:' || (allowHttp && u.protocol === 'http:');
  } catch {
    return false;
  }
}
