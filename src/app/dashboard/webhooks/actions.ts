'use server';

import { randomBytes } from 'crypto';
import { revalidatePath } from 'next/cache';
import { requireMerchant } from '@/lib/dashboard/queries';
import { createSupabaseAdminClient } from '@/lib/supabase/server';

const MAX_WEBHOOKS = 5;

export async function addWebhook(args: { url: string; events: string[]; mode: 'test' | 'live' | 'both' }): Promise<{ ok: boolean; secret?: string; error?: string }> {
  const { merchant } = await requireMerchant();
  const cleanUrl = (args.url ?? '').trim();
  if (!cleanUrl.match(/^https?:\/\//)) {
    return { ok: false, error: `URL must start with http(s):// — got: "${cleanUrl}" (length ${cleanUrl.length})` };
  }
  if (!['test', 'live', 'both'].includes(args.mode)) {
    return { ok: false, error: 'Scope invalide' };
  }
  const admin = createSupabaseAdminClient();
  const { count } = await admin.from('webhooks').select('*', { count: 'exact', head: true })
    .eq('merchant_id', merchant.id);
  if ((count ?? 0) >= MAX_WEBHOOKS) return { ok: false, error: `Max ${MAX_WEBHOOKS} webhooks per merchant.` };
  const secret = `whsec_${randomBytes(24).toString('hex')}`;
  const { error } = await admin.from('webhooks').insert({
    merchant_id: merchant.id,
    url: cleanUrl,
    secret,
    events: args.events.length > 0 ? args.events : ['payment.succeeded', 'payment.expired', 'payment.cancelled'],
    enabled: true,
    mode: args.mode,
  });
  if (error) return { ok: false, error: error.message };
  // NOTE: do NOT revalidatePath here — it would remount AddWebhookButton
  // and clear the showSecret state. The client calls router.refresh() on close.
  return { ok: true, secret };
}

export async function toggleWebhook(id: string, enabled: boolean) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  await admin.from('webhooks').update({ enabled }).eq('id', id).eq('merchant_id', merchant.id);
  revalidatePath('/dashboard/webhooks');
}

export async function deleteWebhook(id: string) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  await admin.from('webhooks').delete().eq('id', id).eq('merchant_id', merchant.id);
  revalidatePath('/dashboard/webhooks');
}

export async function fireTestWebhook(id: string) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  await admin.from('webhook_deliveries').insert({
    webhook_id: id,
    merchant_id: merchant.id,
    event_type: 'webhook.test',
    payload: {
      id: `evt_test_${randomBytes(8).toString('hex')}`,
      type: 'webhook.test',
      created: Math.floor(Date.now() / 1000),
      livemode: false,
      data: { object: { ref: 'KP-TESTXX', amount: 1, status: 'paid', mode: 'test' } },
    },
    status: 'pending',
    next_retry_at: new Date().toISOString(),
  });
}

export async function retryDelivery(deliveryId: string) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  await admin.from('webhook_deliveries').update({
    status: 'pending', next_retry_at: new Date().toISOString(), attempt: 1,
  }).eq('id', deliveryId).eq('merchant_id', merchant.id);
  revalidatePath('/dashboard/webhooks');
}
