'use server';

import { revalidatePath } from 'next/cache';
import { requireMerchant } from '@/lib/dashboard/queries';
import { createSupabaseAdminClient } from '@/lib/supabase/server';

export async function cancelIntent(ref: string) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  const { error } = await admin
    .from('payment_intents')
    .update({ status: 'cancelled' })
    .eq('ref', ref).eq('merchant_id', merchant.id).eq('status', 'pending');
  if (error) return { ok: false, error: error.message };
  revalidatePath(`/dashboard/intents/${ref}`);
  return { ok: true };
}

export async function replayWebhooks(ref: string) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  const { data: failed } = await admin
    .from('webhook_deliveries_safe')
    .select('id')
    .eq('merchant_id', merchant.id)
    .in('status', ['failed', 'expired']);
  if (!failed || failed.length === 0) return { ok: true, replayed: 0 };
  const { error } = await admin
    .from('webhook_deliveries')
    .update({ status: 'pending', next_retry_at: new Date().toISOString(), attempt: 1 })
    .in('id', failed.map(f => f.id));
  if (error) return { ok: false, error: error.message };
  return { ok: true, replayed: failed.length };
}
