'use server';

import { revalidatePath } from 'next/cache';
import { requireMerchant } from '@/lib/dashboard/queries';
import { createSupabaseAdminClient } from '@/lib/supabase/server';
import { generateForwarderToken, hashForwarderToken } from '@/lib/forwarders';

const MAX_DEVICES = 5;

export async function createForwarderDevice(args: { label: string }): Promise<
  { ok: true; token: string } | { ok: false; error: string }
> {
  const { merchant, user } = await requireMerchant();
  const label = (args.label ?? '').trim();
  if (label.length < 2 || label.length > 60) {
    return { ok: false, error: 'Label requis (2-60 caracteres)' };
  }
  const admin = createSupabaseAdminClient();

  const { count } = await admin.from('forwarder_devices')
    .select('*', { count: 'exact', head: true })
    .eq('merchant_id', merchant.id)
    .is('revoked_at', null);
  if ((count ?? 0) >= MAX_DEVICES) {
    return { ok: false, error: `Max ${MAX_DEVICES} devices actifs par marchand` };
  }

  const token = generateForwarderToken();
  const tokenHash = hashForwarderToken(token);
  const { error } = await admin.from('forwarder_devices').insert({
    merchant_id: merchant.id,
    label,
    token_hash: tokenHash,
    enabled: true,
    created_by: user.id,
  });
  if (error) return { ok: false, error: error.message };

  // NOTE: do NOT revalidatePath here - the client component shows the plaintext
  // token once and then calls router.refresh() on close. Match the webhook UX.
  return { ok: true, token };
}

export async function rotateForwarderDevice(id: string): Promise<
  { ok: true; token: string } | { ok: false; error: string }
> {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();

  const token = generateForwarderToken();
  const tokenHash = hashForwarderToken(token);

  const { error } = await admin.from('forwarder_devices')
    .update({ token_hash: tokenHash, enabled: true, revoked_at: null, last_seen_at: null })
    .eq('id', id)
    .eq('merchant_id', merchant.id);
  if (error) return { ok: false, error: error.message };
  // Same note as createForwarderDevice: skip revalidatePath so the client can display the token.
  return { ok: true, token };
}

export async function revokeForwarderDevice(id: string) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  await admin.from('forwarder_devices')
    .update({ enabled: false, revoked_at: new Date().toISOString() })
    .eq('id', id)
    .eq('merchant_id', merchant.id);
  revalidatePath('/dashboard/forwarders');
}

export async function toggleForwarderDevice(id: string, enabled: boolean) {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  await admin.from('forwarder_devices')
    .update({ enabled })
    .eq('id', id)
    .eq('merchant_id', merchant.id);
  revalidatePath('/dashboard/forwarders');
}
