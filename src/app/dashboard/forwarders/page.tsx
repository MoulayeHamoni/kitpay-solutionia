import { requireMerchant } from '@/lib/dashboard/queries';
import { createSupabaseAdminClient } from '@/lib/supabase/server';
import { PageHeader } from '@/components/dashboard/PageHeader';
import { CreateDeviceButton } from './CreateDeviceButton';
import { revokeForwarderDevice } from './actions';

export const dynamic = 'force-dynamic';

type DeviceRow = {
  id: string;
  label: string;
  enabled: boolean;
  created_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
};

export default async function ForwardersPage() {
  const { merchant } = await requireMerchant();
  const admin = createSupabaseAdminClient();
  const { data } = await admin
    .from('forwarder_devices')
    .select('id, label, enabled, created_at, last_seen_at, revoked_at')
    .eq('merchant_id', merchant.id)
    .order('created_at', { ascending: false });
  const devices = (data ?? []) as DeviceRow[];
  const activeCount = devices.filter(d => !d.revoked_at).length;

  return (
    <div className="max-w-3xl">
      <PageHeader
        eyebrow="Securite"
        title={<>Forwarders</>}
        description="Appareils autorises a envoyer les SMS d'operateur vers /api/sms-ingest. Chaque forwarder porte son propre token Bearer."
        action={<CreateDeviceButton />}
      />

      {devices.length === 0 ? (
        <div className="mt-8 border border-dashed border-[var(--stone-300)] rounded-sm p-10 text-center">
          <p className="text-sm text-[var(--stone-600)]">
            Aucun forwarder enregistre. Cliquez sur &ldquo;Nouveau forwarder&rdquo; pour creer le premier token
            a coller dans la configuration MacroDroid.
          </p>
        </div>
      ) : (
        <>
          <p className="mt-6 text-xs text-[var(--stone-500)] uppercase tracking-wider">
            {activeCount} actif(s) / {devices.length} total
          </p>
          <ul className="mt-3 divide-y divide-[var(--stone-200)] border border-[var(--stone-200)] rounded-sm bg-white">
            {devices.map(d => (
              <li key={d.id} className="p-4 flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <div className="font-medium truncate">{d.label}</div>
                  <div className="text-xs text-[var(--stone-500)] mt-0.5">
                    Cree {new Date(d.created_at).toLocaleDateString('fr')}
                    {' · '}
                    Dernier SMS : {d.last_seen_at ? new Date(d.last_seen_at).toLocaleString('fr') : 'jamais'}
                    {d.revoked_at && <span className="text-red-700"> · REVOQUE</span>}
                    {!d.revoked_at && !d.enabled && <span className="text-[var(--stone-500)]"> · desactive</span>}
                  </div>
                </div>
                {!d.revoked_at && (
                  <form
                    action={
                      revokeForwarderDevice.bind(null, d.id) as unknown as (
                        formData: FormData
                      ) => Promise<void>
                    }
                  >
                    <button type="submit" className="kp-btn kp-btn-ghost text-xs text-red-700">
                      Revoquer
                    </button>
                  </form>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
