import Link from 'next/link';
import { requireMerchant } from '@/lib/dashboard/queries';
import { EmptyState } from '@/components/dashboard/EmptyState';
import { AddWebhookButton } from './AddWebhookButton';
import { toggleWebhook, deleteWebhook, fireTestWebhook } from './actions';
import { PageHeader } from '@/components/dashboard/PageHeader';

export default async function WebhooksPage() {
  const { merchant, supabase } = await requireMerchant();
  const { data: webhooks } = await supabase
    .from('webhooks')
    .select('*')
    .eq('merchant_id', merchant.id)
    .order('created_at', { ascending: false });

  return (
    <div>
      <PageHeader
        eyebrow="Notifications"
        title={<><em>Webhooks</em> sortants</>}
        description="Recevez les événements payment.succeeded, payment.expired, payment.cancelled signés HMAC SHA-256 sur votre serveur."
        action={<AddWebhookButton />}
      />

      {!webhooks || webhooks.length === 0 ? (
        <EmptyState
          title="Aucun webhook"
          description="Ajoutez l'URL de votre serveur pour recevoir les événements de paiement."
          action={<AddWebhookButton />}
        />
      ) : (
        <ul className="bg-white border border-[var(--stone-200)] rounded-sm divide-y divide-[var(--stone-100)] overflow-hidden">
          {webhooks.map((w) => (
            <li
              key={w.id}
              className="p-5 hover:bg-[var(--stone-50)] transition-colors duration-150"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <Link
                      href={`/dashboard/webhooks/${w.id}`}
                      className="block truncate font-mono text-sm text-[var(--ink)] hover:text-[var(--bronze)] transition-colors duration-200"
                    >
                      {w.url}
                    </Link>
                    {w.mode && (
                      <span className="shrink-0 inline-block text-[10px] uppercase tracking-wider px-1.5 py-0.5 border border-[var(--stone-300)] text-[var(--stone-600)] rounded-sm">
                        {w.mode}
                      </span>
                    )}
                  </div>
                  {w.events && w.events.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {(w.events as string[]).map((e) => (
                        <span
                          key={e}
                          className="font-mono text-[10px] tracking-wider text-[var(--stone-600)] bg-[var(--paper-warm)] border border-[var(--stone-200)] rounded-sm px-1.5 py-0.5"
                        >
                          {e}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <form
                    action={
                      fireTestWebhook.bind(null, w.id) as unknown as (
                        formData: FormData
                      ) => Promise<void>
                    }
                  >
                    <button
                      type="submit"
                      className="font-mono text-[10px] tracking-wider uppercase border border-[var(--stone-200)] text-[var(--ink)] hover:bg-[var(--stone-100)] rounded-sm px-2.5 py-1 cursor-pointer transition-colors duration-200"
                    >
                      Tester
                    </button>
                  </form>
                  <form
                    action={
                      toggleWebhook.bind(null, w.id, !w.enabled) as unknown as (
                        formData: FormData
                      ) => Promise<void>
                    }
                  >
                    <button
                      type="submit"
                      className={`inline-flex items-center gap-1.5 font-mono text-[10px] tracking-wider uppercase border rounded-sm px-2.5 py-1 cursor-pointer transition-colors duration-200 ${
                        w.enabled
                          ? 'border-[var(--forest)]/40 text-[var(--forest)] bg-[var(--forest)]/[0.06] hover:bg-[var(--forest)]/[0.1]'
                          : 'border-[var(--stone-300)] text-[var(--stone-500)] bg-[var(--stone-100)] hover:bg-[var(--stone-200)]'
                      }`}
                    >
                      {w.enabled && <span className="kp-pulse" aria-hidden="true" />}
                      {w.enabled ? 'Activé' : 'Désactivé'}
                    </button>
                  </form>
                  <form
                    action={
                      deleteWebhook.bind(null, w.id) as unknown as (
                        formData: FormData
                      ) => Promise<void>
                    }
                  >
                    <button
                      type="submit"
                      className="font-mono text-[10px] tracking-wider uppercase border border-[var(--stone-200)] text-[#9b1c1c] hover:bg-[#fef2f2] hover:border-[#9b1c1c]/40 rounded-sm px-2.5 py-1 cursor-pointer transition-colors duration-200"
                    >
                      Supprimer
                    </button>
                  </form>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
