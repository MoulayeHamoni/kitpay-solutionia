import { notFound } from 'next/navigation';
import { requireMerchant } from '@/lib/dashboard/queries';
import { retryDelivery } from '../actions';

export default async function WebhookDeliveryLog({ params }: { params: { id: string } }) {
  const { merchant, supabase } = await requireMerchant();
  const { data: webhook } = await supabase.from('webhooks').select('*')
    .eq('id', params.id).eq('merchant_id', merchant.id).maybeSingle();
  if (!webhook) notFound();

  const { data: deliveries } = await supabase.from('webhook_deliveries_safe')
    .select('*').eq('webhook_id', params.id).eq('merchant_id', merchant.id)
    .order('created_at', { ascending: false }).limit(100);

  return (
    <div>
      <h1 className="font-mono text-2xl font-bold">{webhook.url}</h1>
      <p className="mt-1 text-sm text-neutral-600">Events : {webhook.events.join(', ')}</p>

      <div className="mt-6 overflow-hidden rounded-lg bg-white shadow-sm">
        <table className="w-full text-sm">
          <thead className="bg-neutral-50 text-left text-xs uppercase text-neutral-500">
            <tr><th className="px-4 py-3">Date</th><th className="px-4 py-3">Event</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">HTTP</th><th className="px-4 py-3">Tentatives</th><th></th></tr>
          </thead>
          <tbody>
            {(deliveries ?? []).map(d => (
              <tr key={d.id} className="border-t border-neutral-100">
                <td className="px-4 py-3 text-xs">{new Date(d.created_at).toLocaleString('fr-FR')}</td>
                <td className="px-4 py-3">{d.event_type}</td>
                <td className="px-4 py-3"><StatusBadge status={d.status} /></td>
                <td className="px-4 py-3">{d.http_status ?? '—'}</td>
                <td className="px-4 py-3">{d.attempt}</td>
                <td className="px-4 py-3">
                  {(d.status === 'failed' || d.status === 'expired') && (
                    <form action={retryDelivery.bind(null, d.id) as unknown as (formData: FormData) => Promise<void>}>
                      <button type="submit" className="text-xs text-blue-700 hover:underline">Retry</button>
                    </form>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    pending: 'bg-blue-100 text-blue-800',
    delivered: 'bg-emerald-100 text-emerald-800',
    failed: 'bg-amber-100 text-amber-800',
    expired: 'bg-red-100 text-red-800',
  };
  return <span className={`rounded px-2 py-0.5 text-xs ${colors[status] ?? 'bg-neutral-100'}`}>{status}</span>;
}
