'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { Modal } from '@/components/dashboard/Modal';
import { CopyButton } from '@/components/dashboard/CopyButton';
import { addWebhook } from './actions';

const ALL_EVENTS = ['payment.succeeded', 'payment.expired', 'payment.cancelled'];

export function AddWebhookButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();
  const [showSecret, setShowSecret] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState<{ url: string; events: string[] }>({ url: '', events: [...ALL_EVENTS] });
  const [mode, setMode] = useState<'test' | 'live' | 'both'>('live');

  function toggleEvent(ev: string) {
    setForm(f => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter(e => e !== ev) : [...f.events, ev],
    }));
  }

  function submit() {
    setErr(null);
    startTransition(async () => {
      const res = await addWebhook({ ...form, mode });
      if (!res.ok) setErr(res.error ?? null);
      else if (res.secret) setShowSecret(res.secret);
    });
  }

  function close() {
    const wasShowingSecret = showSecret !== null;
    setOpen(false);
    setShowSecret(null);
    setForm({ url: '', events: [...ALL_EVENTS] });
    setMode('live');
    setErr(null);
    // Only refresh the list once the user is done with the secret modal
    if (wasShowingSecret) router.refresh();
  }

  return (
    <>
      <button onClick={() => setOpen(true)} className="rounded-md bg-neutral-900 px-4 py-2 text-sm text-white">+ Ajouter webhook</button>
      <Modal open={open} onClose={close} title={showSecret ? 'Webhook créé — copiez le secret' : 'Ajouter un webhook'}>
        {showSecret ? (
          <div>
            <p className="text-sm text-amber-900">⚠ Ce secret ne sera plus jamais affiché. Stockez-le côté serveur pour vérifier les signatures HMAC.</p>
            <pre className="mt-3 select-all rounded bg-neutral-900 p-3 font-mono text-xs text-neutral-100">{showSecret}</pre>
            <div className="mt-3 flex justify-end gap-2">
              <CopyButton value={showSecret}>Copier</CopyButton>
              <button onClick={close} className="rounded-md bg-neutral-900 px-4 py-2 text-sm text-white">J'ai sauvegardé</button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <input
              value={form.url}
              onChange={e => setForm({ ...form, url: e.target.value })}
              placeholder="https://votre-serveur.com/webhooks/kitpay"
              className="w-full rounded-md border border-neutral-300 px-3 py-2"
            />
            <div>
              <p className="mb-2 text-xs uppercase tracking-wide text-neutral-500">Événements</p>
              <div className="space-y-1">
                {ALL_EVENTS.map(ev => (
                  <label key={ev} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={form.events.includes(ev)}
                      onChange={() => toggleEvent(ev)}
                    />
                    <span className="font-mono">{ev}</span>
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs mt-4 mb-1 uppercase tracking-wider text-[var(--stone-500)]">
                Scope
              </label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as 'test' | 'live' | 'both')}
                className="w-full border border-[var(--stone-300)] px-3 py-2 rounded-sm text-sm"
              >
                <option value="live">Live uniquement (defaut)</option>
                <option value="test">Test uniquement</option>
                <option value="both">Les deux (test + live)</option>
              </select>
            </div>
            {err && <p className="text-sm text-red-600">{err}</p>}
            <button onClick={submit} disabled={pending} className="w-full rounded-md bg-neutral-900 px-4 py-2 text-white disabled:opacity-50">
              {pending ? 'Création…' : 'Créer'}
            </button>
          </div>
        )}
      </Modal>
    </>
  );
}
