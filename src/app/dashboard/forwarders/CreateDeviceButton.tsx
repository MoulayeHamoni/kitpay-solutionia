'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { createForwarderDevice } from './actions';

export function CreateDeviceButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();

  const submit = () => {
    setError(null);
    start(async () => {
      const r = await createForwarderDevice({ label });
      if (!r.ok) {
        setError(r.error);
        return;
      }
      setToken(r.token);
    });
  };

  const close = () => {
    setOpen(false);
    setLabel('');
    setToken(null);
    setError(null);
    router.refresh();
  };

  return (
    <>
      <button onClick={() => setOpen(true)} className="kp-btn kp-btn-primary text-sm">
        Nouveau forwarder
      </button>
      {open && (
        <div
          className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4"
          onClick={close}
        >
          <div
            className="bg-white max-w-md w-full p-6 rounded-sm shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            {!token ? (
              <>
                <h3 className="font-medium mb-1">Nouveau forwarder</h3>
                <p className="text-xs text-[var(--stone-600)] mb-4">
                  Donnez un nom reconnaissable (ex. &ldquo;Phone-Nouakchott&rdquo;). Le token sera affiche une seule fois.
                </p>
                <label className="block text-xs mb-1 uppercase tracking-wider text-[var(--stone-500)]">
                  Nom du forwarder
                </label>
                <input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="Phone-Nouakchott"
                  className="w-full border border-[var(--stone-300)] px-3 py-2 rounded-sm text-sm"
                  autoFocus
                />
                {error && <p className="text-red-700 text-sm mt-3">{error}</p>}
                <div className="flex gap-2 mt-5 justify-end">
                  <button onClick={close} className="kp-btn kp-btn-ghost text-sm">
                    Annuler
                  </button>
                  <button onClick={submit} disabled={pending || !label.trim()} className="kp-btn kp-btn-primary text-sm">
                    {pending ? 'Creation...' : 'Creer'}
                  </button>
                </div>
              </>
            ) : (
              <>
                <h3 className="font-medium mb-2">Token forwarder genere</h3>
                <p className="text-xs text-[var(--stone-600)] mb-3">
                  Copiez-le maintenant. Il ne sera plus jamais affiche. A coller dans l&apos;header
                  <code className="font-mono text-[11px]"> Authorization: Bearer </code>
                  de la requete HTTP MacroDroid.
                </p>
                <code className="block bg-[var(--stone-100)] p-3 rounded-sm text-xs font-mono break-all">
                  {token}
                </code>
                <div className="flex gap-2 mt-5 justify-end">
                  <button
                    onClick={() => navigator.clipboard.writeText(token!)}
                    className="kp-btn kp-btn-ghost text-sm"
                  >
                    Copier
                  </button>
                  <button onClick={close} className="kp-btn kp-btn-primary text-sm">
                    Ferme
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}
