import { supabaseAdmin } from "@/lib/supabase";
import { formatMRU } from "@/lib/format";
import { sendReceiptEmail } from "@/lib/email";
import { notifyPaymentConfirmed } from "@/lib/telegram";
import type { PaymentIntent } from "@/lib/types";
import Link from "next/link";

export const dynamic = "force-dynamic";

const TIER_LABEL: Record<number, string> = {
  1: "Match parfait (numéro + montant)",
  2: "Match probable (montant unique)",
  3: "Validation manuelle",
};

export default async function SuccessPage({ params }: { params: { ref: string } }) {
  const sb = supabaseAdmin();
  const { data, error } = await sb
    .from("payment_intents")
    .select("*")
    .eq("ref", params.ref)
    .single();

  if (error || !data) {
    return (
      <main className="min-h-[70vh] flex items-center justify-center px-4">
        <div className="text-center">
          <p className="kp-eyebrow text-[var(--stone-500)] mb-3">— Erreur</p>
          <h1 className="serif text-2xl text-[var(--ink)] italic">
            Paiement introuvable
          </h1>
          <Link href="/" className="kp-link mt-6 inline-block">
            Retour à l&apos;accueil
          </Link>
        </div>
      </main>
    );
  }
  const intent = data as PaymentIntent;

  if (intent.status !== "paid") {
    return (
      <main className="min-h-[70vh] flex items-center justify-center px-4">
        <div className="text-center max-w-md">
          <p className="kp-eyebrow text-[var(--bronze)] mb-3">— En attente</p>
          <h1 className="serif text-2xl text-[var(--ink)] italic mb-3">
            Ce paiement n&apos;est pas encore confirmé
          </h1>
          <Link href={`/pay/${params.ref}`} className="kp-btn kp-btn-ghost mt-2">
            Retour au paiement
          </Link>
        </div>
      </main>
    );
  }

  let emailJustSent = false;
  // Uniquement pour les vrais paiements (mode='live') : les intents 'test' peuvent etre
  // marques 'paid' via les endpoints simulate sans qu'aucun paiement reel ait eu lieu.
  if (!intent.invoice_sent_at && intent.mode === "live") {
    notifyPaymentConfirmed(intent).catch((e) =>
      console.error("Telegram notification failed:", e)
    );

    if (intent.customer_email) {
      const result = await sendReceiptEmail(intent);
      if (result.ok) emailJustSent = true;
      else console.error("Email send failed:", result.error);
    }

    await sb
      .from("payment_intents")
      .update({ invoice_sent_at: new Date().toISOString() })
      .eq("ref", params.ref);
  }

  return (
    <main className="min-h-screen bg-[var(--paper)] py-10 sm:py-16 px-4">
      <div className="mx-auto max-w-md">
        <header className="text-center mb-8">
          <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-[var(--forest)]/[0.08] border border-[var(--forest)]/30">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="36"
              height="36"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.25"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="text-[var(--forest)]"
              aria-hidden="true"
            >
              <path d="M20 6 9 17l-5-5" />
            </svg>
          </div>
          <p className="kp-eyebrow text-[var(--forest)] mb-2">— Paiement confirmé</p>
          <h1 className="serif text-3xl font-medium text-[var(--ink)] tracking-tight italic">
            Merci de votre paiement
          </h1>
          <p className="mt-3 text-sm text-[var(--stone-600)]">
            Votre commande a bien été enregistrée.
          </p>
          {emailJustSent && (
            <p className="mt-4 inline-flex items-center gap-2 font-mono text-[11px] tracking-wider uppercase border border-[var(--forest)]/40 text-[var(--forest)] bg-[var(--forest)]/[0.06] rounded-sm px-3 py-1">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M20 6 9 17l-5-5" />
              </svg>
              Reçu envoyé à {intent.customer_email}
            </p>
          )}
          {intent.customer_email && intent.invoice_sent_at && !emailJustSent && (
            <p className="mt-4 font-mono text-[11px] tracking-wider text-[var(--stone-500)]">
              Reçu envoyé à {intent.customer_email}
            </p>
          )}
        </header>

        <ul className="bg-white border border-[var(--stone-200)] rounded-sm divide-y divide-[var(--stone-200)] shadow-[0_1px_2px_rgba(0,0,0,0.02),0_24px_60px_-24px_rgba(58,52,42,0.18)]">
          <Row label="Article" value={intent.product_name} />
          <Row label="Montant" value={formatMRU(intent.amount)} highlight />
          <Row label="Méthode" value={intent.method} />
          <Row label="Référence" value={intent.ref} mono />
          <Row label="Numéro déclaré" value={intent.expected_phone} mono />
          {intent.actual_sender_phone && (
            <Row
              label="Numéro payeur"
              value={
                intent.actual_sender_phone +
                (intent.actual_sender_phone !== intent.expected_phone ? " (différent)" : "")
              }
              mono
            />
          )}
          {intent.matched_tier && (
            <Row label="Validation" value={TIER_LABEL[intent.matched_tier]} />
          )}
          {intent.paid_at && (
            <Row
              label="Confirmé le"
              value={new Date(intent.paid_at).toLocaleString("fr-FR")}
              mono
            />
          )}
        </ul>

        <div className="text-center mt-8">
          <Link href="/" className="kp-link inline-block">
            Retour à l&apos;accueil
          </Link>
        </div>

        <p className="mt-10 text-center kp-eyebrow text-[var(--stone-500)]">
          — Sécurisé par KitPay · Mauritanie
        </p>
      </div>
    </main>
  );
}

function Row({
  label,
  value,
  mono,
  highlight,
}: {
  label: string;
  value: string;
  mono?: boolean;
  highlight?: boolean;
}) {
  return (
    <li className="flex items-center justify-between gap-3 px-5 py-3.5 text-sm">
      <span className="kp-eyebrow text-[var(--stone-500)]">— {label}</span>
      <span
        className={`text-right text-[var(--ink)] ${
          mono
            ? "font-mono text-[13px]"
            : highlight
              ? "serif text-base italic font-medium"
              : ""
        }`}
      >
        {value}
      </span>
    </li>
  );
}
