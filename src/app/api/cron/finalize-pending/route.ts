import { NextRequest, NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase";
import { sendReceiptEmail } from "@/lib/email";
import { notifyPaymentConfirmed } from "@/lib/telegram";
import type { PaymentIntent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Cron de recovery — finalise les paiements payes qui n'ont pas ete notifies.
//
// Scanne les intents : status='paid' AND invoice_sent_at IS NULL
//   - Envoie le recu par email (si customer_email present)
//   - Envoie la notification Telegram
//   - Marque invoice_sent_at
//
// Filet de securite si :
//   - n8n n'a pas appele /api/internal/finalize apres match_payment
//   - L'utilisateur a ferme l'onglet avant que la page bascule
//   - Une panne reseau a interrompu le flow
//
// Securise par CRON_SECRET dans le header x-cron-secret ou ?secret=...
// Frequence recommandee : toutes les 5 minutes
//
// Limite par appel : 50 intents (pour eviter les longs jobs sur Vercel)
const BATCH_LIMIT = 50;

export async function GET(req: NextRequest) {
  return handle(req);
}

export async function POST(req: NextRequest) {
  return handle(req);
}

async function handle(req: NextRequest) {
  const secret = req.headers.get("x-cron-secret");
  if (secret !== process.env.CRON_SECRET) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const sb = supabaseAdmin();

  // Trouver les paiements payes mais pas finalises.
  // On filtre sur mode='live' : les intents 'test' peuvent etre marques 'paid'
  // via les endpoints simulate — les notifier declencherait de faux positifs Telegram/email.
  const { data, error } = await sb
    .from("payment_intents")
    .select("*")
    .eq("status", "paid")
    .eq("mode", "live")
    .is("invoice_sent_at", null)
    .order("paid_at", { ascending: true })
    .limit(BATCH_LIMIT);

  if (error) {
    console.error("[finalize-pending] query failed", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }

  const intents = (data || []) as PaymentIntent[];

  if (intents.length === 0) {
    return NextResponse.json({ finalized: 0, message: "Aucun paiement a finaliser" });
  }

  const results: Array<{
    ref: string;
    email_sent: boolean;
    email_error?: string;
    telegram_ok: boolean;
  }> = [];

  // Sequentiel pour ne pas bombarder Resend / Telegram
  for (const intent of intents) {
    let emailSent = false;
    let emailError: string | undefined;

    // Telegram (toujours)
    const tg = await notifyPaymentConfirmed(intent).catch((e) => ({
      ok: false,
      error: e instanceof Error ? e.message : String(e)
    }));

    // Email (si customer_email)
    if (intent.customer_email) {
      const r = await sendReceiptEmail(intent);
      if (r.ok) {
        emailSent = true;
      } else {
        emailError = r.error;
      }
    }

    // Marquer comme finalise (meme si email/telegram a echoue — sinon boucle infinie)
    await sb
      .from("payment_intents")
      .update({ invoice_sent_at: new Date().toISOString() })
      .eq("ref", intent.ref);

    results.push({
      ref: intent.ref,
      email_sent: emailSent,
      email_error: emailError,
      telegram_ok: tg.ok ?? false
    });
  }

  return NextResponse.json({
    finalized: intents.length,
    results
  });
}
