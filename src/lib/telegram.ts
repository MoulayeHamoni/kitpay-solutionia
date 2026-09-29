import "server-only";
import type { PaymentIntent, OrphanSms } from "@/lib/types";
import { formatMRU } from "@/lib/format";

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

// Échappe les caractères spéciaux pour Telegram MarkdownV2
function escapeMd(text: string): string {
  return text.replace(/([_*\[\]()~`>#+\-=|{}.!\\])/g, "\\$1");
}

// Formate une durée écoulée en français
function timeAgo(isoDate: string): string {
  const seconds = Math.floor((Date.now() - new Date(isoDate).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h${minutes % 60 > 0 ? ` ${minutes % 60}m` : ""}`;
  const days = Math.floor(hours / 24);
  return `${days}j`;
}

// Envoie un message Telegram avec gestion d'erreur silencieuse
export async function sendTelegramMessage(
  text: string,
  options: { parseMode?: "MarkdownV2" | "HTML"; disableLinkPreview?: boolean } = {}
): Promise<{ ok: boolean; error?: string }> {
  if (!BOT_TOKEN || !CHAT_ID) {
    console.warn("Telegram not configured (TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing)");
    return { ok: false, error: "telegram_not_configured" };
  }

  try {
    const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: CHAT_ID,
        text,
        parse_mode: options.parseMode || "MarkdownV2",
        disable_web_page_preview: options.disableLinkPreview ?? true
      })
    });
    if (!res.ok) {
      const errorBody = await res.text();
      console.error("Telegram API error:", errorBody);
      return { ok: false, error: errorBody };
    }
    return { ok: true };
  } catch (e: any) {
    console.error("sendTelegramMessage error:", e);
    return { ok: false, error: e.message };
  }
}

// === Notifications spécifiques ===

export async function notifyPaymentConfirmed(intent: PaymentIntent) {
  // Garde de securite : ne jamais notifier pour un intent qui n'est pas en mode 'live'.
  // Les intents 'test' peuvent etre marques 'paid' via /api/v1/test/sandbox-simulate
  // ou /api/v1/test/simulate-payment sans qu'aucun paiement reel n'ait lieu ; les notifier
  // au canal Telegram de production donnerait de fausses confirmations.
  if (intent.mode !== "live") {
    console.info("[telegram] notifyPaymentConfirmed skipped (non-live mode)", {
      ref: intent.ref,
      mode: intent.mode,
    });
    return { ok: true };
  }

  const tierLabel: Record<number, string> = {
    1: "🟢 Tier 1 · Match parfait",
    2: "🟡 Tier 2 · Match probable",
    3: "🟠 Tier 3 · Validation manuelle"
  };

  const phoneNote =
    intent.actual_sender_phone &&
    intent.actual_sender_phone !== intent.expected_phone
      ? ` (déclaré : ${intent.expected_phone})`
      : "";

  const elapsed = intent.paid_at
    ? `Délai paiement : ${timeAgo(intent.created_at).replace(/^/, "")} après création`
    : "";

  const lines = [
    `*✅ Paiement confirmé · ${escapeMd(formatMRU(intent.amount))}*`,
    ``,
    `📦 *Article :* ${escapeMd(intent.product_name)}`,
    `💳 *Mode :* ${escapeMd(intent.method)}`,
    `📱 *Numéro payeur :* \`${escapeMd((intent.actual_sender_phone || intent.expected_phone) + phoneNote)}\``,
    `🔖 *Référence :* \`${escapeMd(intent.ref)}\``,
    `${escapeMd(intent.matched_tier ? tierLabel[intent.matched_tier] : "—")}`,
    intent.customer_email ? `📧 *Email client :* ${escapeMd(intent.customer_email)}` : "",
    elapsed ? `⏱ ${escapeMd(elapsed)}` : "",
    ``,
    `[Voir admin](${APP_URL}/admin)`
  ].filter(Boolean);

  return sendTelegramMessage(lines.join("\n"));
}

export async function notifyOrphanSms(orphan: OrphanSms) {
  const lines = [
    `*🟠 SMS orphelin · action requise*`,
    ``,
    `💰 *Montant :* ${escapeMd(orphan.parsed_amount ? formatMRU(orphan.parsed_amount) : "?")}`,
    `📱 *De :* \`${escapeMd(orphan.parsed_phone || "?")}\``,
    `💳 *Mode :* ${escapeMd(orphan.parsed_method || "?")}`,
    `⏱ *Reçu il y a :* ${escapeMd(timeAgo(orphan.received_at))}`,
    ``,
    `_${escapeMd(orphan.raw_body.substring(0, 200))}_`,
    ``,
    `Aucun match auto trouvé\\. À réconcilier manuellement\\.`,
    ``,
    `[Aller à l'admin](${APP_URL}/admin)`
  ];

  return sendTelegramMessage(lines.join("\n"));
}

export async function notifyIntentExpired(intent: PaymentIntent) {
  const lines = [
    `*⚪ Intention expirée · paiement non reçu*`,
    ``,
    `📦 *Article :* ${escapeMd(intent.product_name)}`,
    `💰 *Montant attendu :* ${escapeMd(formatMRU(intent.amount))}`,
    `💳 *Mode :* ${escapeMd(intent.method)}`,
    `📱 *Numéro :* \`${escapeMd(intent.expected_phone)}\``,
    intent.customer_email ? `📧 ${escapeMd(intent.customer_email)}` : "",
    `🔖 \`${escapeMd(intent.ref)}\``,
    `⏱ ${escapeMd(timeAgo(intent.created_at))} après création`,
    ``,
    `Le client n'a pas envoyé le SMS dans les 15 min\\.`
  ].filter(Boolean);

  return sendTelegramMessage(lines.join("\n"));
}

export async function notifyManualReconciliation(intent: PaymentIntent, orphanId: string) {
  const lines = [
    `*🛠 Réconciliation manuelle effectuée*`,
    ``,
    `🔖 *Référence :* \`${escapeMd(intent.ref)}\``,
    `💰 *Montant :* ${escapeMd(formatMRU(intent.amount))}`,
    `📦 *Article :* ${escapeMd(intent.product_name)}`,
    `📱 *Payeur réel :* \`${escapeMd(intent.actual_sender_phone || "?")}\``,
    `💳 *Mode :* ${escapeMd(intent.method)}`,
    ``,
    `Un admin a associé manuellement le SMS orphelin à cette commande\\.`
  ];

  return sendTelegramMessage(lines.join("\n"));
}
