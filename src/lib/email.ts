import type { PaymentIntent } from "@/lib/types";
import { formatMRU } from "@/lib/format";

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = process.env.RESEND_FROM || "KitPay <onboarding@resend.dev>";

// Envoie un reçu par email via Resend
export async function sendReceiptEmail(
  intent: PaymentIntent
): Promise<{ ok: boolean; error?: string }> {
  if (!intent.customer_email) {
    return { ok: false, error: "no email" };
  }
  if (!RESEND_API_KEY) {
    console.error("RESEND_API_KEY not set");
    return { ok: false, error: "RESEND_API_KEY not configured" };
  }

  const html = buildReceiptHtml(intent);
  const text = buildReceiptText(intent);

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${RESEND_API_KEY}`
      },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: [intent.customer_email],
        subject: `Reçu de paiement · ${intent.ref}`,
        html,
        text
      })
    });
    if (!res.ok) {
      const errorBody = await res.text();
      console.error("Resend error:", errorBody);
      return { ok: false, error: errorBody };
    }
    return { ok: true };
  } catch (e: any) {
    console.error("sendReceiptEmail error:", e);
    return { ok: false, error: e.message };
  }
}

function escapeHtml(s: string): string {
  return (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function buildReceiptHtml(intent: PaymentIntent): string {
  const paidAt = intent.paid_at
    ? new Date(intent.paid_at).toLocaleString("fr-FR", {
        dateStyle: "long",
        timeStyle: "short"
      })
    : "—";

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Reçu ${escapeHtml(intent.ref)}</title>
</head>
<body style="margin:0;padding:0;background:#f5f5f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f4;padding:32px 16px;">
    <tr>
      <td align="center">
        <table width="100%" style="max-width:480px;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e7e5e4;">
          <!-- Header -->
          <tr>
            <td style="padding:24px;border-bottom:1px solid #e7e5e4;">
              <table width="100%">
                <tr>
                  <td>
                    <div style="display:inline-block;width:32px;height:32px;background:#1c1917;color:#fff;text-align:center;line-height:32px;border-radius:6px;font-weight:600;font-family:monospace;vertical-align:middle;">K</div>
                    <span style="font-size:18px;font-weight:600;color:#1c1917;margin-left:8px;vertical-align:middle;">KitPay</span>
                  </td>
                  <td align="right" style="font-size:12px;color:#78716c;">
                    Reçu de paiement
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Confirmation -->
          <tr>
            <td style="padding:32px 24px 16px;text-align:center;">
              <div style="width:56px;height:56px;background:#dcfce7;color:#15803d;border-radius:50%;line-height:56px;text-align:center;font-size:24px;display:inline-block;">✓</div>
              <h1 style="font-size:20px;font-weight:600;color:#1c1917;margin:16px 0 4px;">Paiement confirmé</h1>
              <p style="font-size:14px;color:#78716c;margin:0;">Merci, votre commande a bien été enregistrée.</p>
            </td>
          </tr>

          <!-- Montant -->
          <tr>
            <td style="padding:0 24px 24px;text-align:center;">
              <div style="background:#fafaf9;border-radius:8px;padding:20px;">
                <div style="font-size:32px;font-weight:600;color:#1c1917;">${formatMRU(intent.amount)}</div>
                <div style="font-size:13px;color:#78716c;margin-top:4px;">${escapeHtml(intent.product_name)}</div>
              </div>
            </td>
          </tr>

          <!-- Détails -->
          <tr>
            <td style="padding:0 24px 24px;">
              <table width="100%" style="font-size:13px;">
                ${rowHtml("Référence", escapeHtml(intent.ref), true)}
                ${rowHtml("Mode de paiement", escapeHtml(intent.method))}
                ${rowHtml("Numéro déclaré", escapeHtml(intent.expected_phone ?? ''))}
                ${
                  intent.actual_sender_phone &&
                  intent.actual_sender_phone !== intent.expected_phone
                    ? rowHtml("Numéro payeur", escapeHtml(intent.actual_sender_phone))
                    : ""
                }
                ${rowHtml("Confirmé le", paidAt)}
              </table>
            </td>
          </tr>

          <!-- Émetteur -->
          <tr>
            <td style="padding:16px 24px;background:#fafaf9;border-top:1px solid #e7e5e4;font-size:12px;color:#78716c;">
              <span style="color:#a8a29e;">Reçu généré automatiquement par KitPay</span>
            </td>
          </tr>
        </table>

        <p style="font-size:11px;color:#a8a29e;margin-top:16px;">
          Cet email a été envoyé automatiquement suite à votre paiement.<br>
          Conservez-le comme preuve de transaction.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function rowHtml(label: string, value: string, mono = false): string {
  return `
    <tr>
      <td style="padding:6px 0;color:#78716c;">${label}</td>
      <td align="right" style="padding:6px 0;color:#1c1917;${mono ? "font-family:monospace;" : ""}">${value}</td>
    </tr>`;
}

function buildReceiptText(intent: PaymentIntent): string {
  const paidAt = intent.paid_at
    ? new Date(intent.paid_at).toLocaleString("fr-FR")
    : "—";

  return `KitPay — Reçu de paiement

Paiement confirmé
${formatMRU(intent.amount)} — ${intent.product_name}

Référence : ${intent.ref}
Mode : ${intent.method}
Numéro déclaré : ${intent.expected_phone}
${intent.actual_sender_phone && intent.actual_sender_phone !== intent.expected_phone ? `Numéro payeur : ${intent.actual_sender_phone}\n` : ""}Confirmé le : ${paidAt}

Reçu généré automatiquement par KitPay`;
}
