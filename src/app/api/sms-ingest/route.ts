import { NextRequest, NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase";
import { sendReceiptEmail } from "@/lib/email";
import { notifyPaymentConfirmed } from "@/lib/telegram";
import type { PaymentIntent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Remplace n8n : recoit le SMS brut de MacroDroid, parse, match_payment, finalise.
// Body: { from: string, sms_body?: string, body?: string }
// ou query param: ?sms_body=... (pour SMS multi-lignes depuis MacroDroid)
// Header: x-webhook-secret

type ParseResult = { method: string; amount: number; senderPhone: string } | null;

function normalize(s: string): string {
  return s
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[\n\r]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function parseSms(from: string, rawSms: string): ParseResult {
  const sms = normalize(rawSms);
  const f = from.toLowerCase();

  // Bankily: SMS contient "(BANKILY)" - expediteur variable (souvent Click/GIMTEL)
  // Example format: "Transfert recu : 5  de +222XXXXXXXX (BANKILY)\n#REF..."
  if (f.includes("bankily") || /\(bankily\)/i.test(sms)) {
    const pm = sms.match(/[+\s]?222\s*(\d{8,})/);
    // Format "Transfert recu : X  de" (NFD: recu sans accent)
    let am = sms.match(/transfert\s+recu\s*:\s*(\d+(?:[.,]\d+)?)/i);
    // Fallback format avec MRU
    if (!am) am = sms.match(/(\d+(?:[.,]\d+)?)\s*MRU/i);
    if (pm && am) return { method: "Bankily", amount: Math.round(parseFloat(am[1].replace(",", "."))), senderPhone: pm[1].replace(/\s/g, "") };
  }

  // Masrvi (expediteur BMCI): "Client +222 XX XX XX XX (REF123456) a paye 50.00 MRU pour la facture"
  if (f.includes("bmci") || f.includes("masrvi") || /pour la facture/i.test(sms)) {
    const pm = sms.match(/[+\s]222\s+([\d][\d\s]*?)\s*\(/);
    const am = sms.match(/a\s+paye\s+(\d+(?:[.,]\d+)?)\s*MRU/i);
    if (pm && am) return { method: "Masrvi", amount: Math.round(parseFloat(am[1].replace(",", "."))), senderPhone: pm[1].replace(/\s/g, "") };
  }

  // Click: "Client +222 XX XX XX XX a paye 5.00 MRU"
  //   ou ancien masque: "Client *NNNN a paye 5.00 MRU. (REFXXXXXXX)."
  if (f.includes("click")) {
    const am = sms.match(/a\s+paye\s+(\d+(?:[.,]\d+)?)\s*MRU/i);
    // Format complet : "+222 XX XX XX XX a paye"
    let pm = sms.match(/[+\s]222\s+([\d][\d\s]*?)\s+a\s+paye/i);
    let senderPhone = "";
    if (pm) {
      senderPhone = pm[1].replace(/\s/g, "");
    } else {
      // Ancien format masque : "Client *0015"
      const pm2 = sms.match(/Client\s+\*(\d+)/i);
      senderPhone = pm2 ? pm2[1] : "";
    }
    if (am) return { method: "Click", amount: Math.round(parseFloat(am[1].replace(",", "."))), senderPhone };
  }

  // BIM: "Vous avez recu 40 MRU du XXXXXXXX"
  if (f.includes("bim") && !f.includes("bci")) {
    const m = sms.match(/recu\s+(\d+(?:[.,]\d+)?)\s*MRU\s+du\s+(\d{8,})/i);
    if (m) return { method: "BIM", amount: Math.round(parseFloat(m[1].replace(",", "."))), senderPhone: m[2] };
  }

  // BCIPAY: meme format que BIM ("Vous avez recu X MRU du XXXXXXXX")
  if (f.includes("bci") || f.includes("bcipay")) {
    const m = sms.match(/recu\s+(\d+(?:[.,]\d+)?)\s*MRU\s+du\s+(\d{8,})/i);
    if (m) return { method: "BCIPAY", amount: Math.round(parseFloat(m[1].replace(",", "."))), senderPhone: m[2] };
  }

  // Sedad: "Vous avez recu 5.0 MRU du XXXXXXXX" - actual SMS sender = "BMI", the phone
  //   forwarder must set from=Sedad manually (see docs/operators.md)
  if (f.includes("sedad")) {
    const m = sms.match(/recu\s+(\d+(?:[.,]\d+)?)\s*MRU\s+d[eu]\s+(\d{8,})/i);
    if (m) return { method: "Sedad", amount: Math.round(parseFloat(m[1].replace(",", "."))), senderPhone: m[2] };
  }

  return null;
}

export async function POST(req: NextRequest) {
  // --- 1. Auth : Bearer kpf_... -> device + merchant ---
  const auth = req.headers.get("authorization") ?? "";
  const m = auth.match(/^Bearer\s+(kpf_[A-Za-z0-9_-]{20,})$/);
  if (!m) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const sb = supabaseAdmin();
  const { data: authData, error: authErr } = await sb.rpc("verify_forwarder_token", {
    p_token: m[1],
  });
  if (authErr || !authData || (Array.isArray(authData) && authData.length === 0)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const authRow = Array.isArray(authData) ? authData[0] : authData;
  const callerMerchantId: string = (authRow as { merchant_id: string }).merchant_id;

  // --- 2. Body ---
  const url = new URL(req.url);
  const querySms = url.searchParams.get("sms_body") ?? "";
  const queryFrom = url.searchParams.get("from") ?? "";

  let rawSms = "";
  let from = "";
  try {
    const body = await req.json();
    from = String(body.from ?? "").trim() || queryFrom;
    rawSms = querySms || String(body.sms_body ?? body.body ?? body.text ?? body.message ?? "").trim();
  } catch {
    from = queryFrom;
    rawSms = querySms;
  }

  if (!rawSms) {
    return NextResponse.json({ error: "SMS body manquant" }, { status: 400 });
  }

  // --- 3. Parse ---
  const parsed = parseSms(from, rawSms);
  if (!parsed) {
    console.warn("[sms-ingest] parse_failed", { from, sms: rawSms.slice(0, 100) });
    return NextResponse.json({ ok: false, matched: false, error: "parse_failed", from, sms: rawSms.slice(0, 100) });
  }

  // --- 4. Dispatch ---
  const METHOD_FN: Record<string, string> = {
    Bankily: "match_payment_bankily",
    Masrvi:  "match_payment_masrvi",
    BIM:     "match_payment_bim",
    Sedad:   "match_payment_sedad",
    BCIPAY:  "match_payment_bcipay",
    Click:   "match_payment_click",
  };
  const fnName = METHOD_FN[parsed.method] ?? "match_payment";
  const rpcParams: Record<string, unknown> = {
    p_amount: parsed.amount,
    p_sender_phone: parsed.senderPhone,
    p_raw_sms: rawSms.slice(0, 1000),
  };

  if (fnName === "match_payment") {
    // v3 fallback : resolve this merchant's receiver phone for the method
    const { data: op } = await sb.from("merchant_operators")
      .select("expected_phone")
      .eq("merchant_id", callerMerchantId)
      .eq("method", parsed.method)
      .eq("enabled", true)
      .maybeSingle();
    if (!op) {
      return NextResponse.json({ ok: false, matched: false, reason: "method_not_enabled_for_merchant" });
    }
    rpcParams.p_method = parsed.method;
    rpcParams.p_merchant_phone = (op as { expected_phone: string }).expected_phone;
  } else {
    rpcParams.p_merchant_id = callerMerchantId;
  }

  const { data, error } = await sb.rpc(fnName as any, rpcParams);

  if (error) {
    console.error("[sms-ingest] match_payment error", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }

  const matchResult = (Array.isArray(data) ? data[0] : data) as { matched?: boolean; tier?: number; ref?: string } | null;
  const matched = matchResult?.matched === true;
  const ref = matchResult?.ref ?? null;

  if (!matched || !ref) {
    return NextResponse.json({ ok: true, matched: false, parsed, debug: matchResult });
  }

  const { data: intentData } = await sb.from("payment_intents").select("*").eq("ref", ref).single();
  if (intentData) {
    const intent = intentData as PaymentIntent;
    if (!intent.invoice_sent_at) {
      notifyPaymentConfirmed(intent).catch((e) => console.error("[sms-ingest] telegram error", e));
      let emailSent = false;
      if (intent.customer_email) {
        const r = await sendReceiptEmail(intent);
        emailSent = r.ok;
      }
      await sb.from("payment_intents").update({ invoice_sent_at: new Date().toISOString() }).eq("ref", ref);
      return NextResponse.json({ ok: true, matched: true, ref, email_sent: emailSent });
    }
  }

  return NextResponse.json({ ok: true, matched: true, ref, already_finalized: true });
}
