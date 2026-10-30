import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "crypto";
import { supabaseAdmin } from "@/lib/supabase";
import { generateRef } from "@/lib/format";
import { canonicalMauritanianPhone } from "@/lib/phone";

const VALID_METHODS = ["Bankily", "Masrvi", "Sedad", "BIM", "Click"];
const DEMO_PRODUCT_ID = "__kitpay_demo__";
// Sandbox montants symboliques (5 a 100 MRU): the public /sandbox page uses
// this endpoint to create real intents with a tiny amount, useful to smoke-test
// the SMS ingest pipeline end to end.
const DEMO_MIN_AMOUNT = 5;
const DEMO_MAX_AMOUNT = 100;

// No fallback. If the env var isn't set, the sandbox is disabled.
// Fallback to "first merchant" would silently create live-mode intents against an unintended merchant.
const SANDBOX_MERCHANT_ID = process.env.SANDBOX_MERCHANT_ID ?? null;

async function resolveSandboxMerchantId(_sb: ReturnType<typeof supabaseAdmin>): Promise<string | null> {
  // No fallback. If the env var isn't set, the sandbox is disabled.
  // Fallback to "first merchant" would silently create live-mode intents against an unintended merchant.
  return SANDBOX_MERCHANT_ID;
}

// In-memory rate limiter for the demo endpoint
const demoRateBuckets = new Map<string, { count: number; resetAt: number }>();
const DEMO_RATE_LIMIT = 5;              // 5 requests
const DEMO_RATE_WINDOW_MS = 60_000;     // per 60 seconds per IP
function tooManyDemoRequests(ip: string): boolean {
  const now = Date.now();
  const b = demoRateBuckets.get(ip);
  if (!b || b.resetAt < now) {
    demoRateBuckets.set(ip, { count: 1, resetAt: now + DEMO_RATE_WINDOW_MS });
    return false;
  }
  b.count += 1;
  return b.count > DEMO_RATE_LIMIT;
}

// Public sandbox endpoint: creates a payment_intent without authentication.
// Intents are inserted in mode='live' so real Bankily/Masrvi SMS get matched
// by the /api/sms-ingest pipeline. Demo intents are tagged with
// product_id='__kitpay_demo__' for reporting.
export async function POST(req: NextRequest) {
  try {
    const { phone, method, amount, label, email } = await req.json();

    const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    if (tooManyDemoRequests(ip)) {
      return NextResponse.json({ error: 'rate_limit' }, { status: 429 });
    }

    const cleanPhone = canonicalMauritanianPhone(phone);
    if (!cleanPhone || cleanPhone.length < 8) {
      return NextResponse.json({ error: "Numero invalide (8 chiffres minimum)" }, { status: 400 });
    }

    if (!VALID_METHODS.includes(method)) {
      return NextResponse.json({ error: "Mode de paiement invalide" }, { status: 400 });
    }

    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt < DEMO_MIN_AMOUNT || amt > DEMO_MAX_AMOUNT) {
      return NextResponse.json(
        { error: `Montant invalide (entre ${DEMO_MIN_AMOUNT} et ${DEMO_MAX_AMOUNT} MRU)` },
        { status: 400 }
      );
    }

    let cleanEmail: string | null = null;
    if (email && typeof email === "string") {
      const trimmed = email.trim();
      if (trimmedEmailIsValid(trimmed)) {
        cleanEmail = trimmed.slice(0, 120);
      } else if (trimmed.length > 0) {
        return NextResponse.json({ error: "Email invalide" }, { status: 400 });
      }
    }

    const sb = supabaseAdmin();

    const sandboxMerchantId = await resolveSandboxMerchantId(sb);
    if (!sandboxMerchantId) {
      return NextResponse.json(
        { error: "Sandbox is disabled: SANDBOX_MERCHANT_ID is not set." },
        { status: 503 }
      );
    }

    // Resolve merchant_operator_id matching the requested method
    const { data: operator } = await sb
      .from("merchant_operators")
      .select("id, expected_phone")
      .eq("merchant_id", sandboxMerchantId)
      .eq("method", method)
      .eq("enabled", true)
      .maybeSingle();

    if (!operator) {
      return NextResponse.json(
        { error: `Aucun opérateur configuré pour ${method} en sandbox` },
        { status: 422 }
      );
    }

    const ref = generateRef();
    const productName =
      typeof label === "string" && label.trim().length > 0
        ? label.trim().slice(0, 80)
        : "Demo KitPay";

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const clientSecret = `kpcs_${randomBytes(16).toString("hex")}`;

    // Sandbox intents run in mode='live' so real SMS get matched by
    // /api/sms-ingest -> match_payment_* (which only look at live intents).
    // Demo intents are tagged with product_id='__kitpay_demo__' for reporting.
    const { error } = await sb.from("payment_intents").insert({
      ref,
      merchant_id: sandboxMerchantId,
      merchant_operator_id: operator.id,
      product_id: DEMO_PRODUCT_ID,
      product_name: productName,
      amount: Math.round(amt),
      method,
      mode: "live",
      status: "pending",
      expected_phone: cleanPhone,
      customer_phone: cleanPhone,
      customer_email: cleanEmail,
      expires_at: expiresAt,
      client_secret: clientSecret,
      description: productName,
    });

    if (error) {
      console.error("[demo] insert intent failed", error);
      return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }

    return NextResponse.json({ ref, amount: Math.round(amt), method });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Erreur";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

function trimmedEmailIsValid(s: string): boolean {
  if (s.length === 0) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}
