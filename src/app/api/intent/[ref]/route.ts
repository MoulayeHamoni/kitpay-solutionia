import { NextRequest, NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase";

// Endpoint public legacy : n'expose QUE les champs necessaires a la page /pay/[ref].
// Historiquement retournait select('*'), ce qui leakait `client_secret`, `sms_received`,
// `customer_email`, `expected_phone`, etc. Pour toute integration serveur, utiliser
// `/api/v1/intents/[ref]` avec une cle API.
const PUBLIC_FIELDS = [
  "ref",
  "status",
  "mode",
  "amount",
  "method",
  "description",
  "expires_at",
  "paid_at",
  "matched_tier",
] as const;

export async function GET(_req: NextRequest, { params }: { params: { ref: string } }) {
  const sb = supabaseAdmin();
  const { data, error } = await sb
    .from("payment_intents")
    .select(PUBLIC_FIELDS.join(","))
    .eq("ref", params.ref)
    .single();

  if (error || !data) {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
  return NextResponse.json(data);
}
