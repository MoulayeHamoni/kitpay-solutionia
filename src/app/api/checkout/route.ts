import { NextRequest, NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase";
import { fetchProductById } from "@/lib/products";
import { generateRef } from "@/lib/format";
import { canonicalMauritanianPhone } from "@/lib/phone";

const VALID_METHODS = ["Bankily", "Masrvi", "Sedad", "BIM", "Click"];

export async function POST(req: NextRequest) {
  try {
    const { product_id, phone, method, email } = await req.json();

    const product = await fetchProductById(product_id);
    if (!product || !product.active) {
      return NextResponse.json({ error: "Produit invalide ou indisponible" }, { status: 400 });
    }
    if (!phone || phone.length < 8) {
      return NextResponse.json({ error: "Numéro invalide" }, { status: 400 });
    }
    if (!VALID_METHODS.includes(method)) {
      return NextResponse.json({ error: "Mode invalide" }, { status: 400 });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: "Email invalide" }, { status: 400 });
    }

    const cleanPhone = canonicalMauritanianPhone(phone);

    const sb = supabaseAdmin();
    const ref = generateRef();

    const { error } = await sb.from("payment_intents").insert({
      ref,
      product_id: product.id,
      product_name: product.name,
      amount: product.price,
      expected_phone: cleanPhone,
      method,
      customer_email: email || null
    });

    if (error) {
      console.error("[checkout] insert intent failed", error);
      return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }

    return NextResponse.json({ ref });
  } catch (e: any) {
    console.error("[checkout] unexpected error", e);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
