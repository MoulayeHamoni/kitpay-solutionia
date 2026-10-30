import { NextRequest, NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase";
import { slugify } from "@/lib/format";
import { checkAdminAuth } from "@/lib/admin-auth";

// POST : créer un produit
export async function POST(req: NextRequest) {
  if (new URL(req.url).searchParams.has('pwd')) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }
  if (!checkAdminAuth(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const body = await req.json();
  const { name, description, price } = body;
  let { id } = body;

  if (!name || typeof name !== "string") {
    return NextResponse.json({ error: "Nom requis" }, { status: 400 });
  }
  if (!price || price <= 0) {
    return NextResponse.json({ error: "Prix invalide" }, { status: 400 });
  }

  if (!id) {
    id = slugify(name);
    if (!id) id = "produit-" + Date.now();
  } else {
    id = slugify(id);
  }

  const sb = supabaseAdmin();

  // Vérifier unicité de l'id
  const { data: existing } = await sb.from("products").select("id").eq("id", id).single();
  if (existing) {
    // Ajoute un suffixe si l'id existe déjà
    id = id + "-" + Math.floor(Math.random() * 1000);
  }

  const { data, error } = await sb
    .from("products")
    .insert({
      id,
      name: name.trim(),
      description: description?.trim() || null,
      price,
      active: true
    })
    .select()
    .single();

  if (error) {
    console.error("[admin/products] DB error", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
  return NextResponse.json(data);
}

// PUT : modifier un produit existant
export async function PUT(req: NextRequest) {
  if (new URL(req.url).searchParams.has('pwd')) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }
  if (!checkAdminAuth(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const body = await req.json();
  const { id, name, description, price, active } = body;

  if (!id) {
    return NextResponse.json({ error: "ID requis" }, { status: 400 });
  }

  const update: any = {};
  if (name !== undefined) update.name = name.trim();
  if (description !== undefined) update.description = description?.trim() || null;
  if (price !== undefined) {
    if (price <= 0) return NextResponse.json({ error: "Prix invalide" }, { status: 400 });
    update.price = price;
  }
  if (active !== undefined) update.active = active;

  const sb = supabaseAdmin();
  const { data, error } = await sb
    .from("products")
    .update(update)
    .eq("id", id)
    .select()
    .single();

  if (error) {
    console.error("[admin/products] DB error", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
  return NextResponse.json(data);
}
