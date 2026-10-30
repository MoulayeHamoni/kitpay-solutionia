import { NextRequest, NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase";
import { checkAdminAuth } from "@/lib/admin-auth";

export async function GET(req: NextRequest) {
  if (new URL(req.url).searchParams.has('pwd')) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }
  if (!checkAdminAuth(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const sb = supabaseAdmin();
  const [pendingRes, orphansRes, productsRes, recentRes] = await Promise.all([
    sb
      .from("payment_intents")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(50),
    sb
      .from("orphan_sms")
      .select("*")
      .is("resolved_at", null)
      .order("received_at", { ascending: false })
      .limit(50),
    sb.from("products").select("*").order("created_at", { ascending: false }),
    sb
      .from("payment_intents")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(100)
  ]);
  return NextResponse.json({
    pending: pendingRes.data || [],
    orphans: orphansRes.data || [],
    products: productsRes.data || [],
    recentPayments: recentRes.data || []
  });
}
