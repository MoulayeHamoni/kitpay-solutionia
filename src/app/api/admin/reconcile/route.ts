import { NextRequest, NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase";
import { notifyManualReconciliation } from "@/lib/telegram";
import type { PaymentIntent } from "@/lib/types";
import { checkAdminAuth } from "@/lib/admin-auth";

export async function POST(req: NextRequest) {
  if (new URL(req.url).searchParams.has('pwd')) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }
  if (!checkAdminAuth(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const { orphan_id, ref } = await req.json();
  if (!orphan_id || !ref) {
    return NextResponse.json({ error: "missing fields" }, { status: 400 });
  }
  const sb = supabaseAdmin();
  const { data, error } = await sb.rpc("reconcile_orphan", {
    p_orphan_id: orphan_id,
    p_target_ref: ref,
    p_admin: "admin"
  });
  if (error) {
    console.error("[reconcile] RPC failed", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }

  // Notification Telegram (non bloquante)
  try {
    const { data: intent } = await sb
      .from("payment_intents")
      .select("*")
      .eq("ref", ref)
      .single();
    if (intent) {
      notifyManualReconciliation(intent as PaymentIntent, orphan_id).catch((e) =>
        console.error("Telegram notif (reconcile) failed:", e)
      );
    }
  } catch (e) {
    console.error("Failed to fetch intent for notification:", e);
  }

  return NextResponse.json(data);
}
