import { NextRequest, NextResponse } from "next/server";
import { assertAdminAuthConfigured, checkAdminAuth } from "@/lib/admin-auth";

assertAdminAuthConfigured();  // throws at module-load if unset/default/short

// In-memory rate limiter: max 5 attempts per IP per 15 min
const attempts = new Map<string, { count: number; resetAt: number }>();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;

function getIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    req.headers.get("x-real-ip") ??
    "unknown"
  );
}

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || now > entry.resetAt) {
    attempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_ATTEMPTS;
}

function resetAttempts(ip: string): void {
  attempts.delete(ip);
}

export async function POST(req: NextRequest) {
  if (new URL(req.url).searchParams.has('pwd')) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  const ip = getIp(req);

  if (isRateLimited(ip)) {
    return NextResponse.json(
      { error: "too_many_attempts" },
      { status: 429, headers: { "Retry-After": "900" } }
    );
  }

  // The login route checks the password from the request body (not the header),
  // so we re-implement the check inline rather than calling checkAdminAuth which
  // reads from the x-admin-pwd header.
  const body = await req.json().catch(() => ({}));
  const { password } = body;

  if (!password || typeof password !== "string") {
    return NextResponse.json({ error: "invalid" }, { status: 401 });
  }

  // Use checkAdminAuth via a synthetic request that has the password in the
  // x-admin-pwd header, so the timingSafeEqual path is shared.
  const syntheticReq = new Request(req.url, {
    headers: { 'x-admin-pwd': password },
  });
  const match = checkAdminAuth(syntheticReq as unknown as NextRequest);

  if (match) {
    resetAttempts(ip);
    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "invalid" }, { status: 401 });
}
