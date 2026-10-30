import { NextResponse, type NextRequest } from 'next/server';
import { createSupabaseServerClient } from '@/lib/supabase/server';

function sanitizeNext(next: string | null, requestUrl: URL): string {
  if (!next) return '/dashboard';
  try {
    // Allow only relative paths beginning with "/" (not "//" protocol-relative)
    if (next.startsWith('/') && !next.startsWith('//')) return next;
    // Allow absolute URLs only if same host as request
    const u = new URL(next);
    if (u.origin === requestUrl.origin) return u.pathname + u.search + u.hash;
  } catch {}
  return '/dashboard';
}

export async function GET(request: NextRequest) {
  const requestUrl = new URL(request.url);
  const { searchParams, origin } = requestUrl;
  const code = searchParams.get('code');

  if (!code) {
    return NextResponse.redirect(`${origin}/auth/auth-error?reason=missing_code`);
  }

  const supabase = createSupabaseServerClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);

  if (error) {
    return NextResponse.redirect(`${origin}/auth/auth-error?reason=${encodeURIComponent(error.message)}`);
  }

  // If next was explicitly provided, honor it (after allowlist check).
  // Otherwise, redirect super_admin to /admin, everyone else to /dashboard.
  if (searchParams.has('next')) {
    const safePath = sanitizeNext(searchParams.get('next'), requestUrl);
    return NextResponse.redirect(`${origin}${safePath}`);
  }

  const { data: { user } } = await supabase.auth.getUser();
  const isAdmin = (user?.app_metadata as any)?.role === 'super_admin';
  return NextResponse.redirect(`${origin}${isAdmin ? '/admin' : '/dashboard'}`);
}
