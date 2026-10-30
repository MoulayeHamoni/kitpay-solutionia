import { timingSafeEqual } from 'crypto';
import type { NextRequest } from 'next/server';

const DEFAULT_SENTINEL = 'change-me-to-a-strong-random-string';

export function assertAdminAuthConfigured(): void {
  const pwd = process.env.ADMIN_PASSWORD;
  if (!pwd || pwd === DEFAULT_SENTINEL || pwd.length < 16) {
    throw new Error('ADMIN_PASSWORD is unset, too short, or still the default. Set a strong value before enabling admin routes.');
  }
}

export function checkAdminAuth(req: NextRequest): boolean {
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected || expected === DEFAULT_SENTINEL || expected.length < 16) return false;
  const provided = req.headers.get('x-admin-pwd') ?? '';
  if (provided.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(provided, 'utf8'), Buffer.from(expected, 'utf8'));
  } catch {
    return false;
  }
}
