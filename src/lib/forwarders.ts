import { randomBytes, createHash } from 'crypto';

// Generates a new forwarder bearer token. Server-only (uses Node crypto).
// Format: kpf_<base64url(16 random bytes)> (22 chars after prefix, 26 total).
// The plaintext token is shown to the operator exactly once at creation and never
// stored. Only the sha256 digest lives in forwarder_devices.token_hash.
export function generateForwarderToken(): string {
  return 'kpf_' + randomBytes(16).toString('base64url');
}

// Produces the sha256 hex digest the server uses to look up a device.
// Called from the dashboard server actions (storage) and matches what
// verify_forwarder_token computes inside Postgres.
export function hashForwarderToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
