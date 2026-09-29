# Security advisories

Public log of security vulnerabilities that were reported to KitPay, and how
they were fixed. Entries are ordered from most recent to oldest.

Reporters are credited by the name or handle they provided. To have a report
published here, follow the disclosure process in [`SECURITY.md`](./SECURITY.md).

## Entry format

Each advisory contains:

- **ID** - a stable identifier of the form `KP-SEC-<year>-<sequence>`.
- **Severity** - Critical / High / Medium / Low (based on impact and exploitability).
- **Status** - Fixed / In progress / Won't fix.
- **Reported** - date the private report was received.
- **Fixed** - date the fix landed in the default branch.
- **Reporter** - name or handle, and a public contact if provided.
- **Summary** - one-line description.
- **Details** - technical description of the vulnerability.
- **Impact** - what an attacker could achieve.
- **Fix** - the patch that resolves it, with a link to the migration or commit.
- **Timeline** - key events from report to fix.

---

## KP-SEC-2026-001 - Unauthenticated payment forgery via public match_payment_* RPC

- **Severity** : Critical
- **Status** : Fixed
- **Reported** : 2026-09-27
- **Fixed** : 2026-09-29
- **Reporter** : [0xMR](https://0xmr.org) (`contact@0xmr.org`), with Bellamech Brahim
- **Summary** : Any caller holding the public Supabase anon key could mark
  an existing pending payment intent as `paid` by calling one of the
  `match_payment_*` RPC endpoints directly, causing KitPay to emit a
  correctly HMAC-signed `payment.succeeded` webhook to the merchant.

### Details

The `match_payment_*` family of Postgres functions
(`match_payment`, `match_payment_v3`, `match_payment_bankily`,
`match_payment_masrvi`, `match_payment_bim`, `match_payment_sedad`,
`match_payment_click`, `match_payment_bcipay`) were declared
`SECURITY DEFINER` so that the trusted server ingestion endpoint
(`/api/sms-ingest`) could match a forwarded operator SMS against a pending
intent while bypassing row-level security.

The definitions did not include a
`REVOKE EXECUTE ... FROM PUBLIC` clause. Postgres grants `EXECUTE` to
`PUBLIC` by default on any function created in the `public` schema, and
Supabase PostgREST automatically exposes every callable public function at
`/rest/v1/rpc/<name>` for anyone holding the anon key. The anon key is
public by design and ships in every browser bundle.

An attacker could therefore:

1. Create or discover an existing pending intent (for example via the
   public `/api/demo` sandbox endpoint, which produces a live-mode intent
   for 5 to 100 MRU).
2. Send one HTTP request:

   ```
   POST /rest/v1/rpc/match_payment_masrvi
   Host: <project-ref>.supabase.co
   apikey: <public sb_publishable_ key>
   Authorization: Bearer <same key>
   Content-Type: application/json

   { "p_amount": <amount>, "p_sender_phone": "<phone>", "p_raw_sms": "test" }
   ```
3. The `SECURITY DEFINER` function updated `status='paid'` on the matched
   intent and enqueued a `payment.succeeded` webhook, which the async
   worker later signed and delivered to the merchant.

### Impact

Any merchant integrated with KitPay could be induced to receive a
validly-signed `payment.succeeded` webhook without any money changing hands.
For merchants that automatically fulfil an order on webhook receipt
(delivery, credit top-up, digital goods, service activation), this is
equivalent to free orders at scale. The forged SMS text is stored in the
`sms_received` column and would show up as the system's own "proof of
payment" in audit trails.

The vulnerability affected production. It did not, to our knowledge, cause
any financial loss between report and fix. No customer data was exposed.

### Fix

Migration `supabase/v37_lockdown_match_payment_rpcs.sql` revokes `EXECUTE`
from `PUBLIC`, `anon` and `authenticated` on all eight `match_payment_*`
functions, and grants `EXECUTE` explicitly to `service_role`. The
legitimate ingestion path (`/api/sms-ingest` using the service role key)
continues to work unchanged.

The migration includes an automated verification block that queries
`information_schema.routine_privileges` and raises an exception if any of
the previously public roles still holds `EXECUTE` on any of the locked
functions, which ensures the fix cannot be silently regressed by future
migrations that recreate the functions without a corresponding revoke.

A rule has been added to `SECURITY.md` requiring every future state-mutating
public-schema function to be paired with an explicit `REVOKE` and, where
appropriate, a targeted `GRANT`.

Additional hardening shipped alongside the migration:

- `notifyPaymentConfirmed()` now refuses to fire when `intent.mode !== 'live'`
  (defence in depth against the same class of confused deputy).
- The cron finalizer `/api/cron/finalize-pending` filters `mode = 'live'`
  in its Supabase query.
- The success page `/success/[ref]` only sends receipts and notifications
  when the intent is in live mode.
- The legacy public endpoint `/api/intent/[ref]` no longer returns the
  full intent row. It now returns a whitelist of non-sensitive fields
  (`ref`, `status`, `mode`, `amount`, `method`, `description`,
  `expires_at`, `paid_at`, `matched_tier`), which prevents leaking
  `client_secret`, `customer_email`, `expected_phone` or `sms_received`
  to unauthenticated callers.

### Timeline

- **2026-09-27** - Report received by 0xMR at
  `contact@solutionia.work` (filtered to spam folder, initial acknowledgement
  delayed).
- **2026-09-29** - Report read, triaged as Critical, fix scoped and applied
  to production. Public disclosure through this advisory and a LinkedIn
  post the same day.

### Credit

Reported responsibly by [0xMR](https://0xmr.org) and Bellamech Brahim.
Their report included a clean proof of concept, a reproduction script and
a concrete remediation recommendation, which made the triage and fix
straightforward. Thank you.
