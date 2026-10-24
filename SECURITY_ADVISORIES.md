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

## KP-SEC-2026-002 - Anon-callable state-mutating RPCs (webhook forgery, cross-tenant reconciliation IDOR, API-key oracle) + orphan RLS policy regression

- **Severity** : Critical (webhook forgery) + High (reconciliation IDOR) + Medium (API-key oracle, orphan policy)
- **Status** : Fixed for Findings 1-2 and the orphan policy (migration v38). Finding 3 (platform-wide Tier 1 matching) and the footnote weaknesses (`generateRef` CSPRNG, `/api/demo` rate-limit) tracked separately for a follow-up advisory.
- **Reported** : 2026-10-24
- **Fixed** : 2026-10-24 (same day)
- **Reporter** : Bechar (`agattbechar@gmail.com`)
- **Summary** : Multiple `SECURITY DEFINER` functions in the `public` schema still lacked an explicit `REVOKE EXECUTE` after KP-SEC-2026-001 was patched. `enqueue_webhook_delivery` could be called with the anon key to produce a validly-signed `payment.succeeded` webhook. `reconcile_orphan` had no ownership check between the orphan and the target intent, letting any registered merchant mark another merchant's pending intent as `paid`. `verify_api_key` acted as an anon oracle for API-key validity. The `members read orphans` row-level policy, as written in `v14_rls_enable.sql`, contained a tautology branch (`id IN (SELECT id FROM orphan_sms o2 WHERE o2.id = orphan_sms.id)`) that would leak every merchant's orphan SMS content, phone and amount to any authenticated user.

### Details

**Finding 1 - `enqueue_webhook_delivery` anon-callable (Critical)**

`public.enqueue_webhook_delivery(uuid, text, jsonb)` (`supabase/v22_enqueue_webhook_delivery.sql`) is `SECURITY DEFINER` and had `GRANT EXECUTE TO service_role` only. The required `REVOKE EXECUTE FROM PUBLIC` was never emitted. Postgres grants `EXECUTE` to `PUBLIC` by default and Supabase PostgREST exposes every callable public function at `/rest/v1/rpc/<name>`. KP-SEC-2026-001's remediation migration (`v37`) only covered the `match_payment_*` family.

Any caller holding the anon key could insert arbitrary rows into `webhook_deliveries` for any merchant that has at least one enabled webhook subscribed to the chosen event type:

```
POST /rest/v1/rpc/enqueue_webhook_delivery
apikey: <public sb_publishable_ key>
Content-Type: application/json

{
  "p_merchant_id": "<victim merchant uuid>",
  "p_event_type": "payment.succeeded",
  "p_payload": {"id":"evt_forged","type":"payment.succeeded","livemode":true,
    "data":{"object":{"ref":"<real pending ref>","status":"paid","amount":9999}}}
}
```

The delivery worker (`/api/cron/deliver-webhooks`) then signs the stored payload with the merchant's webhook secret (`X-KitPay-Signature`, HMAC-SHA256) and POSTs it to the configured endpoint. For merchants that fulfil orders on webhook receipt without re-querying `/v1/intents/{ref}`, this is equivalent to free goods. Merchants that follow the documented verify-before-deliver pattern are not exposed to unpaid fulfilment, but the forged event still lands and pollutes reconciliation. Merchant UUIDs are discoverable through the `anon read merchant public fields` policy on the `merchants` table.

**Finding 2 - `reconcile_orphan` cross-tenant IDOR (High)**

`public.reconcile_orphan(uuid, text, text)` (`supabase/schema.sql`) is `SECURITY DEFINER` and validated only that the orphan existed and was unresolved, and that the target intent existed and was `pending`. It performed no ownership check between the orphan's merchant and the target intent's merchant before `UPDATE payment_intents SET status='paid', matched_tier=3, ... WHERE ref = p_target_ref`.

The dashboard server action `src/app/dashboard/reconciliation/actions.ts` filters the orphan by `merchant_id = merchant.id` but forwards `args.target_ref` unvalidated. Server-action arguments are caller-controlled.

A registered merchant could therefore:

1. Produce an own unresolved orphan (self-SMS to their inbound number with a mismatched amount).
2. Place an order at a victim merchant through the public checkout and note the resulting `ref`.
3. Call the reconciliation server action with `{ orphan_id: <own orphan>, target_ref: <victim ref> }`.
4. The victim's intent flips to `status='paid', matched_tier=3`, with the attacker's SMS text stored as proof of payment.

Additionally, because `reconcile_orphan` was itself anon-callable (same root cause as Finding 1), the same effect could be achieved without a merchant account if the attacker knew both an unresolved orphan UUID and a target `ref`.

**Finding 3 (Medium) - `verify_api_key` anon oracle**

`public.verify_api_key(text)` (`supabase/v21_verify_api_key.sql`) is `SECURITY DEFINER` with no `REVOKE`, exposing an oracle that returns `(merchant_id, api_key_id, mode, scopes)` for any valid key submitted by an anon caller, and silently updates `last_used_at` on every hit (polluting audit logs).

**Policy fix - `members read orphans` tautology**

`v14_rls_enable.sql` defined the `members read orphans` policy on `orphan_sms` with a second `OR` branch `orphan_sms.id IN (SELECT id FROM orphan_sms o2 WHERE o2.id = orphan_sms.id)` that is a tautology (equivalent to `TRUE` whenever the row exists). As written, the policy allowed every authenticated user to read every merchant's orphan SMS content, phone, amount and method. Live production had, through a sequence of policy drops/recreates, converged to `is_super_admin()` only, which was functionally safe but did not scope members to their own merchant's orphans. The policy has been rewritten to use `user_is_member_of(merchant_id) OR is_super_admin()`.

### Impact

- Finding 1 enabled a correctly-signed forged `payment.succeeded` webhook to be delivered to any merchant with webhooks enabled, with the attack reachable from any browser holding the public anon key. Same class as KP-SEC-2026-001.
- Finding 2 enabled any registered merchant to flip arbitrary pending intents of any other merchant to `paid`, with the attacker's SMS stored as the system's own evidence of payment.
- Finding 3 enabled brute-forced validation of API keys and extraction of their merchant/scope metadata.
- The orphan policy regression (as written in the migrations) would have leaked, for every merchant, the full SMS content, parsed phone and parsed amount of every orphan — a cross-tenant payment-data leak. The live schema had already drifted to a safer form, so no exploit was reachable in production between report and fix.

No financial loss and no exposure of customer data is known to have occurred between report and fix.

### Fix

Migration [`supabase/v38_lockdown_remaining_rpcs.sql`](./supabase/v38_lockdown_remaining_rpcs.sql) (same SQL applied to the shared Supabase project as `v40` in the private deployment repo):

- Rewrites `public.reconcile_orphan(uuid, text, text)` with explicit guards: rejects Tier 4 orphans (`merchant_id IS NULL`) and rejects any call where `v_intent.merchant_id <> v_orphan.merchant_id`. `SET search_path = public, extensions, pg_temp` added for consistency with v37/v38 hardening.
- `REVOKE EXECUTE ... FROM PUBLIC, anon, authenticated` on `enqueue_webhook_delivery`, `reconcile_orphan`, `verify_api_key`, `expire_old_intents`. `GRANT EXECUTE ... TO service_role` kept on all four.
- Drops and recreates the `members read orphans` row-level policy with `((merchant_id IS NOT NULL AND user_is_member_of(merchant_id)) OR is_super_admin())`.
- Automated verification block that queries `information_schema.routine_privileges` and `pg_policies` and raises an exception if any of the previously public roles still holds `EXECUTE`, or if the new orphan policy is missing.
- `NOTIFY pgrst, 'reload schema'` to flush the PostgREST cache.

Known not covered by this advisory and tracked for a follow-up (expected within the standard disclosure window):

- Platform-wide Tier 1 matching across the dedicated per-operator `match_payment_bim` / `_masrvi` / `_sedad` / `_click` / `_bcipay` / `_bankily` functions, composed with the unauthenticated `/api/demo` endpoint (reporter's Finding 3). Mitigation requires passing the receiving merchant identity through `/api/sms-ingest` to the matchers, plus route-level rate-limiting and sandbox isolation on `/api/demo`.
- `generateRef()` in `src/lib/format.ts` uses `Math.random()` (~31 bits of entropy) for refs that appear in `/pay/` and `/success/` URLs. The REST API already uses `randomBytes()` via `src/lib/api/intents.ts`; the checkout/demo path will be migrated to the same.

### Timeline

- **2026-10-24, morning (Nouakchott)** - Report received at `contact@solutionia.work` with full repro steps against public commit `2c8707117c1e` of `MoulayeHamoni/KitPay-SolutionIA`.
- **2026-10-24, same day** - Report read, each finding verified against the two source trees (public OSS + private deployment), fix migration `v40` written and applied to the shared Supabase project `rpgmzookqozeijtexmgl`, verification block passed, PostgREST reloaded. Public disclosure through this advisory.

### Credit

Reported responsibly by Bechar (`agattbechar@gmail.com`). The report derived every finding from the public MIT-licensed source alone, with no interaction with vendor-operated systems. It included precise file-and-line references, reproduction steps written against the reader's own instance, and concrete fix recommendations, which made triage and verification fast. Thank you.

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
