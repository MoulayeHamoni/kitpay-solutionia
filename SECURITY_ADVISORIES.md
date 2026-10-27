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

## KP-SEC-2026-003 - Merchant table over-exposed to anon and authenticated roles, test-key reaches live intents, orphan merchant attribution regression

- **Severity** : Critical (anon read of every column of `merchants` including KYC documents) + High (test API keys reach live intents GET/cancel) + Medium (orphan attribution regression bricking the reconciliation queue)
- **Status** : Fixed for F1, F3, F4, idempotency scope, and the webhook SSRF guard (OSS deliver-webhooks route). F2 (shared `WEBHOOK_SECRET`) and the first-report Finding 3 (platform-wide Tier 1 matching, including the generateRef CSPRNG) remain tracked for a follow-up architectural PR.
- **Reported** : 2026-10-27
- **Fixed** : 2026-10-27 (same day)
- **Reporter** : Bechar (`agattbechar@gmail.com`)
- **Summary** : A second static review against commit `d2375cc` surfaced four additional issues, two of which touch the payment boundary. The REST `GET /v1/intents/{ref}` and `POST /v1/intents/{ref}/cancel` endpoints did not restrict reads and writes to the API key's mode, so a merchant's own `kp_test_` key could fetch any of that merchant's live intents (including `sms_received`, `customer_phone`, `client_secret`) and cancel them while pending. The `merchants` table had `anon` `SELECT USING(true)` policy with no column restriction, letting anyone with the public anon key read `kyc_documents`, `nif`, `rc_number`, `kyc_notes`, `owner_password_hash`, `contact_email` and `owner_email` for every merchant; a parallel `members update merchant` policy let any accepted member of any role update any column, enabling self-serving KYC approval or plan upgrades. The six per-method `match_payment_*` functions inserted orphans with `merchant_id = NULL`; combined with the Tier-4 guard introduced in v40, that bricked the reconciliation workflow for 64 unresolved orphans already in production. Three smaller items worth tracking: the OSS `deliver-webhooks` route fetched merchant-supplied URLs with no SSRF filter, test-mode webhook events were still delivered to merchant endpoints with `livemode: false`, and the idempotency UNIQUE constraint did not scope by `mode`.

### Details

**F1 - Test API keys reach live intents (High)**

`src/app/api/v1/intents/[ref]/route.ts` (GET) and `src/app/api/v1/intents/[ref]/cancel/route.ts` (POST) filtered the Supabase query by `ref` and `merchant_id` from the authenticated key's context, but never by `mode`. A merchant's own `kp_test_` key could therefore read and cancel their live intents. The GET response was serialized under the key's mode (test), which still returned `sms_received`, `customer_phone`, `client_secret` and the full intent payload. The cancellation webhook took its `livemode` flag from the API key's mode, not from the intent being cancelled, so a live-mode cancellation emitted an event marked `livemode: false`. The cancel UPDATE also lacked a `status='pending'` guard, leaving a check-then-update race.

**F2 - Shared `WEBHOOK_SECRET` for `/api/sms-ingest` (Critical conditional on reachability)**

`src/app/api/sms-ingest/route.ts:87-90` validates one global `WEBHOOK_SECRET` environment variable for every caller. Nothing in the request is bound to a specific merchant or forwarder device. `docs/android-setup.md` has the operator paste this secret into the MacroDroid configuration on every forwarding phone. In a multi-forwarder deployment, any party who obtains the secret from any forwarder config can submit a correctly-formatted synthetic SMS and the matcher pipeline will mark a legitimate matching live, pending, unexpired intent as paid, emit the signed `payment.succeeded` webhook, send the receipt email, and update dashboards. The attack is bounded by the matching logic: the amount and expected_phone must line up for Tier 1, or the amount-only fallback must be unambiguous. In the current production deployment the forwarder count is one (operator-owned), which bounds reachability today but does not solve the design flaw.

**F3 - Orphan rows from per-method matchers have `merchant_id = NULL` (Medium)**

The six per-method matchers (`match_payment_bankily`, `_masrvi`, `_bim`, `_sedad`, `_click`, `_bcipay`) built in v26-v36 all insert into `orphan_sms` using the 4-column form (no `merchant_id`), falling back to the column default (`NULL`). The reconciliation page and server action filter orphans by `merchant_id = <caller's merchant>`, so these orphans were never visible from any dashboard; v40 then added the `merchant_id IS NULL` guard inside `reconcile_orphan`, which blocked even the super-admin path. 64 unresolved orphan rows in production were in this state at report time.

**F4 - Merchant table over-exposed (Critical)**

`v14_rls_enable.sql:40-50` and the live `pg_policies` state agreed on two problematic policies:

- `anon read merchant public fields` : `FOR SELECT TO anon USING (true)` with no column restriction, over a table whose columns include `owner_password_hash`, `nif`, `rc_number`, `kyc_notes`, `kyc_documents` (jsonb payload including the uploaded KYC files JSON structure), `contact_email`, `owner_email`.
- `members update merchant` : `FOR UPDATE TO authenticated USING(user_is_member_of(id) OR is_super_admin())` with no column-level restriction and no check against `merchant_members.role`. Any accepted member of any role could update their own merchant's `status`, `plan_id`, `kyc_verified_at`, `kyc_notes`, `kyc_documents` or `owner_password_hash`, enabling self-serving KYC approval and plan upgrades.

The effective privileges in production confirm this is not conditional: `anon` and `authenticated` both hold `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `public.merchants` at the table-privilege level, and RLS does the filtering. Three merchants in production had `kyc_documents` populated at report time; `nif` and `rc_number` were populated for one of them. `owner_password_hash` was not populated for any merchant, which is why no credentials have leaked, but the write path for that column was reachable from any authenticated member session.

**Smaller items**

- `src/app/api/cron/deliver-webhooks/route.ts` fetches `webhooks.url` directly from a merchant-controlled column. A merchant configuring `http://169.254.169.254/latest/meta-data/` or `http://127.0.0.1:...` reaches the cloud metadata service or any service bound to the Netlify/Vercel egress interface. The production deployment delivers webhooks via n8n, not this route, so the exposed path only applies to self-hosted operators of the OSS code - but the shape is still worth fixing in the public source.
- Test-mode intents emit webhooks to the same merchant subscription with `livemode: false`. Separate test-mode endpoints or an explicit subscription per mode would be cleaner.
- `idempotency_keys` carried `UNIQUE(merchant_id, key)` without `mode`. A merchant replaying a key across test and live would collide.

### Fix

Migration [`supabase/v39_followup_bechar.sql`](./supabase/v39_followup_bechar.sql) (private deployment repo mirrors it as `v41`):

- Drops the `anon read merchant public fields` and `members update merchant` policies on `merchants`. All reads and writes in the application already go through the admin (service_role) client (`createSupabaseAdminClient`), so the two removed policies were unused in the live code paths. `members read merchant` is kept for future use since the dashboard reads continue through `service_role` today.
- Rewrites the six per-method matchers to resolve a fallback `merchant_id` from `merchant_operators` (single enabled merchant for the method) and attribute every `orphan_sms` row at insert time. If multiple merchants have the method enabled the orphan goes to the super-admin-only queue. Each function keeps the hardening introduced in v37/v38 (`SECURITY DEFINER`, `SET search_path = public, extensions, pg_temp`).
- Backfills unresolved orphans in production where derivable (`parsed_method` → single enabled merchant).
- Adds `mode` to `idempotency_keys` and recreates the `UNIQUE(merchant_id, key, mode)` constraint.
- Automated verification blocks fail-fast if the merchants policies remain or if the attribution block is missing from any of the six functions.

Code patches (both repos):

- `src/app/api/v1/intents/[ref]/route.ts` : `GET` adds `.eq('mode', ctx.mode)` to the lookup.
- `src/app/api/v1/intents/[ref]/cancel/route.ts` : `POST` adds `.eq('mode', ctx.mode)` to the lookup and the UPDATE, adds `.eq('status', 'pending')` to the UPDATE to close the race, and derives `livemode` from the updated intent (`updated.mode === 'live'`) rather than from the API key.
- OSS only - `src/app/api/cron/deliver-webhooks/route.ts` : adds an `assertPublicUrl()` guard that rejects URLs resolving to RFC1918, loopback, link-local (including the IMDS `169.254.169.254`), ULA, multicast, hostnames ending in `.localhost / .internal / .local`, and non-http(s) protocols. Rejected deliveries are marked `failed` with `response_body = 'url_rejected: <reason>'`.

Still tracked for a follow-up architectural PR (same batch as the first-report Finding 3):

- F2 (shared `WEBHOOK_SECRET`) : per-device or per-merchant ingest credentials, server-side binding of merchant/device identity, replay protection, rotation.
- First-report Finding 3 : threading the receiving merchant identity through `/api/sms-ingest` so Tier 1 matching is merchant-scoped. The orphan attribution introduced in v41/v39 is a correct interim since it uses the same single-merchant assumption.
- `generateRef()` migrates from `Math.random()` to the `randomBytes` helper in `src/lib/api/intents.ts`.
- Test-mode webhook delivery isolation.

### Timeline

- **2026-10-27, morning (Nouakchott)** - Follow-up report received at `contact@solutionia.work` against commit `d2375cc`. Every finding verified against both source trees and live Supabase privileges (including a live check that confirmed `anon` and `authenticated` hold full table privileges on `merchants`, confirming F4 is unconditional).
- **2026-10-27, same day** - Migration `v41_followup_bechar.sql` (private) / `v39_followup_bechar.sql` (public OSS) applied to the shared Supabase project, code patches shipped in both repos, verification blocks passed, PostgREST reloaded. Public disclosure through this advisory.

### Credit

Reported responsibly by Bechar (`agattbechar@gmail.com`). The follow-up derived from static review of the public source plus unauthenticated loads of the deployed site's public pages and JS bundles, with no payment-changing requests sent and no database interaction. The report corrected two assessments: F3 was initially downgraded as "the dashboard already filtered these" but v40's Tier-4 guard made the regression a live operational problem (64 stuck orphans) rather than a non-issue, and F4 was offered as conditional on effective grants but was in fact unconditional in production. Thank you.

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
