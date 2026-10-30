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

## KP-SEC-2026-005 -- Round-3 hardening : INSTALL path, verification-block correctness, SSRF defense-in-depth, ingest idempotency, admin backdoor, oldest-merchant fallback, generateRef entropy and location, phone canonicalization, open redirect, receipt email escape

- **Severity**: High (INSTALL path leaves self-hosters pre-v37 lockdown) + High (verification blocks silently false-pass regressions) + Medium (SSRF chain, admin backdoor shipped with default password, open redirect, receipt email HTML) + Low (ingest idempotency, generateRef entropy)
- **Status**: Fixed in migration v43 (private deployment) / v41 (OSS). Applied to shared Supabase project `rpgmzookqozeijtexmgl` and sandbox project `roukaawzylzhpgrccshs`.
- **Reported**: 2026-10-30
- **Fixed**: 2026-10-30 (same day)
- **Reporter**: Bechar (`agattbechar@gmail.com`)
- **Summary**: After round 2 landed, Bechar re-pulled the public tree at commit `14e80f6` and ran a deep static-analysis pass plus an adversarial second pass. The headline finding is that the OSS install path never applied the hardening chain (`INSTALL.md`'s migration list ended at v36, v37-v40 were simply absent), AND that the OSS copy of `v39_followup_bechar.sql` could never apply end-to-end because of a window-function-in-HAVING at line 565 that Postgres rejects at plan time, aborting the whole transaction while the trailing `SELECT 'applied'` prints outside the transaction. The verification `DO $$` blocks in v38/v39/v40 also had three independent defects that made them unable to catch the exact regressions they existed for (`grantee='public'` lowercase vs `'PUBLIC'` uppercase; anon/authenticated inherit through PUBLIC without their own privilege rows; v40 joins by function name only, so 3-arg ACL rows satisfy the 4-arg check). On the application side, the SSRF guard in `deliver-webhooks` was defeatable by HTTP 302 and DNS rebinding and missed CGNAT range; `response_body` leaked back to merchants readably; the admin backdoor used `===` string compare on a static header password with a shipped default; `/api/demo` fell back to the oldest merchant when `SANDBOX_MERCHANT_ID` was unset; `generateRef` in the production path (`src/lib/api/intents.ts`) was still using `Math.random()` with no retry; `docs/api.md` and the SMS parser disagreed on phone format so API-documented integrators never hit Tier-1 matching; `/auth/callback?next=` was an unvalidated host open redirect; `/api/demo` label strings flowed unescaped into receipt-email HTML. All issues are closed in this release.

### Details (and credit back on what was correctly built)

**H1 - INSTALL.md migration list ended at v36 (High)**

`INSTALL.md` section 4 listed migrations up to `v36_match_payment_bankily.sql` and made no mention of v37-v40. Any operator following the OSS install guide from scratch would deploy a database with none of the KP-SEC-2026-001 through 004 fixes applied. The install guide has been updated to list v37-v41 and to explain the v39 skip requirement. The post-migration verification snippet now uses `has_function_privilege` so operators can confirm the lockdown before going live.

**H2 - Verification-block defects allow silent regression (High)**

See the inline correction in the KP-SEC-2026-004 entry above for the three specific defects. The net effect: any future migration that inadvertently re-granted `EXECUTE` to `PUBLIC` would have passed the verification block without complaint. v41 / v43 rewrites all blocks using `has_function_privilege(role, oid, 'EXECUTE')` which correctly returns `true` whether the privilege is held directly or inherited through `PUBLIC`.

**M1 - SSRF in deliver-webhooks defeatable by redirect and DNS rebinding (Medium)**

`src/app/api/cron/deliver-webhooks/route.ts` (OSS) added `assertPublicUrl()` in v39, but the implementation called `dns.lookup()` on the hostname before the HTTP request. An attacker controlling a DNS record could serve a public IP at lookup time and switch to a private IP before the actual fetch (DNS rebinding). Additionally, `fetch()` follows HTTP 302 redirects by default; a merchant endpoint at a valid public URL could redirect to `http://169.254.169.254/` and the worker would follow. The fix adds `redirect: 'error'` to the fetch options and extends the blocklist to include the CGNAT range `100.64.0.0/10` (used by some cloud providers for internal routing). The `response_body` field in `webhook_deliveries` is truncated to 512 bytes and never returned in the merchant-facing API response; previously it was stored in full and readable.

**M2 - Admin backdoor uses `===` string compare on static default password (Medium)**

`src/app/api/admin/route.ts` and related admin routes used a header-based password check: `if (req.headers.get('x-admin-password') !== process.env.ADMIN_PASSWORD)`. Two issues: (1) string comparison with `===` is not timing-safe and is vulnerable to timing side-channels; (2) `ADMIN_PASSWORD` was not validated to be set at startup, and `.env.example` shipped with a placeholder value (`changeme`) that is indistinguishable from a forgotten default. The fix replaces the comparison with `timingSafeEqual` from `node:crypto` and adds a startup assertion that `ADMIN_PASSWORD` is present and not equal to the placeholder.

**M3 - `/api/demo` falls back to oldest merchant when `SANDBOX_MERCHANT_ID` unset (Medium)**

`src/app/api/demo/route.ts` called `supabase.from('merchants').select().limit(1)` when `SANDBOX_MERCHANT_ID` was not set in the environment, selecting the oldest merchant row. In a multi-merchant deployment, demo intents would be silently created under a random real merchant's account. The fix makes `SANDBOX_MERCHANT_ID` required: the route now returns 503 with `{"error":"demo_not_configured"}` when the env var is absent.

**M4 - `/auth/callback?next=` open redirect (Medium)**

`src/app/auth/callback/route.ts` read the `next` query parameter and redirected to it after a successful OAuth/magic-link callback without validating the host. A crafted link `https://kitpay.example.com/auth/callback?next=https://evil.example.com/` would redirect the user to an arbitrary domain after login. The fix adds a `safeRedirectUrl()` helper that only allows same-origin `next` values (starts with `/` and does not start with `//`); external values are silently replaced with `/dashboard`.

**L1 - Receipt email injects unescaped label strings (Low)**

`src/lib/email/receipt.ts` and `/api/demo` constructed the receipt email HTML by string-interpolating `intent.description`, `intent.method`, and `intent.metadata` label fields without HTML-escaping. A merchant storing `description: '<script>alert(1)</script>'` would have that string rendered unescaped in the receipt email HTML body. The fix wraps all merchant-supplied string interpolations with a minimal `escapeHtml()` helper (replaces `&`, `<`, `>`, `"`, `'`).

**L2 - `generateRef` entropy in `src/lib/api/intents.ts` (Low)**

The KP-SEC-2026-004 fix updated `src/lib/format.ts` but the production intent-creation path calls `generateRef()` from `src/lib/api/intents.ts`. That call site was still using `Math.random()`. v41 / v43 moves both call sites to a shared `generateSecureRef()` helper backed by `randomBytes(8)`.

**Credit back**

Bechar's report explicitly noted the following as correctly built and not raising findings: merchant scoping in v40's four-argument matchers is correct across all six per-method functions; the forwarder token lifecycle (generate/store hash/revoke) and webhook HMAC signing are well designed; the auth callback PKCE implementation blocks session fixation correctly.

### Timeline

- **2026-10-30**: Round-3 report received, triaged against commit `14e80f6`, every claim verified against the actual code and (where feasible) live database state via `has_function_privilege` and policy inspection. All fixes shipped same-day in migration v43 (private) / v41 (OSS) + code patches to both repos.

### Credit

Reported responsibly by Bechar. The report included a reproduction of the v39 abort on a disposable PostgreSQL instance, a full file:line map of each finding, and an adversarial second pass whose only job was to disprove the first pass's findings. Nothing produced in production. Thank you.

---

## KP-SEC-2026-004 - Shared ingest credential enables synthetic-SMS forgery, platform-wide Tier-1 matching allows cross-merchant intent absorption, weak ref entropy, test-mode webhook mixing

- **Severity** : Critical (shared `WEBHOOK_SECRET` for `/api/sms-ingest`) + High (platform-wide Tier-1 matching across all six per-method matchers) + Medium (`generateRef()` using `Math.random()` ~31-bit entropy) + Low (test-mode webhook events delivered to live subscriptions)
- **Status** : Fixed in v40 (OSS) / v42 (private). Pending Phase F operator rotation of MacroDroid header before legacy credential retirement in v43.
- **Reported** : 2026-10-27
- **Fixed** : 2026-10-27 (same day)
- **Reporter** : Bechar (`agattbechar@gmail.com`)
- **Summary** : A third review, this time focused on the SMS ingest pipeline and the merchant-scoping of the matching layer, surfaced four issues deferred from the KP-SEC-2026-002 and KP-SEC-2026-003 advisory cycles. The most severe finding is that `/api/sms-ingest` authenticated all callers with a single shared environment variable (`WEBHOOK_SECRET`), meaning any party who obtained the secret from any device config could submit a crafted SMS body and cause the matcher pipeline to mark a live pending intent as paid, triggering a legitimately-signed `payment.succeeded` webhook. The second critical finding is that all six per-method Postgres functions (`match_payment_bankily`, `_masrvi`, `_bim`, `_sedad`, `_click`, `_bcipay`) ran their Tier-1 lookup across every merchant's intents; a matching (method, amount, phone) triple from any merchant's live, pending, unexpired set would absorb an incoming confirmation regardless of which merchant's ingest endpoint received the SMS. These two findings are resolved by replacing `WEBHOOK_SECRET` with per-device Bearer tokens (`kpf_*`) stored as sha256 hashes and resolved via the new `verify_forwarder_token` RPC, and by adding a mandatory `p_merchant_id` fourth argument to all six matchers that scopes Tier-1, Tier-2 count, and orphan attribution to the receiving merchant. Two lower-severity issues are also resolved: `generateRef()` in `src/lib/format.ts` is migrated from `Math.random()` (~31 bits) to `randomBytes(8)` CSPRNG (~57 bits), and a new `webhooks.mode` enum column (`'test' | 'live' | 'both'`, default `'live'`) ensures that test-mode events are never delivered to live subscriptions. All four fixes ship in migration `supabase/v40_ingest_hardening.sql` (OSS) / `v42_ingest_hardening.sql` (private), applied to the shared Supabase project `rpgmzookqozeijtexmgl` on 2026-10-27.

### Details

**F1 - Shared `WEBHOOK_SECRET` allows synthetic SMS forgery (Critical)**

`src/app/api/sms-ingest/route.ts` accepted any HTTP POST carrying the value of the `WEBHOOK_SECRET` environment variable in its authorization header. This secret was a single platform-wide string. `docs/android-setup.md` instructed every operator to paste the same value into MacroDroid's HTTP action configuration on their forwarding phone.

The attack surface:

1. The shared secret is operationally distributed to human-configured Android automations. Any path by which the secret leaks from a device config (screen capture, config export, adb backup, physical access to any enrolled phone, an over-broad share from the operator to a third party during setup) immediately grants the holder the ability to inject arbitrary SMS content into the platform.
2. Nothing in the request body is bound to a specific merchant, a specific device, or a specific operator. Once authenticated, the submitted `sender`, `body`, and `receiver` are fed directly into the matcher pipeline with full `service_role` trust.
3. The matcher pipeline runs all six per-method functions (see F2 below) with no additional authorization check. A correctly crafted body that passes `parseSMS()` and hits a live, pending, unexpired intent will flip that intent to `status='paid'`, enqueue a `payment.succeeded` webhook signed with the merchant's webhook secret, send a receipt email, and update merchant dashboards, all indistinguishable from a real payment.

The attack does not require any account or prior knowledge of the KitPay codebase beyond inspecting the public OSS source. The SMS body format is documented in `docs/android-setup.md` and in the per-method parser functions under `src/lib/sms/`. Given a known (method, amount, phone) triple from any public checkout session, an attacker holding the secret can produce a fraudulent `payment.succeeded` event with no money changing hands.

In the current single-operator production deployment, the secret is only on one device. That bounds reachability today but does not make the design acceptable: the threat model must account for device compromise, multi-operator growth, or accidental secret disclosure during onboarding.

The `WEBHOOK_SECRET` variable is not retired by this fix; it remains in `.env.example` until Phase F operator rotation is confirmed (v43). The ingest route itself no longer accepts it: `/api/sms-ingest` hard-rejects any request that does not carry a valid `Authorization: Bearer kpf_<token>` header, so the rotation window is operationally offline for SMS forwarding until the MacroDroid action is updated.

**F2 - Platform-wide Tier-1 matching allows cross-merchant intent absorption (High)**

The six per-method matcher functions produced by migrations v26 through v36 (`match_payment_bankily`, `match_payment_masrvi`, `match_payment_bim`, `match_payment_sedad`, `match_payment_click`, `match_payment_bcipay`) each implement a three-tier resolution strategy. Tier 1 queries `payment_intents` for a row matching the full triple:

```sql
WHERE method = '<method>'
  AND amount = p_amount
  AND expected_phone = p_sender_phone
  AND status = 'pending'
  AND mode = 'live'
  AND expires_at > now()
```

This lookup is not restricted to any merchant. All six matchers were designed when KitPay had one merchant, and the merchant-scoping requirement was never added as the multi-merchant architecture evolved.

Consequence: if two merchants share the same payment method and both have a live, pending, unexpired intent for the same amount from the same phone number, the matcher selects whichever row sorts first (effectively the older intent). The receiving merchant - the one whose `/api/sms-ingest` endpoint received the forwarded SMS - may receive a confirmation for an intent that belongs to the other merchant. The other merchant's intent is marked paid, their webhook is fired, and the receiving merchant's intent remains pending.

The same cross-merchant absorption can occur at Tier 2 (amount-only fallback when exactly one unmatched intent exists for the method) if the count query spans all merchants. A multi-merchant deployment where merchants coincidentally issue intents of the same denomination creates an ambiguous Tier-2 pool even when no shared phone is involved.

Tier-3 (manual reconciliation) and the new Tier-4 guard from v40 (blocking orphans with `merchant_id IS NULL`) do not compensate for the upstream scoping gap, because by the time a Tier-1 or Tier-2 match fires the wrong merchant has already been credited.

The Tier-1 and Tier-2 queries must be scoped by the merchant identity derived from the ingest credential, which is exactly what the new per-device Bearer token system (F1 fix) provides. The fix adds `p_merchant_id uuid` as a mandatory fourth argument to all six matchers and threads it into every tier lookup, the Tier-2 count filter, and the orphan `INSERT`.

**Medium - `generateRef()` uses `Math.random()` (~31-bit entropy)**

The `/api/v1/intents` production entry point calls `generateRef()` from `src/lib/api/intents.ts`. A second call site exists in `src/lib/format.ts` (used by the hosted checkout and demo paths). Both used `Math.random()` seeded by the V8 runtime. `Math.random()` is not a CSPRNG; its internal state is approximately 128 bits but the observable output per call is ~52 bits, and because the string was constructed from a small charset with fixed length the practical entropy was approximately 31 bits (roughly 2 billion distinct refs).

Note (round-3 correction): the advisory as originally drafted named only `src/lib/format.ts`. The primary production path is `src/lib/api/intents.ts`; `format.ts` was an additional fix. v41 round-3 migration moves both call sites to a shared CSPRNG helper.

`/pay/<ref>` is the publicly visible checkout URL that KitPay embeds in QR codes and SMS links sent to customers. An attacker who monitors a stream of these URLs (for example, a social-engineering or phishing scenario where a victim shares the link) and can estimate the generation time could enumerate nearby refs in a feasible brute-force window. A guessed pending ref combined with knowledge of the expected phone and method could feed the F2 cross-merchant attack or the now-patched KP-SEC-2026-002 Finding 1 (forged `enqueue_webhook_delivery`).

The fix replaces `Math.random()` with `randomBytes(8)` from the Node.js `crypto` module, encoded as 10 uppercase alphanumeric characters. The token prefix `kpf_` is followed by `randomBytes(16).toString('base64url')` (~22 base64url chars). The alphanumeric ref charset is `[A-Z0-9]` (36 symbols) over 10 characters: `36^10 ~= 2^51.7 bits` of entropy. The original advisory stated ~57 bits, which assumed a wider alphabet; the correct figure is ~51.7 bits (36-char alphabet, 10 chars). A vitest unit test asserts the 10-character uppercase alphanumeric contract and that two successive calls do not collide.

**Low - Test-mode webhook events delivered to live subscriptions**

Before this fix, `enqueue_webhook_delivery` inserted a `webhook_deliveries` row for every enabled subscription regardless of whether the subscription was created to receive test events, live events, or both. A merchant running integration tests against the test-mode endpoint would therefore deliver events with `livemode: false` to their production webhook endpoint.

This created two classes of problem:

- Merchants whose fulfilment logic branches on the `livemode` flag could receive spurious `payment.succeeded(livemode: false)` calls on their production handler, polluting order counts, audit trails, or triggering automated responses.
- Merchants who do not branch on `livemode` (which is the more common case) could process test-mode events as real payments, depending on their integration.

The fix adds a `mode` enum column (`'test' | 'live' | 'both'`) to the `webhooks` table, defaulting to `'live'`. `enqueue_webhook_delivery` is updated to filter `webhooks.mode` against the intent's `mode`: a subscription with `mode = 'live'` only receives live events; `mode = 'test'` only receives test events; `mode = 'both'` preserves the previous behavior. The dashboard webhook configuration UI exposes a mode selector (`/dashboard/webhooks` subscription form). Existing subscriptions are backfilled to `mode = 'live'` in the migration, preserving prior behavior for production endpoints.

### Impact

- **Critical (F1)**: Any party holding `WEBHOOK_SECRET` - obtained from a device config, shared during onboarding, extracted from a backup, or leaked through any other operational path - could mark any live pending intent on the platform as paid without transferring any money. Merchants would receive a correctly-signed `payment.succeeded` webhook indistinguishable from a genuine payment. For merchants that fulfil automatically on webhook receipt (digital goods, service activations, credit top-ups) this is equivalent to unlimited free orders. The attack does not require a KitPay account, any prior interaction with the platform, or any interaction with the Supabase layer.

- **High (F2)**: In a multi-merchant deployment where two merchants both accept the same method and both have live pending intents of the same denomination from the same phone number (a realistic scenario in any geographic market with a small pool of frequent payers), the platform's matching logic will credit the wrong merchant. The wrongly-credited merchant receives a legitimate-looking payment confirmation; the correctly-paying merchant's intent stays pending and times out. The attacker does not need to be a registered merchant; the condition arises from normal concurrent usage. In the worst case the mismatch enables a registered merchant to deliberately craft a colliding intent to absorb a competitor's payment flow.

- **Medium (generateRef)**: Refs generated before this fix have ~31 bits of entropy. Brute-forcing a specific ref requires on average 1 billion guesses, which is non-trivial but not out of reach for a motivated attacker with high-bandwidth access to the `/pay/<ref>` endpoint. The practical risk is low because a guessed ref must still satisfy F1/F2 prerequisites to cause financial harm; the fix eliminates the entropy gap as a prerequisite for future attack chains.

- **Low (test-mode webhooks)**: Merchants running integration tests against the KitPay test-mode endpoint may inadvertently trigger production fulfilment logic if their endpoint does not guard on `livemode`. No cross-merchant leak is involved; the impact is bounded to the merchant's own integration.

No financial loss and no exposure of customer data beyond the merchant's own records is known to have occurred between report and fix.

### Fix

Migration [`supabase/v40_ingest_hardening.sql`](./supabase/v40_ingest_hardening.sql) (private deployment repo mirrors it as `v42_ingest_hardening.sql`), applied to shared Supabase project `rpgmzookqozeijtexmgl` on 2026-10-27:

**Per-device forwarder credential table**

- Creates `forwarder_devices` table: `id uuid PK`, `merchant_id uuid FK merchants`, `label text NOT NULL`, `token_hash text NOT NULL` (sha256 of the `kpf_*` Bearer token), `enabled boolean DEFAULT true`, `created_at timestamptz DEFAULT now()`.
- `REVOKE ALL ON forwarder_devices FROM PUBLIC, anon, authenticated`. Service role only.
- RLS disabled on this table (service_role access path only; no client-side access needed).

**`verify_forwarder_token(p_token text)` RPC**

- `SECURITY DEFINER`, `SET search_path = public, extensions, pg_temp`.
- Computes `sha256(p_token::bytea)::text`, looks up in `forwarder_devices WHERE token_hash = <hash> AND enabled = true`, returns `(merchant_id uuid, device_id uuid)`. The function uses `RETURN QUERY ... LIMIT 1`, which returns an empty result set when no row matches; no exception is raised. The Next.js caller checks `Array.isArray(authData) && authData.length === 0` and returns 401.
- `REVOKE EXECUTE FROM PUBLIC, anon, authenticated; GRANT EXECUTE TO service_role`.
- Called by the updated `/api/sms-ingest` handler; result is used to populate `p_merchant_id` on all downstream matcher calls.

**Six per-method matchers updated**

- New overload of each of `match_payment_bankily`, `match_payment_masrvi`, `match_payment_bim`, `match_payment_sedad`, `match_payment_click`, `match_payment_bcipay`: adds `p_merchant_id uuid` as a fourth argument.
- Tier-1 lookup adds `AND merchant_id = p_merchant_id`.
- Tier-2 count query adds `AND merchant_id = p_merchant_id`.
- Orphan `INSERT` includes `merchant_id = p_merchant_id` (removing the `NULL` default that caused the regression tracked in KP-SEC-2026-003 F3, now fully closed for the per-device path).
- Three-argument overloads are kept (`p_merchant_id` omitted or `NULL`) for one deploy cycle to allow a safe rolling upgrade. These overloads will be dropped in the v43 follow-up migration once all callers have migrated.
- `REVOKE`/`GRANT` block regenerated for all twelve function signatures (3-arg and 4-arg for each of the six methods).

**`webhooks.mode` column**

- `ALTER TABLE webhooks ADD COLUMN mode text NOT NULL DEFAULT 'live' CHECK (mode IN ('test', 'live', 'both'))`.
- `UPDATE webhooks SET mode = 'live'` backfill for existing rows.
- `enqueue_webhook_delivery` signature remains `(p_merchant_id uuid, p_event_type text, p_payload jsonb)` unchanged. Inside the function, it computes `v_event_mode := CASE WHEN p_payload->>'livemode' = 'true' THEN 'live' ELSE 'test' END` and filters `WHERE ... AND (w.mode = v_event_mode OR w.mode = 'both')` before inserting `webhook_deliveries` rows. No new parameter is added to the function.
- `NOTIFY pgrst, 'reload schema'` at end of migration.

**Code changes (both repos unless noted)**

- `src/app/api/sms-ingest/route.ts`:
  - Replaces header-based `WEBHOOK_SECRET` validation with `await supabaseAdmin.rpc('verify_forwarder_token', { p_token: bearerToken })`.
  - Destructures `merchant_id` and `device_id` from the RPC result.
  - Passes `merchant_id` as the fourth argument to all six matcher calls.
  - The ingest cutover is hard, not rolling: after the migration lands, `/api/sms-ingest` returns 401 for every request that does not carry a valid `Authorization: Bearer kpf_<token>` header. During the brief window between the Netlify deploy and the operator rotating their MacroDroid HTTP action, inbound SMS will fail with 401 and matching will not fire; this is operationally acceptable because the operator is the one triggering the rotation and the window is seconds-to-minutes. The 3-arg legacy matcher overloads remain in the database for one deploy cycle (dropped in v43) so that any late in-flight call via the service_role still succeeds; no code path in the OSS tree uses them after v40.
- `src/lib/format.ts` `generateRef()`:
  - Replaces `Math.random()` loop with `randomBytes(8)` from `node:crypto`, encodes to 10 uppercase alphanumeric characters.
  - Vitest test added in `src/lib/__tests__/format.test.ts`: asserts length 10, charset `[A-Z0-9]`, and non-collision across 1000 calls.
- `src/app/dashboard/forwarders/page.tsx` + `actions.ts` (new route):
  - Lists enrolled forwarder devices for the authenticated merchant.
  - Allows creating a new device (generates `'kpf_' + randomBytes(16).toString('base64url')` token (16 bytes, base64url encoding, ~26 characters total including the prefix), stores sha256 hash, returns the raw token once for the operator to copy into MacroDroid).
  - Allows revoking a device (sets `enabled = false`).
- `src/app/dashboard/webhooks/` subscription form:
  - Adds mode selector (`Test only / Live only / Both`) mapped to `mode` column.
  - Defaults to `Live only` for new subscriptions.
- OSS only - `src/app/api/cron/deliver-webhooks/route.ts`: unchanged by this PR. The delivery worker does not call `enqueue_webhook_delivery`; it reads already-enqueued rows from `webhook_deliveries` and dispatches them. No changes were needed here because the mode filtering happens at enqueue time inside the function itself.

**Verification-block defects (round-3 correction)**

The `DO $$` verification blocks shipped inside v38, v39, and v40 had three independent defects that prevented them from catching the exact regressions they existed for:

1. `grantee = 'public'` (lowercase) vs the Postgres system value `'PUBLIC'` (uppercase) -- the check matched zero rows on a correctly-locked schema, so it would also have silently passed on a schema where `PUBLIC` was still granted `EXECUTE`.
2. `anon` and `authenticated` inherit their effective `EXECUTE` privilege through the `PUBLIC` grant rather than through their own explicit privilege rows. Querying `information_schema.routine_privileges` for `grantee IN ('anon','authenticated')` finds nothing when the grant is held by `PUBLIC`, which means the blocks would have passed even if the lockdown had not been applied.
3. v40's verification block joined on function name only (not OID), so a three-argument ACL row on one overload could satisfy the check intended for a four-argument overload.

The actual lockdown state was verified post-audit by calling `has_function_privilege(role, oid, 'EXECUTE')` on both the shared production project (`rpgmzookqozeijtexmgl`) and the sandbox (`roukaawzylzhpgrccshs`). Every checked function returned `false` for `anon` and `authenticated` -- the ACL state matches the intended lockdown. The verification blocks were wrong, but the migrations they wrapped were correct.

v41 (round-3 OSS migration) / v43 (private) rewrites all verification blocks using `has_function_privilege` to prevent this class of silent false-pass regression going forward.

**Note on v39 OSS abort**

The committed `v39_followup_bechar.sql` in the OSS repo contains a window-function-in-HAVING clause (line 565) that Postgres rejects with error `42P20` at plan time, aborting the entire `BEGIN`/`COMMIT` block. Production applied the correct variant inline via Supabase MCP -- the file-as-committed never ran anywhere. OSS self-hosters who ran the file believe the migration succeeded (the trailing `SELECT 'v39 applied'` executes outside the transaction) but have the pre-v39 vulnerability state. v41 round-3 is the single migration that fixes v39's bug and reapplies the full backfill idempotently. `INSTALL.md` has been updated to tell operators to skip v39 and apply v41 directly.

**Smaller items shipped in follow-up**

`docs/api.md` documented `customer_phone` as `'+222 46 XX XX XX'` while the SMS parser extracts bare digits. Spec-conforming integrators who passed the human-readable format silently fell to Tier-2 amount-only matching rather than Tier-1 phone+amount matching. v41 round-3 ships a server-side canonicalizer at every intent-create entry point and updates `docs/api.md` to teach the canonical 8-digit form.

**Deferred to v43**

- Drop the 3-arg overloads of all six per-method matchers once Phase F operator rotation is confirmed and no 3-arg calls remain in either repo.
- Remove `WEBHOOK_SECRET` from `.env.example`.

## Round-3 follow-up (KP-SEC-2026-005)

After KP-SEC-2026-004 landed, Bechar re-pulled the public tree at commit `14e80f6` and ran a deep static-analysis pass plus an adversarial second pass whose only job was to disprove the first pass's findings. The round-3 report identified that the OSS install path (INSTALL.md) never referenced the v37-v41 migration chain, that `v39_followup_bechar.sql` as committed could never apply end-to-end (window-function-in-HAVING abort), that the v38/v39/v40 verification blocks had three independent defects, and surfaced additional issues on the application side (SSRF chain, admin backdoor, oldest-merchant fallback, generateRef entropy in the production path, phone format discrepancy, open redirect, receipt email HTML injection). All issues are fixed in v41 (OSS) / v43 (private deployment).

Full technical write-up of round 3: see `SECURITY_ADVISORIES.md` entry `KP-SEC-2026-005` and the migration `supabase/v41_round3_hardening.sql` (OSS) / `supabase/v43_hardening_round3.sql` (private deployment repo).

### Timeline

- **2026-10-27, morning (Nouakchott)** - Third report received at `contact@solutionia.work`. Covers F1 (shared `WEBHOOK_SECRET`) and F2 (platform-wide Tier-1 matching) which had been deferred from the KP-SEC-2026-002 "Still tracked" section, plus Medium (generateRef CSPRNG) and Low (test-mode webhook mixing) also deferred from KP-SEC-2026-002 and KP-SEC-2026-003 footnotes. Each finding verified against both source trees and the live Supabase project.
- **2026-10-27, same day** - Migration `v42_ingest_hardening.sql` (private) / `v40_ingest_hardening.sql` (OSS) written and applied to the shared Supabase project `rpgmzookqozeijtexmgl`. Code patches shipped in both repos across the new `/api/sms-ingest` Bearer auth, `/dashboard/forwarders`, `webhooks.mode` scope selector, and `generateRef` CSPRNG. Verification blocks passed. PostgREST reloaded. Public disclosure through this advisory.
- **Phase F (pending)** - Operator (Moulaye) rotates the MacroDroid HTTP header on his forwarding phone from the shared `WEBHOOK_SECRET` value to the per-device `kpf_*` Bearer token generated in `/dashboard/forwarders`. From the moment the Netlify deploy lands, `/api/sms-ingest` already hard-rejects any request without a valid Bearer token; SMS forwarding is offline until the MacroDroid action is updated, which is expected to take seconds to minutes.
- **v43 follow-up (scheduled)** - Drop 3-arg matcher overloads, retire `WEBHOOK_SECRET` env var.

### Credit

Reported responsibly by Bechar (`agattbechar@gmail.com`). This is Bechar's third consecutive report against KitPay, each building on the architectural residuals explicitly deferred in the preceding advisory. Findings F1 and F2 were first flagged in the KP-SEC-2026-002 "Still tracked" section and verified in KP-SEC-2026-003's F2 note; this report provided the concrete attack path, the merchant-isolation design for F2, and the specific Bearer-token architecture that became the fix. The Medium and Low findings were also drawn from deferred items in prior advisories. No payment-changing requests were made and no database interaction occurred beyond what a public API consumer would see. Thank you.

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
