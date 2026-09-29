# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in KitPay SolutionIA, please **do
not open a public GitHub issue**. Instead, send a private email to:

**security@solutionia.work**

Please include:
- A clear description of the vulnerability and its impact.
- Steps to reproduce, or a proof of concept if possible.
- The affected component (SMS ingest, webhook worker, dashboard, migrations,
  hosted checkout, etc.) and the commit or tag you tested against.
- Your name or handle if you would like credit in the acknowledgements.

We will acknowledge your report within 5 business days and give you an
estimated timeline for a fix. Please give us reasonable time to publish a
patched release before disclosing the issue publicly.

## Scope

In scope:
- The source code in this repository (Next.js app, Supabase SQL migrations,
  webhook worker, HMAC signing library).
- The default `.env.example` values and any hard-coded fallbacks.
- The Postgres schema and RLS policies produced by the migrations.

Out of scope:
- Third-party services this project depends on (Supabase, Netlify, Vercel,
  Resend, Telegram, cron-job.org). Report those directly to the vendor.
- Attacks that require physical access to the merchant phone.
- Vulnerabilities in a merchant's own integration code that consumes KitPay
  webhooks or the REST API.

## Hardening reminders for operators

- Rotate `WEBHOOK_SECRET`, `CRON_SECRET` and `ADMIN_PASSWORD` on a schedule.
- Never expose the Supabase `SUPABASE_SERVICE_ROLE_KEY` to a browser or a
  client bundle.
- Restrict outbound traffic from your Netlify or Vercel account.
- Enable Supabase MFA and IP allowlists on the project used by KitPay.
- Any new SQL function that mutates state and is created in the `public`
  schema must be paired with an explicit
  `REVOKE EXECUTE ... FROM PUBLIC, anon, authenticated` and, when appropriate,
  a matching `GRANT EXECUTE ... TO service_role`. Postgres grants `EXECUTE`
  to `PUBLIC` by default, and Supabase PostgREST exposes every callable
  public function at `/rest/v1/rpc/<name>` for anyone holding the anon key.
  See `SECURITY_ADVISORIES.md` entry `KP-SEC-2026-001` for the incident that
  motivated this rule.

## Acknowledgements

We are grateful to the security researchers who have reported vulnerabilities
responsibly. Published advisories, including the researchers who reported them,
are tracked in [`SECURITY_ADVISORIES.md`](./SECURITY_ADVISORIES.md).

Notable contributors:

- [0xMR](https://0xmr.org) (`contact@0xmr.org`) - reported `KP-SEC-2026-001`
  (unauthenticated payment forgery via public match_payment_* RPC) on
  2026-09-27 with a complete proof of concept.
