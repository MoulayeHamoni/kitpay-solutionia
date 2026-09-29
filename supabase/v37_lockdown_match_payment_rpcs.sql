-- v37 : Verrouillage des RPC match_payment_*
--
-- Contexte : Rapport 0xMR du 2026-09-27 (contact@0xmr.org).
--
-- Vulnerabilite critique (CVSS estime > 9) :
--   Les fonctions match_payment_* sont declarees SECURITY DEFINER mais aucun
--   REVOKE EXECUTE FROM PUBLIC n'a jamais ete emis. Par defaut Postgres accorde
--   EXECUTE a PUBLIC sur toute fonction du schema public. Supabase PostgREST
--   expose alors chaque RPC a /rest/v1/rpc/<name> accessible avec la cle anon
--   (publique par definition). Un attaquant peut :
--     POST /rest/v1/rpc/match_payment_masrvi
--     apikey: sb_publishable_...
--     Body: { "p_amount": <montant>, "p_sender_phone": "<tel>", "p_raw_sms": "..." }
--   La fonction SECURITY DEFINER bypass RLS, matche un intent live pending,
--   set status='paid' et envoie un webhook payment.succeeded HMAC-signe au marchand.
--   Consequence : commandes gratuites sur tout marchand integre a KitPay.
--
-- Fix : revoquer EXECUTE aupres de PUBLIC/anon/authenticated, ne conserver
--   que service_role. Les appels legitimes passent tous par supabaseAdmin()
--   (service_role) cote serveur (endpoint /api/sms-ingest, cron, admin).
--   Aucun code client ne doit appeler ces RPC directement.
--
-- Verification : voir bloc de tests en fin de fichier (NOTICE 'ok' attendu).

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Revoquer EXECUTE de tous les roles publics/logges
-- ---------------------------------------------------------------------------

REVOKE EXECUTE ON FUNCTION public.match_payment(integer, text, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.match_payment_v3(integer, text, text, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.match_payment_masrvi(integer, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.match_payment_bim(integer, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.match_payment_bankily(integer, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.match_payment_bcipay(integer, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.match_payment_sedad(integer, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.match_payment_click(integer, text, text)
  FROM PUBLIC, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. Grants explicites service_role (endpoint /api/sms-ingest, admin, cron)
--    service_role a deja bypass RLS mais on rend le contrat explicite.
-- ---------------------------------------------------------------------------

GRANT EXECUTE ON FUNCTION public.match_payment(integer, text, text, text)                 TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_v3(integer, text, text, text, text)        TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_masrvi(integer, text, text)                TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_bim(integer, text, text)                   TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_bankily(integer, text, text)               TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_bcipay(integer, text, text)                TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_sedad(integer, text, text)                 TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_click(integer, text, text)                 TO service_role;

-- ---------------------------------------------------------------------------
-- 3. Verification : les anon/authenticated ne doivent PAS avoir EXECUTE
-- ---------------------------------------------------------------------------

DO $$
DECLARE
  v_fn text;
  v_bad_role text;
  v_count int;
  v_functions text[] := ARRAY[
    'match_payment',
    'match_payment_v3',
    'match_payment_masrvi',
    'match_payment_bim',
    'match_payment_bankily',
    'match_payment_bcipay',
    'match_payment_sedad',
    'match_payment_click'
  ];
BEGIN
  FOREACH v_fn IN ARRAY v_functions LOOP
    FOR v_bad_role IN SELECT unnest(ARRAY['anon', 'authenticated', 'public']) LOOP
      SELECT COUNT(*) INTO v_count
      FROM information_schema.routine_privileges
      WHERE routine_schema = 'public'
        AND routine_name = v_fn
        AND grantee = v_bad_role
        AND privilege_type = 'EXECUTE';
      IF v_count > 0 THEN
        RAISE EXCEPTION 'v37 FAIL: role % still has EXECUTE on public.%', v_bad_role, v_fn;
      END IF;
    END LOOP;

    SELECT COUNT(*) INTO v_count
    FROM information_schema.routine_privileges
    WHERE routine_schema = 'public'
      AND routine_name = v_fn
      AND grantee = 'service_role'
      AND privilege_type = 'EXECUTE';
    IF v_count = 0 THEN
      RAISE EXCEPTION 'v37 FAIL: service_role missing EXECUTE on public.%', v_fn;
    END IF;

    RAISE NOTICE 'v37 ok: public.% locked down (service_role only)', v_fn;
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Forcer PostgREST a recharger le schema (sinon cache anon marche encore ~10s)
-- ---------------------------------------------------------------------------

NOTIFY pgrst, 'reload schema';

COMMIT;

SELECT 'v37 lockdown match_payment_* applied' AS info;
