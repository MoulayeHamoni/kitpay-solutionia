-- v38 : Verrouillage des RPC SECURITY DEFINER restantes + fix reconcile_orphan
-- + fix policy "members read orphans"
--
-- Contexte : Rapport Bechar (agattbechar@gmail.com) recu le 2026-10-24.
-- Prolonge le fix KP-SEC-2026-001 (v37) a toutes les fonctions SECURITY DEFINER
-- du schema public qui n'avaient pas encore de REVOKE.
--
-- La BD Supabase est partagee avec le depot prive, qui livre la meme
-- migration sous v40_lockdown_remaining_rpcs.sql. Reappliquer est idempotent.
--
-- Verrouille :
--   * public.enqueue_webhook_delivery(uuid, text, jsonb)
--     Finding 1 (Critical) : anon-callable permet de forger un webhook
--     payment.succeeded signe HMAC pour n'importe quel marchand.
--   * public.reconcile_orphan(uuid, text, text)
--     Finding 2 (High) : SECURITY DEFINER sans scope merchant ;
--     la fonction est reecrite pour exiger
--     payment_intents.merchant_id = v_orphan.merchant_id.
--   * public.verify_api_key(text)
--     Footnote 1 : anon-callable permet un oracle de validite de cle API.
--   * public.expire_old_intents()
--     Footnote : fonction non sensible mais regle generale (SECURITY.md).
--
-- Fix policy :
--   * "members read orphans" ON orphan_sms : la v14 contenait une tautologie
--     ( id IN (SELECT id FROM orphan_sms o2 WHERE o2.id = orphan_sms.id) )
--     qui autorisait tout authenticated a lire TOUS les orphans. Remplace
--     par un vrai scope merchant via user_is_member_of().

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Reecrire reconcile_orphan avec check d'ownership
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.reconcile_orphan(
  p_orphan_id uuid,
  p_target_ref text,
  p_admin text DEFAULT 'admin'
)
RETURNS json
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_orphan orphan_sms;
  v_intent payment_intents;
BEGIN
  SELECT * INTO v_orphan FROM orphan_sms WHERE id = p_orphan_id;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'orphan not found');
  END IF;
  IF v_orphan.resolved_at IS NOT NULL THEN
    RETURN json_build_object('success', false, 'error', 'already resolved');
  END IF;
  IF v_orphan.merchant_id IS NULL THEN
    -- Tier 4 orphan (unknown merchant) : jamais reconciliable automatiquement.
    RETURN json_build_object('success', false, 'error', 'orphan not scoped to a merchant');
  END IF;

  SELECT * INTO v_intent FROM payment_intents WHERE ref = p_target_ref;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'intent not found');
  END IF;
  IF v_intent.status != 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'intent not pending');
  END IF;
  IF v_intent.merchant_id <> v_orphan.merchant_id THEN
    -- Fix Finding 2 (Bechar 2026-10-24) : empeche un marchand d'utiliser son
    -- orphan pour marquer paid l'intent d'un autre marchand.
    RETURN json_build_object('success', false, 'error', 'orphan and intent belong to different merchants');
  END IF;

  UPDATE payment_intents
  SET status = 'paid',
      matched_tier = 3,
      actual_sender_phone = v_orphan.parsed_phone,
      sms_received = v_orphan.raw_body,
      paid_at = now()
  WHERE ref = p_target_ref;

  UPDATE orphan_sms
  SET resolved_at = now(),
      resolved_to_ref = p_target_ref,
      resolved_by = p_admin
  WHERE id = p_orphan_id;

  RETURN json_build_object('success', true, 'ref', p_target_ref);
END;
$$;

-- ---------------------------------------------------------------------------
-- 2. Revoquer EXECUTE des roles publics/logges sur les 4 fonctions
-- ---------------------------------------------------------------------------

REVOKE EXECUTE ON FUNCTION public.enqueue_webhook_delivery(uuid, text, jsonb)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.reconcile_orphan(uuid, text, text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.verify_api_key(text)
  FROM PUBLIC, anon, authenticated;

REVOKE EXECUTE ON FUNCTION public.expire_old_intents()
  FROM PUBLIC, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 3. Grants explicites service_role (contrat clair, bypass RLS deja implicite)
-- ---------------------------------------------------------------------------

GRANT EXECUTE ON FUNCTION public.enqueue_webhook_delivery(uuid, text, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.reconcile_orphan(uuid, text, text)          TO service_role;
GRANT EXECUTE ON FUNCTION public.verify_api_key(text)                        TO service_role;
GRANT EXECUTE ON FUNCTION public.expire_old_intents()                        TO service_role;

-- ---------------------------------------------------------------------------
-- 4. Fix policy orphan_sms : remplacer la tautologie v14 par un vrai scope
-- ---------------------------------------------------------------------------

DROP POLICY IF EXISTS "members read orphans" ON orphan_sms;

CREATE POLICY "members read orphans" ON orphan_sms
  FOR SELECT TO authenticated
  USING (
    (orphan_sms.merchant_id IS NOT NULL
      AND public.user_is_member_of(orphan_sms.merchant_id))
    OR public.is_super_admin()
  );

-- ---------------------------------------------------------------------------
-- 5. Verification : anon/authenticated/public ne doivent PAS avoir EXECUTE
-- ---------------------------------------------------------------------------

DO $$
DECLARE
  v_fn text;
  v_bad_role text;
  v_count int;
  v_functions text[] := ARRAY[
    'enqueue_webhook_delivery',
    'reconcile_orphan',
    'verify_api_key',
    'expire_old_intents'
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
        RAISE EXCEPTION 'v38 FAIL: role % still has EXECUTE on public.%', v_bad_role, v_fn;
      END IF;
    END LOOP;

    SELECT COUNT(*) INTO v_count
    FROM information_schema.routine_privileges
    WHERE routine_schema = 'public'
      AND routine_name = v_fn
      AND grantee = 'service_role'
      AND privilege_type = 'EXECUTE';
    IF v_count = 0 THEN
      RAISE EXCEPTION 'v38 FAIL: service_role missing EXECUTE on public.%', v_fn;
    END IF;

    RAISE NOTICE 'v38 ok: public.% locked down (service_role only)', v_fn;
  END LOOP;
END $$;

-- Verifier aussi que la nouvelle policy orphans est bien en place
DO $$
DECLARE
  v_count int;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM pg_policies
  WHERE schemaname = 'public'
    AND tablename = 'orphan_sms'
    AND policyname = 'members read orphans';
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'v38 FAIL: policy "members read orphans" not applied (count=%)', v_count;
  END IF;
  RAISE NOTICE 'v38 ok: policy "members read orphans" scoped to merchant';
END $$;

-- ---------------------------------------------------------------------------
-- 6. Forcer PostgREST a recharger le schema
-- ---------------------------------------------------------------------------

NOTIFY pgrst, 'reload schema';

COMMIT;

SELECT 'v38 lockdown remaining RPCs + reconcile_orphan ownership + orphan policy fix applied' AS info;
