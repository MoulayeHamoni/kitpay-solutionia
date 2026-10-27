-- v39 : Follow-up to KP-SEC-2026-002 (second report from Bechar 2026-10-27)
--
-- Addresses:
--   * F3 (Medium) - orphans from per-method matchers were inserted with
--     merchant_id = NULL, which combined with v40's "orphan not scoped to a
--     merchant" guard made 64 unresolved orphans unreachable from any
--     dashboard. Patch each of the 6 per-method matchers to resolve the
--     single enabled merchant for the method and attribute the orphan.
--     Backfill the 64 existing rows where derivable.
--   * F4 (Critical) - anon had SELECT (via `USING (true)`) over every column
--     of the merchants table including kyc_documents, nif, rc_number,
--     kyc_notes, owner_password_hash. Authenticated members had UPDATE over
--     every column via `members update merchant` without a role check,
--     allowing self-serving KYC approval or plan upgrades. All reads and
--     writes in the application already use the admin (service_role) client
--     so these two policies are unused by the app. Drop them. Keep
--     `members read merchant` since dashboard reads currently go through
--     service_role but may use the policy path in the future.
--   * Idempotency keys - add `mode` to the UNIQUE constraint so test and live
--     requests don't share a cache slot.
--
-- The private deployment repo tracks this SQL as v41; the public OSS repo
-- ships the same SQL as v39.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. F4 : lock the merchants table down to service_role only for mutations
--         and remove the anon full-column read.
-- ---------------------------------------------------------------------------

DROP POLICY IF EXISTS "anon read merchant public fields" ON merchants;
DROP POLICY IF EXISTS "members update merchant" ON merchants;

-- Verify "members read merchant" is still present (we don't touch it here)
DO $$
DECLARE v_count int;
BEGIN
  SELECT COUNT(*) INTO v_count FROM pg_policies
  WHERE schemaname='public' AND tablename='merchants' AND policyname='members read merchant';
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'v39 FAIL: expected policy "members read merchant" to exist';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. F3 : patch the 6 per-method matchers to attribute merchant_id on orphan
--         inserts. We look up the single enabled merchant for the method; if
--         ambiguous (2+ merchants have the method enabled) we leave NULL and
--         the orphan goes to the super-admin reconciliation queue (which is
--         still gated server-side).
-- ---------------------------------------------------------------------------

-- Helper inlined into each matcher. Kept inlined rather than factored out
-- because every matcher already has its own body and we want the search_path
-- hardening to apply uniformly.

-- match_payment_bankily
CREATE OR REPLACE FUNCTION public.match_payment_bankily(
  p_amount integer,
  p_sender_phone text,
  p_raw_sms text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  -- Tier 1 : amount + exact client phone (LIFO)
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.method = 'Bankily' AND pi.amount = p_amount
    AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;

  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Bankily' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  -- Resolve fallback merchant_id for orphan attribution (single enabled merchant for the method)
  SELECT merchant_id INTO v_fallback_merchant_id FROM (
    SELECT merchant_id FROM merchant_operators
    WHERE method = 'Bankily' AND enabled = true
    GROUP BY merchant_id
  ) m
  HAVING COUNT(*) = 1
  LIMIT 1;

  -- Tier 2 : amount only, guarded
  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.method = 'Bankily' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();

  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Bankily', v_fallback_merchant_id)
    RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;

  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.method = 'Bankily' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Bankily' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  -- Tier 3 : orphan with best-effort merchant attribution
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Bankily', v_fallback_merchant_id)
  RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END;
$fn$;

-- match_payment_masrvi
CREATE OR REPLACE FUNCTION public.match_payment_masrvi(
  p_amount integer,
  p_sender_phone text,
  p_raw_sms text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.method = 'Masrvi' AND pi.amount = p_amount
    AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Masrvi' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  SELECT merchant_id INTO v_fallback_merchant_id FROM (
    SELECT merchant_id FROM merchant_operators
    WHERE method = 'Masrvi' AND enabled = true GROUP BY merchant_id
  ) m HAVING COUNT(*) = 1 LIMIT 1;

  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.method = 'Masrvi' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();

  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Masrvi', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;

  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.method = 'Masrvi' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Masrvi' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Masrvi', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END;
$fn$;

-- match_payment_bim
CREATE OR REPLACE FUNCTION public.match_payment_bim(
  p_amount integer,
  p_sender_phone text,
  p_raw_sms text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.method = 'BIM' AND pi.amount = p_amount
    AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BIM' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  SELECT merchant_id INTO v_fallback_merchant_id FROM (
    SELECT merchant_id FROM merchant_operators
    WHERE method = 'BIM' AND enabled = true GROUP BY merchant_id
  ) m HAVING COUNT(*) = 1 LIMIT 1;

  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.method = 'BIM' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();

  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'BIM', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;

  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.method = 'BIM' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BIM' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'BIM', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END;
$fn$;

-- match_payment_sedad
CREATE OR REPLACE FUNCTION public.match_payment_sedad(
  p_amount integer,
  p_sender_phone text,
  p_raw_sms text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.method = 'Sedad' AND pi.amount = p_amount
    AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Sedad' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  SELECT merchant_id INTO v_fallback_merchant_id FROM (
    SELECT merchant_id FROM merchant_operators
    WHERE method = 'Sedad' AND enabled = true GROUP BY merchant_id
  ) m HAVING COUNT(*) = 1 LIMIT 1;

  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.method = 'Sedad' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();

  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Sedad', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;

  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.method = 'Sedad' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Sedad' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Sedad', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END;
$fn$;

-- match_payment_click (keeps the last4 tier-1 shape from v38)
CREATE OR REPLACE FUNCTION public.match_payment_click(
  p_amount integer,
  p_sender_phone text,
  p_raw_sms text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.method = 'Click' AND pi.amount = p_amount
    AND right(pi.expected_phone, 4) = right(p_sender_phone, 4)
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Click' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  SELECT merchant_id INTO v_fallback_merchant_id FROM (
    SELECT merchant_id FROM merchant_operators
    WHERE method = 'Click' AND enabled = true GROUP BY merchant_id
  ) m HAVING COUNT(*) = 1 LIMIT 1;

  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.method = 'Click' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();

  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Click', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;

  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.method = 'Click' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Click' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Click', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END;
$fn$;

-- match_payment_bcipay
CREATE OR REPLACE FUNCTION public.match_payment_bcipay(
  p_amount integer,
  p_sender_phone text,
  p_raw_sms text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.method = 'BCIPAY' AND pi.amount = p_amount
    AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BCIPAY' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  SELECT merchant_id INTO v_fallback_merchant_id FROM (
    SELECT merchant_id FROM merchant_operators
    WHERE method = 'BCIPAY' AND enabled = true GROUP BY merchant_id
  ) m HAVING COUNT(*) = 1 LIMIT 1;

  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.method = 'BCIPAY' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();

  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'BCIPAY', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;

  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.method = 'BCIPAY' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BCIPAY' AND merchant_id = v_intent.merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
        actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
        merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(v_intent.merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)
    ));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', v_intent.merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'BCIPAY', v_fallback_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END;
$fn$;

-- ---------------------------------------------------------------------------
-- 3. F3 : backfill the 64 unresolved orphans in prod where derivable
-- ---------------------------------------------------------------------------

UPDATE orphan_sms o
SET merchant_id = sub.merchant_id
FROM (
  SELECT mo.method AS m, mo.merchant_id
  FROM merchant_operators mo
  WHERE mo.enabled = true
  GROUP BY mo.method, mo.merchant_id
  HAVING COUNT(*) OVER (PARTITION BY mo.method) = 1
) sub
WHERE o.merchant_id IS NULL
  AND o.resolved_at IS NULL
  AND o.parsed_method = sub.m;

-- ---------------------------------------------------------------------------
-- 4. Idempotency : scope the UNIQUE constraint by mode
-- ---------------------------------------------------------------------------

ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'live';
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS idempotency_keys_unique;
ALTER TABLE idempotency_keys ADD CONSTRAINT idempotency_keys_unique UNIQUE (merchant_id, key, mode);

-- ---------------------------------------------------------------------------
-- 5. Verifications
-- ---------------------------------------------------------------------------

DO $v$
DECLARE v_count int;
BEGIN
  SELECT COUNT(*) INTO v_count FROM pg_policies
  WHERE schemaname='public' AND tablename='merchants'
    AND policyname IN ('anon read merchant public fields','members update merchant');
  IF v_count > 0 THEN
    RAISE EXCEPTION 'v39 FAIL: removed merchants policies are still present';
  END IF;
  RAISE NOTICE 'v39 ok: merchants.anon read + members update policies removed';
END $v$;

DO $v2$
DECLARE v_fn text;
BEGIN
  FOREACH v_fn IN ARRAY ARRAY[
    'match_payment_bankily','match_payment_masrvi','match_payment_bim',
    'match_payment_sedad','match_payment_click','match_payment_bcipay'
  ] LOOP
    IF (SELECT prosrc FROM pg_proc WHERE proname = v_fn AND pronamespace = 'public'::regnamespace)
         !~ 'v_fallback_merchant_id' THEN
      RAISE EXCEPTION 'v39 FAIL: public.% does not have the merchant-attribution block', v_fn;
    END IF;
    RAISE NOTICE 'v39 ok: public.% attributes merchant on orphan insert', v_fn;
  END LOOP;
END $v2$;

NOTIFY pgrst, 'reload schema';

COMMIT;

SELECT 'v39 follow-up applied: merchants RLS lockdown, orphan merchant_id attribution + backfill, idempotency mode scope' AS info;
