-- =====================================================================
-- KitPay v41 -- Round-3 hardening (KP-SEC-2026-005, mirror of private v43)
-- =====================================================================
-- Closes the remaining findings from Bechar round 3 audit:
--
--   S1. Orphan backfill from v41 had window-function-in-HAVING (42P20).
--       OSS self-hosters who ran the broken v39 (= private v41) were left
--       with unresolved orphans. Re-run backfill using the valid subquery
--       pattern (idempotent).
--
--   S2. The 3-arg matchers in v41 and the 4-arg matchers in v42 both had a
--       broken "fallback merchant_id" resolution:
--           SELECT merchant_id FROM (...) m HAVING COUNT(*) = 1 LIMIT 1;
--       The outer SELECT references a non-aggregate column without GROUP BY.
--       Compiles fine (lazy parse) but aborts at first Tier-1-miss execution.
--       Replace with a safe two-step COUNT then SELECT pattern in all 6
--       4-arg matchers (v41 rewrites them). The 3-arg overloads are dropped
--       in S4 so they do not need to be repaired.
--
--   S3. webhook_deliveries.response_body combined with SSRF turns blind SSRF
--       into readable SSRF. Create a column-restricted view and flip the
--       "members read deliveries" policy to USING (false) on the base table.
--       Dashboard code will be updated to read from webhook_deliveries_safe
--       in a follow-up commit.
--
--   S4. Drop the 3-arg matcher overloads (attack surface, no longer needed
--       after Phase F Masrvi validation). Also drop the legacy unscoped
--       match_payment(4-arg) and match_payment_v3 functions.
--
--   S5. BEFORE INSERT/UPDATE trigger on webhooks that enforces SSRF guard
--       server-side (complements Node-side DNS re-resolve).
--
--   S6. expire_old_intents race fix -- single UPDATE ... RETURNING pattern
--       so payment.expired can never fire after payment.succeeded.
--
--   S7. Idempotency table for SMS ingest (device_id, sms_hash) to prevent
--       double-processing of retransmitted SMS.
--
--   S8. Verification DO block using has_function_privilege() which correctly
--       traverses PUBLIC inheritance (unlike information_schema.routine_privileges
--       which: (a) returns grantee 'PUBLIC' not 'public', (b) anon/authenticated
--       inherit via PUBLIC without their own rows, and (c) joins by name only
--       so overloads can falsely satisfy each other).

BEGIN;

-- ---------------------------------------------------------------------------
-- SECTION 1 -- Idempotent backfill of orphan_sms.merchant_id
-- (window function in valid subquery SELECT list; predicate in outer WHERE)
-- ---------------------------------------------------------------------------

UPDATE orphan_sms o
SET merchant_id = sub.merchant_id
FROM (
  SELECT mo.method AS m, mo.merchant_id,
         COUNT(*) OVER (PARTITION BY mo.method) AS merchants_for_method
  FROM (SELECT DISTINCT method, merchant_id FROM merchant_operators WHERE enabled = true) mo
) sub
WHERE o.merchant_id IS NULL
  AND o.resolved_at IS NULL
  AND o.parsed_method = sub.m
  AND sub.merchants_for_method = 1;

-- ---------------------------------------------------------------------------
-- SECTION 2+4 -- Rewrite all 6 four-arg matchers with safe fallback resolution
--               and DROP the 3-arg overloads that v41 shipped.
--
-- The broken pattern was:
--   SELECT merchant_id FROM (SELECT merchant_id FROM merchant_operators
--     WHERE method='X' AND enabled=true GROUP BY merchant_id) m
--   HAVING COUNT(*) = 1 LIMIT 1;
-- which errors at execution because the outer SELECT is a non-aggregate
-- expression in an implicit single-group aggregation (no GROUP BY on outer).
--
-- Replacement: two-step with an explicit COUNT(*) INTO v_fallback_count.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 2a. match_payment_bankily (4-arg, fixed fallback)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_bankily(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  IF p_merchant_id IS NULL THEN
    RETURN jsonb_build_object('matched', false, 'tier', 0, 'reason', 'merchant_id_required');
  END IF;

  -- Tier 1 : merchant-scoped, exact phone match
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Bankily'
    AND pi.amount = p_amount AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Bankily' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  -- Resolve fallback merchant_id for orphan attribution (safe two-step)
  SELECT COUNT(DISTINCT merchant_id) INTO v_fallback_count
    FROM merchant_operators WHERE method = 'Bankily' AND enabled = true;
  IF v_fallback_count = 1 THEN
    SELECT DISTINCT merchant_id INTO v_fallback_merchant_id
      FROM merchant_operators WHERE method = 'Bankily' AND enabled = true LIMIT 1;
  END IF;

  -- Tier 2 : merchant-scoped amount-only, with ambiguity guard
  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Bankily' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();
  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Bankily', p_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;
  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Bankily' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Bankily' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  -- Tier 3 : orphan
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Bankily', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 2b. match_payment_masrvi (4-arg, fixed fallback)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_masrvi(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  IF p_merchant_id IS NULL THEN
    RETURN jsonb_build_object('matched', false, 'tier', 0, 'reason', 'merchant_id_required');
  END IF;

  -- Tier 1 : merchant-scoped, exact phone match
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Masrvi'
    AND pi.amount = p_amount AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Masrvi' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  -- Resolve fallback merchant_id (safe two-step)
  SELECT COUNT(DISTINCT merchant_id) INTO v_fallback_count
    FROM merchant_operators WHERE method = 'Masrvi' AND enabled = true;
  IF v_fallback_count = 1 THEN
    SELECT DISTINCT merchant_id INTO v_fallback_merchant_id
      FROM merchant_operators WHERE method = 'Masrvi' AND enabled = true LIMIT 1;
  END IF;

  -- Tier 2
  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Masrvi' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();
  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Masrvi', p_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;
  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Masrvi' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Masrvi' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Masrvi', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 2c. match_payment_bim (4-arg, fixed fallback)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_bim(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  IF p_merchant_id IS NULL THEN
    RETURN jsonb_build_object('matched', false, 'tier', 0, 'reason', 'merchant_id_required');
  END IF;

  -- Tier 1 : merchant-scoped, exact phone match
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'BIM'
    AND pi.amount = p_amount AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BIM' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  -- Resolve fallback merchant_id (safe two-step)
  SELECT COUNT(DISTINCT merchant_id) INTO v_fallback_count
    FROM merchant_operators WHERE method = 'BIM' AND enabled = true;
  IF v_fallback_count = 1 THEN
    SELECT DISTINCT merchant_id INTO v_fallback_merchant_id
      FROM merchant_operators WHERE method = 'BIM' AND enabled = true LIMIT 1;
  END IF;

  -- Tier 2
  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'BIM' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();
  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'BIM', p_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;
  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.merchant_id = p_merchant_id AND pi.method = 'BIM' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BIM' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'BIM', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 2d. match_payment_sedad (4-arg, fixed fallback)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_sedad(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  IF p_merchant_id IS NULL THEN
    RETURN jsonb_build_object('matched', false, 'tier', 0, 'reason', 'merchant_id_required');
  END IF;

  -- Tier 1 : merchant-scoped, exact phone match
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Sedad'
    AND pi.amount = p_amount AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Sedad' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  -- Resolve fallback merchant_id (safe two-step)
  SELECT COUNT(DISTINCT merchant_id) INTO v_fallback_count
    FROM merchant_operators WHERE method = 'Sedad' AND enabled = true;
  IF v_fallback_count = 1 THEN
    SELECT DISTINCT merchant_id INTO v_fallback_merchant_id
      FROM merchant_operators WHERE method = 'Sedad' AND enabled = true LIMIT 1;
  END IF;

  -- Tier 2
  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Sedad' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();
  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Sedad', p_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;
  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Sedad' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Sedad' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Sedad', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 2e. match_payment_click (4-arg, fixed fallback, keeps last4 tier-1 shape)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_click(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  IF p_merchant_id IS NULL THEN
    RETURN jsonb_build_object('matched', false, 'tier', 0, 'reason', 'merchant_id_required');
  END IF;

  -- Tier 1 : merchant-scoped, last4 phone match (v38 behavior)
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Click'
    AND pi.amount = p_amount AND right(pi.expected_phone, 4) = right(p_sender_phone, 4)
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Click' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  -- Resolve fallback merchant_id (safe two-step)
  SELECT COUNT(DISTINCT merchant_id) INTO v_fallback_count
    FROM merchant_operators WHERE method = 'Click' AND enabled = true;
  IF v_fallback_count = 1 THEN
    SELECT DISTINCT merchant_id INTO v_fallback_merchant_id
      FROM merchant_operators WHERE method = 'Click' AND enabled = true LIMIT 1;
  END IF;

  -- Tier 2
  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Click' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();
  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'Click', p_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;
  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.merchant_id = p_merchant_id AND pi.method = 'Click' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'Click' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Click', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 2f. match_payment_bcipay (4-arg, fixed fallback)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_bcipay(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE;
  v_operator_id uuid;
  v_orphan_id uuid;
  v_payload jsonb;
  v_tier2_count integer;
  v_fallback_count integer;
  v_fallback_merchant_id uuid;
BEGIN
  IF p_merchant_id IS NULL THEN
    RETURN jsonb_build_object('matched', false, 'tier', 0, 'reason', 'merchant_id_required');
  END IF;

  -- Tier 1 : merchant-scoped, exact phone match
  SELECT pi.* INTO v_intent FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'BCIPAY'
    AND pi.amount = p_amount AND pi.expected_phone = p_sender_phone
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
  ORDER BY pi.created_at DESC LIMIT 1;
  IF FOUND THEN
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BCIPAY' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=1,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 1, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  -- Resolve fallback merchant_id (safe two-step)
  SELECT COUNT(DISTINCT merchant_id) INTO v_fallback_count
    FROM merchant_operators WHERE method = 'BCIPAY' AND enabled = true;
  IF v_fallback_count = 1 THEN
    SELECT DISTINCT merchant_id INTO v_fallback_merchant_id
      FROM merchant_operators WHERE method = 'BCIPAY' AND enabled = true LIMIT 1;
  END IF;

  -- Tier 2
  SELECT COUNT(*) INTO v_tier2_count FROM payment_intents pi
  WHERE pi.merchant_id = p_merchant_id AND pi.method = 'BCIPAY' AND pi.amount = p_amount
    AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now();
  IF v_tier2_count > 1 THEN
    INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
    VALUES (p_raw_sms, p_amount, p_sender_phone, 'BCIPAY', p_merchant_id) RETURNING id INTO v_orphan_id;
    RETURN jsonb_build_object('matched', false, 'tier', 2, 'reason', 'tier2_ambiguous',
      'candidates', v_tier2_count, 'orphan_id', v_orphan_id);
  END IF;
  IF v_tier2_count = 1 THEN
    SELECT pi.* INTO v_intent FROM payment_intents pi
    WHERE pi.merchant_id = p_merchant_id AND pi.method = 'BCIPAY' AND pi.amount = p_amount
      AND pi.status = 'pending' AND pi.mode = 'live' AND pi.expires_at > now()
    ORDER BY pi.created_at DESC LIMIT 1;
    SELECT id INTO v_operator_id FROM merchant_operators
    WHERE method = 'BCIPAY' AND merchant_id = p_merchant_id AND enabled = true LIMIT 1;
    UPDATE payment_intents SET status='paid', matched_tier=2,
      actual_sender_phone=p_sender_phone, sms_received=p_raw_sms, paid_at=now(),
      merchant_operator_id=COALESCE(merchant_operator_id, v_operator_id)
    WHERE ref = v_intent.ref;
    SELECT row_to_json(pi.*)::jsonb INTO v_payload FROM payment_intents pi WHERE ref = v_intent.ref;
    PERFORM enqueue_webhook_delivery(p_merchant_id, 'payment.succeeded', jsonb_build_object(
      'id', 'evt_' || encode(gen_random_bytes(12), 'hex'), 'type', 'payment.succeeded',
      'created', extract(epoch from now())::int, 'livemode', true,
      'data', jsonb_build_object('object', v_payload)));
    RETURN jsonb_build_object('matched', true, 'tier', 2, 'ref', v_intent.ref, 'merchant_id', p_merchant_id);
  END IF;

  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'BCIPAY', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- Re-apply lockdown on the rewritten 4-arg matchers (CREATE OR REPLACE
-- may reset grants in some Postgres versions; be explicit).
REVOKE EXECUTE ON FUNCTION public.match_payment_bankily(integer, text, text, uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.match_payment_masrvi(integer, text, text, uuid)  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.match_payment_bim(integer, text, text, uuid)     FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.match_payment_sedad(integer, text, text, uuid)   FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.match_payment_click(integer, text, text, uuid)   FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.match_payment_bcipay(integer, text, text, uuid)  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.match_payment_bankily(integer, text, text, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_masrvi(integer, text, text, uuid)  TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_bim(integer, text, text, uuid)     TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_sedad(integer, text, text, uuid)   TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_click(integer, text, text, uuid)   TO service_role;
GRANT EXECUTE ON FUNCTION public.match_payment_bcipay(integer, text, text, uuid)  TO service_role;

-- ---------------------------------------------------------------------------
-- SECTION 3 -- Column-restrict webhook_deliveries (SSRF -> readable SSRF)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW public.webhook_deliveries_safe AS
SELECT id, webhook_id, merchant_id, event_type, status, http_status,
       attempt, next_retry_at, created_at, delivered_at
FROM public.webhook_deliveries;

-- security_invoker: view runs with the calling role's privileges, so the
-- underlying RLS on webhook_deliveries still applies for service_role reads.
ALTER VIEW public.webhook_deliveries_safe SET (security_invoker = true);

-- Flip the base-table policy to DENY for authenticated (service_role bypasses
-- RLS by default on Supabase so it retains full access).
DROP POLICY IF EXISTS "members read deliveries" ON public.webhook_deliveries;
CREATE POLICY "members read deliveries base" ON public.webhook_deliveries
  FOR SELECT TO authenticated
  USING (false);

-- ---------------------------------------------------------------------------
-- SECTION 4 -- Drop legacy function overloads
-- ---------------------------------------------------------------------------

-- 3-arg (unscoped) overloads from v36-v38 patched in v41:
DROP FUNCTION IF EXISTS public.match_payment_bankily(integer, text, text);
DROP FUNCTION IF EXISTS public.match_payment_masrvi(integer, text, text);
DROP FUNCTION IF EXISTS public.match_payment_bim(integer, text, text);
DROP FUNCTION IF EXISTS public.match_payment_sedad(integer, text, text);
DROP FUNCTION IF EXISTS public.match_payment_click(integer, text, text);
DROP FUNCTION IF EXISTS public.match_payment_bcipay(integer, text, text);

-- Legacy unscoped 4-arg and v3 variant:
DROP FUNCTION IF EXISTS public.match_payment(integer, text, text, text);
DROP FUNCTION IF EXISTS public.match_payment_v3(integer, text, text, text, text);

-- ---------------------------------------------------------------------------
-- SECTION 5 -- SSRF guard trigger on webhooks.url
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.webhook_url_is_safe(p_url text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_host text;
  v_proto text;
BEGIN
  v_proto := lower(split_part(p_url, '://', 1));
  IF v_proto NOT IN ('http', 'https') THEN RETURN false; END IF;
  v_host := lower(split_part(split_part(p_url, '://', 2), '/', 1));
  v_host := split_part(v_host, ':', 1);  -- strip port
  IF v_host = '' THEN RETURN false; END IF;
  IF v_host = 'localhost' THEN RETURN false; END IF;
  IF v_host LIKE '%.localhost' OR v_host LIKE '%.internal' OR v_host LIKE '%.local' THEN RETURN false; END IF;
  -- Literal private IP ranges (string-level; DNS re-resolve enforced in Node)
  IF v_host ~ '^10\.'     THEN RETURN false; END IF;
  IF v_host ~ '^127\.'    THEN RETURN false; END IF;
  IF v_host ~ '^0\.'      THEN RETURN false; END IF;
  IF v_host ~ '^169\.254\.' THEN RETURN false; END IF;
  IF v_host ~ '^192\.168\.' THEN RETURN false; END IF;
  IF v_host ~ '^172\.(1[6-9]|2[0-9]|3[0-1])\.' THEN RETURN false; END IF;
  IF v_host ~ '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.' THEN RETURN false; END IF;
  IF v_host ~ '^(22[4-9]|23[0-9])\.' THEN RETURN false; END IF;  -- multicast
  RETURN true;
END; $$;

CREATE OR REPLACE FUNCTION public.webhooks_url_check_trigger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT public.webhook_url_is_safe(NEW.url) THEN
    RAISE EXCEPTION 'webhook URL rejected (SSRF guard): %', NEW.url;
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS trg_webhooks_url_check ON public.webhooks;
CREATE TRIGGER trg_webhooks_url_check
  BEFORE INSERT OR UPDATE OF url ON public.webhooks
  FOR EACH ROW EXECUTE FUNCTION public.webhooks_url_check_trigger();

-- ---------------------------------------------------------------------------
-- SECTION 6 -- expire_old_intents race fix
-- (single UPDATE...RETURNING; no window between status=paid and status=expired)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.expire_old_intents() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_rec record;
  v_count integer := 0;
  v_payload jsonb;
BEGIN
  FOR v_rec IN
    UPDATE payment_intents
       SET status = 'expired'
     WHERE status = 'pending' AND expires_at < now()
     RETURNING ref, merchant_id, mode
  LOOP
    SELECT row_to_json(pi.*)::jsonb INTO v_payload
      FROM payment_intents pi WHERE ref = v_rec.ref;
    PERFORM enqueue_webhook_delivery(v_rec.merchant_id, 'payment.expired', jsonb_build_object(
      'id',      'evt_' || encode(gen_random_bytes(12), 'hex'),
      'type',    'payment.expired',
      'created', extract(epoch from now())::int,
      'livemode', v_rec.mode = 'live',
      'data',    jsonb_build_object('object', v_payload)
    ));
    v_count := v_count + 1;
  END LOOP;
  RETURN v_count;
END; $$;

REVOKE EXECUTE ON FUNCTION public.expire_old_intents() FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION public.expire_old_intents() TO service_role;

-- ---------------------------------------------------------------------------
-- SECTION 7 -- SMS ingest deduplication table
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.sms_ingest_dedupe (
  device_id   uuid      NOT NULL REFERENCES public.forwarder_devices(id) ON DELETE CASCADE,
  sms_hash    text      NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, sms_hash)
);

CREATE INDEX IF NOT EXISTS idx_sms_ingest_dedupe_received
  ON public.sms_ingest_dedupe(received_at);

ALTER TABLE public.sms_ingest_dedupe ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service all dedupe" ON public.sms_ingest_dedupe
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.cleanup_sms_ingest_dedupe() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE v_count integer;
BEGIN
  DELETE FROM public.sms_ingest_dedupe WHERE received_at < now() - interval '24 hours';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END; $$;

REVOKE EXECUTE ON FUNCTION public.cleanup_sms_ingest_dedupe() FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION public.cleanup_sms_ingest_dedupe() TO service_role;

-- ---------------------------------------------------------------------------
-- SECTION 8 -- Verification block (uses has_function_privilege, not
--              information_schema.routine_privileges which has 3 known bugs:
--              uppercase 'PUBLIC' vs lowercase 'public'; anon/authenticated
--              inherit via PUBLIC without own rows; joins by name cross-
--              contaminate overloads with different arities)
-- ---------------------------------------------------------------------------

DO $v$
DECLARE r record;
BEGIN
  -- Check 1: no PUBLIC/anon/authenticated EXECUTE on secured SECURITY DEFINER functions
  FOR r IN
    SELECT p.oid, p.proname,
           pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname IN (
        'match_payment_bankily', 'match_payment_masrvi', 'match_payment_bim',
        'match_payment_sedad',   'match_payment_click',  'match_payment_bcipay',
        'enqueue_webhook_delivery', 'reconcile_orphan', 'verify_api_key',
        'verify_forwarder_token', 'expire_old_intents', 'cleanup_sms_ingest_dedupe'
      )
  LOOP
    IF has_function_privilege('PUBLIC', r.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'v41 FAIL: PUBLIC has EXECUTE on public.%(%)', r.proname, r.args;
    END IF;
    IF has_function_privilege('anon', r.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'v41 FAIL: anon has EXECUTE on public.%(%)', r.proname, r.args;
    END IF;
    IF has_function_privilege('authenticated', r.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'v41 FAIL: authenticated has EXECUTE on public.%(%)', r.proname, r.args;
    END IF;
    IF NOT has_function_privilege('service_role', r.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'v41 FAIL: service_role missing EXECUTE on public.%(%)', r.proname, r.args;
    END IF;
    RAISE NOTICE 'v41 ok: public.%(%) locked down (service_role only)', r.proname, r.args;
  END LOOP;

  -- Check 2: the dropped 3-arg overloads really gone
  IF EXISTS (
    SELECT 1 FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname IN (
        'match_payment_bankily', 'match_payment_masrvi', 'match_payment_bim',
        'match_payment_sedad',   'match_payment_click',  'match_payment_bcipay'
      )
      AND p.pronargs = 3
  ) THEN
    RAISE EXCEPTION 'v41 FAIL: a 3-arg legacy matcher still exists';
  END IF;
  RAISE NOTICE 'v41 ok: 3-arg matchers dropped';

  -- Check 3: merchants policies locked
  IF EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'merchants'
      AND policyname IN ('anon read merchant public fields', 'members update merchant')
  ) THEN
    RAISE EXCEPTION 'v41 FAIL: insecure merchants policy present';
  END IF;
  RAISE NOTICE 'v41 ok: merchants policies locked';

  -- Check 4: webhooks URL trigger armed
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_webhooks_url_check'
  ) THEN
    RAISE EXCEPTION 'v41 FAIL: webhooks URL trigger missing';
  END IF;
  RAISE NOTICE 'v41 ok: webhooks URL trigger armed';

END $v$;

COMMIT;

NOTIFY pgrst, 'reload schema';
SELECT 'v41 round-3 hardening applied' AS info;
