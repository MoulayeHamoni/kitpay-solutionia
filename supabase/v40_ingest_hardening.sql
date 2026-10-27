-- =====================================================================
-- KitPay v40 — Ingest Hardening (mirror of private v42)
-- Merchant-scoped matchers, forwarder token auth, webhook mode routing
-- =====================================================================
-- Cette migration restructure le matching payment pour etre pleinement
-- merchant-scoped (Tier 1 et 2 confines au merchant fourni). Introduit :
--   1. forwarder_devices : authorisation granulaire pour SMS ingest via token
--   2. verify_forwarder_token : validation HMAC-SHA256 et last_seen tracking
--   3. match_payment_* overloads : signature 4-args (amount, phone, sms, merchant_id)
--   4. webhooks.mode : routage test/live/both
--   5. enqueue_webhook_delivery : filtre mode coherent avec payment_intents.mode
--
-- Contexte securite : KP-SEC-2026-004 (forwarder credential hardening)

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. CREATE TABLE forwarder_devices
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.forwarder_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id uuid NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  label text NOT NULL,
  token_hash text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES auth.users(id),
  last_seen_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (merchant_id, label)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_forwarder_devices_token_hash
  ON public.forwarder_devices(token_hash) WHERE revoked_at IS NULL;

-- Enable RLS on forwarder_devices
ALTER TABLE public.forwarder_devices ENABLE ROW LEVEL SECURITY;

-- Policy : "members read devices"
CREATE POLICY "members read devices" ON public.forwarder_devices
  FOR SELECT TO authenticated
  USING (
    (public.user_is_member_of(merchant_id) OR public.is_super_admin())
  );

-- Policy : "service all devices"
CREATE POLICY "service all devices" ON public.forwarder_devices
  FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- 2. CREATE FUNCTION verify_forwarder_token
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.verify_forwarder_token(p_token text)
RETURNS TABLE(device_id uuid, merchant_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_hash text;
BEGIN
  IF p_token IS NULL OR length(p_token) < 20 THEN
    RETURN;
  END IF;

  v_hash := encode(digest(p_token, 'sha256'), 'hex');

  RETURN QUERY
  SELECT d.id, d.merchant_id
  FROM public.forwarder_devices d
  WHERE d.token_hash = v_hash
    AND d.enabled = true
    AND d.revoked_at IS NULL
  LIMIT 1;

  UPDATE public.forwarder_devices
  SET last_seen_at = now()
  WHERE token_hash = v_hash
    AND enabled = true
    AND revoked_at IS NULL;
END; $fn$;

REVOKE EXECUTE ON FUNCTION public.verify_forwarder_token(text)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.verify_forwarder_token(text)
  TO service_role;

-- ---------------------------------------------------------------------------
-- 3. CREATE FUNCTION match_payment_bankily (4-arg merchant-scoped version)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_bankily(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE; v_operator_id uuid; v_orphan_id uuid;
  v_payload jsonb; v_tier2_count integer;
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

  -- Tier 3 : orphan with merchant attribution
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Bankily', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 4. CREATE FUNCTION match_payment_masrvi (4-arg merchant-scoped version)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_masrvi(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE; v_operator_id uuid; v_orphan_id uuid;
  v_payload jsonb; v_tier2_count integer;
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

  -- Tier 2 : merchant-scoped amount-only, with ambiguity guard
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

  -- Tier 3 : orphan with merchant attribution
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Masrvi', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 5. CREATE FUNCTION match_payment_bim (4-arg merchant-scoped version)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_bim(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE; v_operator_id uuid; v_orphan_id uuid;
  v_payload jsonb; v_tier2_count integer;
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

  -- Tier 2 : merchant-scoped amount-only, with ambiguity guard
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

  -- Tier 3 : orphan with merchant attribution
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'BIM', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 6. CREATE FUNCTION match_payment_sedad (4-arg merchant-scoped version)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_sedad(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE; v_operator_id uuid; v_orphan_id uuid;
  v_payload jsonb; v_tier2_count integer;
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

  -- Tier 2 : merchant-scoped amount-only, with ambiguity guard
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

  -- Tier 3 : orphan with merchant attribution
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Sedad', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 7. CREATE FUNCTION match_payment_click (4-arg merchant-scoped version, last4)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_click(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE; v_operator_id uuid; v_orphan_id uuid;
  v_payload jsonb; v_tier2_count integer;
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

  -- Tier 2 : merchant-scoped amount-only, with ambiguity guard
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

  -- Tier 3 : orphan with merchant attribution
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'Click', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- 8. CREATE FUNCTION match_payment_bcipay (4-arg merchant-scoped version)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.match_payment_bcipay(
  p_amount integer, p_sender_phone text, p_raw_sms text, p_merchant_id uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $fn$
DECLARE
  v_intent payment_intents%ROWTYPE; v_operator_id uuid; v_orphan_id uuid;
  v_payload jsonb; v_tier2_count integer;
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

  -- Tier 2 : merchant-scoped amount-only, with ambiguity guard
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

  -- Tier 3 : orphan with merchant attribution
  INSERT INTO orphan_sms (raw_body, parsed_amount, parsed_phone, parsed_method, merchant_id)
  VALUES (p_raw_sms, p_amount, p_sender_phone, 'BCIPAY', p_merchant_id) RETURNING id INTO v_orphan_id;
  RETURN jsonb_build_object('matched', false, 'tier', 3, 'reason', 'no_intent_found', 'orphan_id', v_orphan_id);
END; $fn$;

-- ---------------------------------------------------------------------------
-- Lockdown: revoke the 6 new 4-arg matcher overloads from public/anon/auth.
-- Same discipline as v39/v40. Only /api/sms-ingest (service_role) should call them.
-- ---------------------------------------------------------------------------

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
-- 9. ALTER TABLE webhooks ADD COLUMN mode
-- ---------------------------------------------------------------------------

ALTER TABLE public.webhooks
ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'live'
CHECK (mode IN ('test', 'live', 'both'));

-- ---------------------------------------------------------------------------
-- 10. CREATE OR REPLACE FUNCTION enqueue_webhook_delivery with mode routing
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.enqueue_webhook_delivery(
  p_merchant_id uuid,
  p_event_type text,
  p_payload jsonb
)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_count integer := 0;
  v_webhook webhooks%ROWTYPE;
  v_event_mode text;
BEGIN
  v_event_mode := CASE WHEN p_payload->>'livemode' = 'true' THEN 'live' ELSE 'test' END;

  FOR v_webhook IN
    SELECT w.* FROM webhooks w
    WHERE w.merchant_id = p_merchant_id
      AND w.enabled = true
      AND p_event_type = ANY(w.events)
      AND (w.mode = v_event_mode OR w.mode = 'both')
  LOOP
    INSERT INTO public.webhook_deliveries (
      webhook_id, merchant_id, event_type, payload, status, next_retry_at
    )
    VALUES (
      v_webhook.id, p_merchant_id, p_event_type, p_payload, 'pending', now()
    );
    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END; $$;

REVOKE EXECUTE ON FUNCTION public.enqueue_webhook_delivery(uuid, text, jsonb)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.enqueue_webhook_delivery(uuid, text, jsonb)
  TO service_role;

-- ---------------------------------------------------------------------------
-- 11. Verification Block
-- ---------------------------------------------------------------------------

DO $$
DECLARE
  v_fn text;
  v_bad_role text;
  v_count int;
  v_matcher_functions text[] := ARRAY[
    'match_payment_bankily',
    'match_payment_masrvi',
    'match_payment_bim',
    'match_payment_sedad',
    'match_payment_click',
    'match_payment_bcipay'
  ];
BEGIN
  -- 1. Verify verify_forwarder_token has NO execute grant for anon/authenticated/PUBLIC
  FOR v_bad_role IN SELECT unnest(ARRAY['anon', 'authenticated', 'public']) LOOP
    SELECT COUNT(*) INTO v_count
    FROM information_schema.routine_privileges
    WHERE routine_schema = 'public'
      AND routine_name = 'verify_forwarder_token'
      AND grantee = v_bad_role
      AND privilege_type = 'EXECUTE';
    IF v_count > 0 THEN
      RAISE EXCEPTION 'v40 FAIL: role % still has EXECUTE on public.verify_forwarder_token', v_bad_role;
    END IF;
  END LOOP;
  RAISE NOTICE 'v40 ok: verify_forwarder_token locked down (service_role only)';

  -- 2. For each matcher, verify 4-arg overload exists AND is locked down
  FOREACH v_fn IN ARRAY v_matcher_functions LOOP
    SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    WHERE p.proname = v_fn
      AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
      AND array_length(p.proargtypes::oid[], 1) = 4;
    IF v_count = 0 THEN
      RAISE EXCEPTION 'v40 FAIL: 4-arg overload missing for public.%', v_fn;
    END IF;
    RAISE NOTICE 'v40 ok: 4-arg overload exists for public.%', v_fn;

    -- Verify lockdown on the 4-arg overload itself
    FOR v_bad_role IN SELECT unnest(ARRAY['anon', 'authenticated', 'public']) LOOP
      SELECT COUNT(*) INTO v_count
      FROM information_schema.routine_privileges rp
      JOIN pg_proc p ON p.proname = rp.routine_name
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND rp.routine_schema = 'public'
        AND rp.routine_name = v_fn
        AND array_length(p.proargtypes::oid[], 1) = 4
        AND rp.grantee = v_bad_role
        AND rp.privilege_type = 'EXECUTE';
      IF v_count > 0 THEN
        RAISE EXCEPTION 'v40 FAIL: 4-arg public.% still callable by %', v_fn, v_bad_role;
      END IF;
    END LOOP;
    SELECT COUNT(*) INTO v_count
    FROM information_schema.routine_privileges rp
    JOIN pg_proc p ON p.proname = rp.routine_name
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND rp.routine_schema = 'public'
      AND rp.routine_name = v_fn
      AND array_length(p.proargtypes::oid[], 1) = 4
      AND rp.grantee = 'service_role'
      AND rp.privilege_type = 'EXECUTE';
    IF v_count = 0 THEN
      RAISE EXCEPTION 'v40 FAIL: service_role missing EXECUTE on 4-arg public.%', v_fn;
    END IF;
    RAISE NOTICE 'v40 ok: 4-arg public.% locked down (service_role only)', v_fn;
  END LOOP;

  -- 3. Verify webhooks.mode column exists
  SELECT COUNT(*) INTO v_count
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND table_name = 'webhooks'
    AND column_name = 'mode';
  IF v_count = 0 THEN
    RAISE EXCEPTION 'v40 FAIL: column webhooks.mode not found';
  END IF;
  RAISE NOTICE 'v40 ok: webhooks.mode column exists';

  -- 4. Verify enqueue_webhook_delivery has service_role EXECUTE
  SELECT COUNT(*) INTO v_count
  FROM information_schema.routine_privileges
  WHERE routine_schema = 'public'
    AND routine_name = 'enqueue_webhook_delivery'
    AND grantee = 'service_role'
    AND privilege_type = 'EXECUTE';
  IF v_count = 0 THEN
    RAISE EXCEPTION 'v40 FAIL: service_role missing EXECUTE on public.enqueue_webhook_delivery';
  END IF;
  RAISE NOTICE 'v40 ok: enqueue_webhook_delivery service_role EXECUTE granted';

  -- 5. Verify enqueue_webhook_delivery has NO execute grant for anon/authenticated/PUBLIC
  FOR v_bad_role IN SELECT unnest(ARRAY['anon', 'authenticated', 'public']) LOOP
    SELECT COUNT(*) INTO v_count
    FROM information_schema.routine_privileges
    WHERE routine_schema = 'public'
      AND routine_name = 'enqueue_webhook_delivery'
      AND grantee = v_bad_role
      AND privilege_type = 'EXECUTE';
    IF v_count > 0 THEN
      RAISE EXCEPTION 'v40 FAIL: role % still has EXECUTE on public.enqueue_webhook_delivery', v_bad_role;
    END IF;
  END LOOP;
  RAISE NOTICE 'v40 ok: enqueue_webhook_delivery locked down (service_role only)';

END $$;

-- ---------------------------------------------------------------------------
-- 12. Notify PostgREST to reload schema
-- ---------------------------------------------------------------------------

COMMIT;

NOTIFY pgrst, 'reload schema';

SELECT 'v40 ingest hardening applied' AS info;
