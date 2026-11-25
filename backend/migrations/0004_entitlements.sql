-- Independent grants avoid an accidental downgrade when multiple sources overlap.
-- FREE is implicit: no active grant is required. Payments are not implemented.
CREATE TABLE promo_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash char(64) NOT NULL UNIQUE CHECK (code_hash ~ '^[a-f0-9]{64}$'),
  grant_tier text NOT NULL CHECK (grant_tier IN ('PRO','FRIENDS_UNLIMITED')),
  duration_days integer,
  max_uses integer NOT NULL CHECK (max_uses BETWEEN 1 AND 10000),
  uses_count integer NOT NULL DEFAULT 0 CHECK (uses_count >= 0 AND uses_count <= max_uses),
  expires_at timestamptz NOT NULL,
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK ((grant_tier='PRO' AND duration_days IS NOT NULL AND duration_days BETWEEN 1 AND 3650) OR (grant_tier='FRIENDS_UNLIMITED' AND duration_days IS NULL))
);
CREATE TABLE subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  tier text NOT NULL CHECK (tier IN ('PRO','FRIENDS_UNLIMITED')),
  source text NOT NULL CHECK (source IN ('admin','promo','payment')),
  promo_code_id uuid REFERENCES promo_codes(id),
  starts_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((tier='FRIENDS_UNLIMITED' AND expires_at IS NULL) OR (tier='PRO' AND expires_at IS NOT NULL AND expires_at > starts_at)),
  CHECK ((source='promo' AND promo_code_id IS NOT NULL) OR (source<>'promo' AND promo_code_id IS NULL))
);
CREATE INDEX subscriptions_user_active_idx ON subscriptions(user_id, starts_at, expires_at) WHERE revoked_at IS NULL;
CREATE TABLE promo_redemptions (
  promo_code_id uuid NOT NULL REFERENCES promo_codes(id),
  user_id uuid NOT NULL REFERENCES users(id),
  subscription_id uuid NOT NULL UNIQUE REFERENCES subscriptions(id),
  redeemed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (promo_code_id, user_id)
);
CREATE TABLE feature_catalog (
  feature_key text PRIMARY KEY CHECK (feature_key ~ '^[A-Z][A-Z0-9_]{1,63}$'),
  enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE tier_features (
  tier text NOT NULL CHECK (tier IN ('FREE','PRO','FRIENDS_UNLIMITED')),
  feature_key text NOT NULL REFERENCES feature_catalog(feature_key),
  PRIMARY KEY (tier, feature_key)
);
INSERT INTO feature_catalog(feature_key) VALUES ('BASIC_PLANNING'),('EXTENDED_HISTORY'),('CUSTOM_THEMES');
INSERT INTO tier_features(tier, feature_key) VALUES
  ('FREE','BASIC_PLANNING'),
  ('PRO','BASIC_PLANNING'),('PRO','EXTENDED_HISTORY'),('PRO','CUSTOM_THEMES'),
  ('FRIENDS_UNLIMITED','BASIC_PLANNING'),('FRIENDS_UNLIMITED','EXTENDED_HISTORY'),('FRIENDS_UNLIMITED','CUSTOM_THEMES');
CREATE TABLE administrative_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id uuid NOT NULL REFERENCES users(id),
  target_user_id uuid REFERENCES users(id),
  promo_code_id uuid REFERENCES promo_codes(id),
  action text NOT NULL CHECK (action IN ('grant_pro','grant_friends','set_free','create_promo','disable_promo','revoke_grant','set_flag')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Runtime gets only these narrowly scoped functions. Session identity is
-- resolved and supplied by the server, never by the client request body.
CREATE FUNCTION public.resolve_user_features(p_user uuid)
RETURNS TABLE (feature_key text, is_enabled boolean, is_allowed boolean, effective_tier text, tier_expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
  SELECT f.feature_key, f.enabled,
         f.enabled AND EXISTS(SELECT 1 FROM public.tier_features tf WHERE tf.feature_key=f.feature_key AND (tf.tier='FREE' OR (a.tier IN ('PRO','FRIENDS_UNLIMITED') AND tf.tier='PRO') OR (a.tier='FRIENDS_UNLIMITED' AND tf.tier='FRIENDS_UNLIMITED'))),
         COALESCE(a.tier,'FREE'), a.expires_at
  FROM public.users u
  LEFT JOIN LATERAL (
    SELECT s.tier,s.expires_at FROM public.subscriptions s
    WHERE s.user_id=u.id AND s.revoked_at IS NULL AND s.starts_at<=now() AND (s.expires_at IS NULL OR s.expires_at>now())
    ORDER BY CASE s.tier WHEN 'FRIENDS_UNLIMITED' THEN 2 ELSE 1 END DESC, s.expires_at DESC NULLS FIRST
    LIMIT 1
  ) a ON true
  CROSS JOIN public.feature_catalog f
  WHERE u.id=p_user AND u.deleted_at IS NULL
  ORDER BY f.feature_key
$body$;
REVOKE ALL ON FUNCTION public.resolve_user_features(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_user_features(uuid) TO sobralis_runtime;

CREATE FUNCTION public.redeem_promo(p_user uuid, p_hash text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE p public.promo_codes%ROWTYPE; new_subscription uuid; start_time timestamptz;
BEGIN
  -- Lock a user first so different promo codes cannot lose concurrent extensions.
  PERFORM 1 FROM public.users WHERE id=p_user AND deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN 'invalid'; END IF;
  SELECT * INTO p FROM public.promo_codes WHERE code_hash=p_hash FOR UPDATE;
  IF NOT FOUND OR p.disabled_at IS NOT NULL OR p.expires_at<=now() OR p.uses_count>=p.max_uses THEN RETURN 'invalid'; END IF;
  IF EXISTS(SELECT 1 FROM public.promo_redemptions WHERE promo_code_id=p.id AND user_id=p_user) THEN RETURN 'invalid'; END IF;
  IF EXISTS(SELECT 1 FROM public.subscriptions WHERE user_id=p_user AND tier='FRIENDS_UNLIMITED' AND revoked_at IS NULL AND starts_at<=now()) THEN RETURN 'already_unlimited'; END IF;
  IF p.grant_tier='PRO' THEN
    SELECT GREATEST(now(), COALESCE(MAX(expires_at), now())) INTO start_time
    FROM public.subscriptions WHERE user_id=p_user AND tier='PRO' AND revoked_at IS NULL AND expires_at>now();
    INSERT INTO public.subscriptions(user_id,tier,source,promo_code_id,starts_at,expires_at)
      VALUES (p_user,'PRO','promo',p.id,start_time,start_time+(p.duration_days * interval '24 hours')) RETURNING id INTO new_subscription;
  ELSE
    INSERT INTO public.subscriptions(user_id,tier,source,promo_code_id,starts_at,expires_at)
      VALUES (p_user,'FRIENDS_UNLIMITED','promo',p.id,now(),NULL) RETURNING id INTO new_subscription;
  END IF;
  INSERT INTO public.promo_redemptions(promo_code_id,user_id,subscription_id) VALUES(p.id,p_user,new_subscription);
  UPDATE public.promo_codes SET uses_count=uses_count+1 WHERE id=p.id;
  RETURN 'redeemed';
END
$body$;
REVOKE ALL ON FUNCTION public.redeem_promo(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_promo(uuid,text) TO sobralis_runtime;
