-- Existing users are intentionally NOT marked verified by migration.
CREATE TABLE email_verification_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  token_hash char(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  revoked_at timestamptz,
  CHECK(expires_at > created_at)
);
CREATE INDEX email_verification_user_idx ON email_verification_tokens(user_id,created_at DESC);

-- Serialized per-user issuance. A 10-minute account cooldown persists across restarts.
CREATE FUNCTION public.issue_email_verification(p_user uuid,p_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
BEGIN
  IF p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
  PERFORM 1 FROM public.users WHERE id=p_user AND deleted_at IS NULL AND email_verified_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM public.email_verification_tokens WHERE user_id=p_user AND created_at>now()-interval '10 minutes') THEN RETURN false; END IF;
  UPDATE public.email_verification_tokens SET revoked_at=now() WHERE user_id=p_user AND used_at IS NULL AND revoked_at IS NULL;
  INSERT INTO public.email_verification_tokens(user_id,token_hash,expires_at) VALUES(p_user,p_hash,now()+interval '30 minutes');
  RETURN true;
END
$body$;
REVOKE ALL ON FUNCTION public.issue_email_verification(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.issue_email_verification(uuid,text) TO sobralis_runtime;

CREATE FUNCTION public.check_email_verification(p_hash text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT EXISTS(SELECT 1 FROM public.email_verification_tokens v JOIN public.users u ON u.id=v.user_id
  WHERE v.token_hash=p_hash AND v.used_at IS NULL AND v.revoked_at IS NULL AND v.expires_at>now()
    AND u.deleted_at IS NULL AND u.email_verified_at IS NULL)
$body$;
REVOKE ALL ON FUNCTION public.check_email_verification(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.check_email_verification(text) TO sobralis_runtime;

-- Verify token, set a NEW password chosen by the email owner, and record their
-- separate consent events atomically. Prevents activation of a password chosen
-- by somebody who registered another person's email address.
CREATE FUNCTION public.consume_email_verification(p_hash text,p_password_hash text,p_ip inet,p_consent_version text,p_consent_url text,p_terms_version text,p_terms_url text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE token_row public.email_verification_tokens%ROWTYPE;
BEGIN
  IF p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' OR p_password_hash IS NULL OR p_password_hash !~ '^\$argon2id\$' OR
     p_consent_version IS NULL OR char_length(p_consent_version) NOT BETWEEN 1 AND 80 OR
     p_terms_version IS NULL OR char_length(p_terms_version) NOT BETWEEN 1 AND 80 OR
     p_consent_url IS NULL OR p_consent_url !~ '^/legal/[a-zA-Z0-9/_-]+$' OR
     p_terms_url IS NULL OR p_terms_url !~ '^/legal/[a-zA-Z0-9/_-]+$' THEN RETURN false; END IF;
  -- Issuance and consumption lock the user first, then token rows.
  SELECT * INTO token_row FROM public.email_verification_tokens WHERE token_hash=p_hash;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM 1 FROM public.users WHERE id=token_row.user_id AND deleted_at IS NULL AND email_verified_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT * INTO token_row FROM public.email_verification_tokens WHERE token_hash=p_hash FOR UPDATE;
  IF NOT FOUND OR token_row.used_at IS NOT NULL OR token_row.revoked_at IS NOT NULL OR token_row.expires_at<=now() THEN RETURN false; END IF;
  UPDATE public.users SET password_hash=p_password_hash,email_verified_at=now(),updated_at=now() WHERE id=token_row.user_id;
  -- Never revive pre-verification sessions when a legacy user confirms ownership.
  UPDATE public.user_sessions SET revoked_at=now() WHERE user_id=token_row.user_id AND revoked_at IS NULL;
  UPDATE public.email_verification_tokens SET used_at=now() WHERE id=token_row.id;
  UPDATE public.email_verification_tokens SET revoked_at=now() WHERE user_id=token_row.user_id AND id<>token_row.id AND used_at IS NULL AND revoked_at IS NULL;
  INSERT INTO public.user_consents(user_id,consent_type,document_version,document_url,ip)
    VALUES(token_row.user_id,'personal_data',p_consent_version,p_consent_url,p_ip),
          (token_row.user_id,'terms',p_terms_version,p_terms_url,p_ip);
  RETURN true;
END
$body$;
REVOKE ALL ON FUNCTION public.consume_email_verification(text,text,inet,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.consume_email_verification(text,text,inet,text,text,text,text) TO sobralis_runtime;
