-- Password recovery is disabled unless explicitly enabled by the API config.
-- Retain all existing user, community, calendar, and session data during upgrade.
CREATE TABLE public.password_reset_tokens (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES public.users(id),
 token_hash char(64) NOT NULL UNIQUE CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 used_at timestamptz,
 revoked_at timestamptz,
 CHECK(expires_at>created_at)
);
CREATE INDEX password_reset_user_idx ON public.password_reset_tokens(user_id,created_at DESC);

-- Both issuing and consuming lock the same user first; one mail per account
-- every ten minutes survives restarts. The raw token is never stored here.
CREATE FUNCTION public.issue_password_reset(p_email text,p_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE uid uuid;
BEGIN
 IF p_email IS NULL OR p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' THEN RETURN false;END IF;
 SELECT u.id INTO uid FROM public.users u WHERE lower(u.email)=p_email
  AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND u.password_hash IS NOT NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM public.password_reset_tokens r WHERE r.user_id=uid AND r.created_at>now()-interval '10 minutes') THEN RETURN false;END IF;
 UPDATE public.password_reset_tokens SET revoked_at=now() WHERE user_id=uid AND used_at IS NULL AND revoked_at IS NULL;
 INSERT INTO public.password_reset_tokens(user_id,token_hash,expires_at) VALUES(uid,p_hash,now()+interval '30 minutes');
 RETURN true;
END $f$;
REVOKE ALL ON FUNCTION public.issue_password_reset(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.issue_password_reset(text,text) TO sobralis_runtime;

CREATE FUNCTION public.check_password_reset(p_hash text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT EXISTS(SELECT 1 FROM public.password_reset_tokens r JOIN public.users u ON u.id=r.user_id
 WHERE r.token_hash=p_hash AND r.used_at IS NULL AND r.revoked_at IS NULL AND r.expires_at>now()
 AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND u.password_hash IS NOT NULL)
$f$;
REVOKE ALL ON FUNCTION public.check_password_reset(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.check_password_reset(text) TO sobralis_runtime;

CREATE FUNCTION public.consume_password_reset(p_hash text,p_password_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE r public.password_reset_tokens%ROWTYPE;
BEGIN
 IF p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' OR p_password_hash IS NULL OR p_password_hash !~ '^\$argon2id\$' THEN RETURN false;END IF;
 SELECT * INTO r FROM public.password_reset_tokens WHERE token_hash=p_hash;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.users WHERE id=r.user_id AND deleted_at IS NULL AND email_verified_at IS NOT NULL AND password_hash IS NOT NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO r FROM public.password_reset_tokens WHERE token_hash=p_hash FOR UPDATE;
 IF NOT FOUND OR r.used_at IS NOT NULL OR r.revoked_at IS NOT NULL OR r.expires_at<=now() THEN RETURN false;END IF;
 UPDATE public.users SET password_hash=p_password_hash,updated_at=now() WHERE id=r.user_id;
 UPDATE public.user_sessions SET revoked_at=now() WHERE user_id=r.user_id AND revoked_at IS NULL;
 UPDATE public.password_reset_tokens SET used_at=now() WHERE id=r.id;
 UPDATE public.password_reset_tokens SET revoked_at=now() WHERE user_id=r.user_id AND id<>r.id AND used_at IS NULL AND revoked_at IS NULL;
 RETURN true;
END $f$;
REVOKE ALL ON FUNCTION public.consume_password_reset(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.consume_password_reset(text,text) TO sobralis_runtime;

-- Recheck the hash after expensive Argon2 verification while holding the same
-- user lock as password reset. An already-started login cannot issue a session
-- with the old password after a reset has completed.
CREATE FUNCTION public.issue_verified_session(p_user uuid,p_expected_hash text,p_new_token_hash text,p_old_token_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF p_new_token_hash IS NULL OR p_new_token_hash !~ '^[a-f0-9]{64}$' OR
   (p_old_token_hash IS NOT NULL AND p_old_token_hash !~ '^[a-f0-9]{64}$') THEN RETURN false;END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_user AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
  AND u.password_hash IS NOT NULL AND u.password_hash=p_expected_hash FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 IF p_old_token_hash IS NOT NULL THEN UPDATE public.user_sessions SET revoked_at=now() WHERE token_hash=p_old_token_hash AND revoked_at IS NULL;END IF;
 INSERT INTO public.user_sessions(user_id,token_hash,expires_at) VALUES(p_user,p_new_token_hash,now()+interval '24 hours');
 RETURN true;
END $f$;
REVOKE ALL ON FUNCTION public.issue_verified_session(uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.issue_verified_session(uuid,text,text,text) TO sobralis_runtime;
REVOKE INSERT (user_id,token_hash,expires_at) ON public.user_sessions FROM sobralis_runtime;
