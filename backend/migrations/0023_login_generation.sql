-- Recheck not only the Argon2 hash but also the verified identity generation.
-- A concurrent email change or verification loss and restoration cannot create
-- a session from an earlier successful password check.
GRANT SELECT (recovery_generation) ON public.users TO sobralis_runtime;
DROP FUNCTION public.issue_verified_session(uuid,text,text,text);
CREATE FUNCTION public.issue_verified_session(p_user uuid,p_email text,p_generation uuid,p_expected_hash text,p_new_token_hash text,p_old_token_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF p_email IS NULL OR p_generation IS NULL OR p_new_token_hash IS NULL OR p_new_token_hash !~ '^[a-f0-9]{64}$' OR
   (p_old_token_hash IS NOT NULL AND p_old_token_hash !~ '^[a-f0-9]{64}$') THEN RETURN false;END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_user AND lower(u.email)=p_email AND u.recovery_generation=p_generation
  AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND u.password_hash IS NOT NULL AND u.password_hash=p_expected_hash FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 IF p_old_token_hash IS NOT NULL THEN UPDATE public.user_sessions SET revoked_at=now() WHERE token_hash=p_old_token_hash AND revoked_at IS NULL;END IF;
 INSERT INTO public.user_sessions(user_id,token_hash,expires_at) VALUES(p_user,p_new_token_hash,now()+interval '24 hours');
 RETURN true;
END $f$;
REVOKE ALL ON FUNCTION public.issue_verified_session(uuid,text,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.issue_verified_session(uuid,text,uuid,text,text,text) TO sobralis_runtime;
