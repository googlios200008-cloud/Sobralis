-- Revoke other live sessions only after password reauthentication. Recheck the
-- session and password generation under the same user lock as session issuance
-- and password recovery. In-flight logins based on the old generation cannot
-- mint a fresh session after this transaction; later password logins still can.
CREATE FUNCTION public.revoke_other_sessions(
  p_user uuid, p_current_hash text, p_expected_password_hash text, p_expected_generation uuid
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE changed integer;
BEGIN
 IF p_user IS NULL OR p_current_hash IS NULL OR p_current_hash !~ '^[a-f0-9]{64}$'
    OR p_expected_password_hash IS NULL OR p_expected_generation IS NULL THEN RETURN -1; END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_user AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
   AND u.password_hash=p_expected_password_hash AND u.recovery_generation=p_expected_generation FOR UPDATE;
 IF NOT FOUND THEN RETURN -1; END IF;
 PERFORM 1 FROM public.user_sessions s WHERE s.user_id=p_user AND s.token_hash=p_current_hash FOR UPDATE;
 IF NOT FOUND THEN RETURN -1; END IF;
 -- Recheck after acquiring the row lock: it may have expired while waiting.
 PERFORM 1 FROM public.user_sessions s WHERE s.user_id=p_user AND s.token_hash=p_current_hash
   AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp();
 IF NOT FOUND THEN RETURN -1; END IF;
 UPDATE public.user_sessions SET revoked_at=now() WHERE user_id=p_user AND token_hash<>p_current_hash
   AND revoked_at IS NULL AND expires_at>clock_timestamp();
 GET DIAGNOSTICS changed = ROW_COUNT;
 -- Invalidates previous password-reset links as well as already-verified but
 -- not-yet-issued logins. The currently authenticated session stays valid.
 UPDATE public.users SET recovery_generation=gen_random_uuid() WHERE id=p_user;
 RETURN changed;
END $f$;
REVOKE ALL ON FUNCTION public.revoke_other_sessions(uuid,text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.revoke_other_sessions(uuid,text,text,uuid) TO sobralis_runtime;
