-- A recovery link is bound to the verified account and its exact email and
-- password generation. Losing and regaining verification must not revive it.
ALTER TABLE public.users ADD COLUMN recovery_generation uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE public.password_reset_tokens ADD COLUMN account_generation uuid;
UPDATE public.password_reset_tokens r SET account_generation=u.recovery_generation FROM public.users u WHERE u.id=r.user_id;
-- Prior tokens do not carry historical generations; revoke rather than assume.
UPDATE public.password_reset_tokens SET revoked_at=now() WHERE used_at IS NULL AND revoked_at IS NULL;
ALTER TABLE public.password_reset_tokens ALTER COLUMN account_generation SET NOT NULL;

CREATE FUNCTION public.rotate_recovery_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF OLD.email IS DISTINCT FROM NEW.email OR OLD.password_hash IS DISTINCT FROM NEW.password_hash OR
    OLD.email_verified_at IS DISTINCT FROM NEW.email_verified_at OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at THEN
   NEW.recovery_generation=gen_random_uuid();
 END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER rotate_recovery_generation BEFORE UPDATE OF email,password_hash,email_verified_at,deleted_at ON public.users
 FOR EACH ROW EXECUTE FUNCTION public.rotate_recovery_generation();
REVOKE ALL ON FUNCTION public.rotate_recovery_generation() FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.issue_password_reset(p_email text,p_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE uid uuid; generation uuid;
BEGIN
 IF p_email IS NULL OR p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' THEN RETURN false;END IF;
 SELECT u.id,u.recovery_generation INTO uid,generation FROM public.users u WHERE lower(u.email)=p_email
  AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND u.password_hash IS NOT NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM public.password_reset_tokens r WHERE r.user_id=uid AND r.created_at>now()-interval '10 minutes') THEN RETURN false;END IF;
 UPDATE public.password_reset_tokens SET revoked_at=now() WHERE user_id=uid AND used_at IS NULL AND revoked_at IS NULL;
 INSERT INTO public.password_reset_tokens(user_id,token_hash,expires_at,account_generation) VALUES(uid,p_hash,now()+interval '30 minutes',generation);
 RETURN true;
END $f$;

CREATE OR REPLACE FUNCTION public.check_password_reset(p_hash text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT EXISTS(SELECT 1 FROM public.password_reset_tokens r JOIN public.users u ON u.id=r.user_id
 WHERE r.token_hash=p_hash AND r.used_at IS NULL AND r.revoked_at IS NULL AND r.expires_at>now()
 AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND u.password_hash IS NOT NULL
 AND u.recovery_generation=r.account_generation)
$f$;

CREATE OR REPLACE FUNCTION public.consume_password_reset(p_hash text,p_password_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE r public.password_reset_tokens%ROWTYPE;
BEGIN
 IF p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' OR p_password_hash IS NULL OR p_password_hash !~ '^\$argon2id\$' THEN RETURN false;END IF;
 SELECT * INTO r FROM public.password_reset_tokens WHERE token_hash=p_hash;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.users WHERE id=r.user_id AND deleted_at IS NULL AND email_verified_at IS NOT NULL
  AND password_hash IS NOT NULL AND recovery_generation=r.account_generation FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO r FROM public.password_reset_tokens WHERE token_hash=p_hash FOR UPDATE;
 IF NOT FOUND OR r.used_at IS NOT NULL OR r.revoked_at IS NOT NULL OR r.expires_at<=now() THEN RETURN false;END IF;
 UPDATE public.users SET password_hash=p_password_hash,updated_at=now() WHERE id=r.user_id;
 UPDATE public.user_sessions SET revoked_at=now() WHERE user_id=r.user_id AND revoked_at IS NULL;
 UPDATE public.password_reset_tokens SET used_at=now() WHERE id=r.id;
 UPDATE public.password_reset_tokens SET revoked_at=now() WHERE user_id=r.user_id AND id<>r.id AND used_at IS NULL AND revoked_at IS NULL;
 RETURN true;
END $f$;
