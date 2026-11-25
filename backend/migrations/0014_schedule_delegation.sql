-- A narrowly scoped permission given by the schedule owner to another verified
-- member. This is not a family relationship or a general account delegation.
CREATE TABLE public.schedule_delegations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 community_id uuid NOT NULL REFERENCES public.communities(id),
 owner_id uuid NOT NULL,
 delegate_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 revoked_at timestamptz,
 CHECK (owner_id <> delegate_id),
 FOREIGN KEY (community_id,owner_id) REFERENCES public.community_members(community_id,user_id),
 FOREIGN KEY (community_id,delegate_id) REFERENCES public.community_members(community_id,user_id)
);
CREATE UNIQUE INDEX schedule_delegations_active ON public.schedule_delegations(community_id,owner_id,delegate_id) WHERE revoked_at IS NULL;
CREATE TABLE public.schedule_delegation_audit (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 delegation_id uuid NOT NULL REFERENCES public.schedule_delegations(id),
 actor_id uuid NOT NULL REFERENCES public.users(id),
 action text NOT NULL CHECK(action IN ('granted','revoked','schedule_changed')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX schedule_delegation_audit_time ON public.schedule_delegation_audit(created_at);
-- Direct table access is deliberately not granted to the runtime role.

-- Cancel outstanding permissions immediately on membership exit/downgrade.
-- Rejoining later must not resurrect permissions even if joined_at is unchanged.
CREATE FUNCTION public.invalidate_schedule_delegations_on_membership() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF OLD.left_at IS NULL AND (NEW.left_at IS NOT NULL OR (OLD.membership_scope='full' AND NEW.membership_scope<>'full') OR (OLD.role IN ('owner','editor') AND NEW.role='viewer')) THEN
   UPDATE public.schedule_delegations d SET revoked_at=clock_timestamp()
   WHERE d.community_id=OLD.community_id AND (d.owner_id=OLD.user_id OR d.delegate_id=OLD.user_id) AND d.revoked_at IS NULL;
 END IF;
 RETURN NEW;
END $f$;
REVOKE ALL ON FUNCTION public.invalidate_schedule_delegations_on_membership() FROM PUBLIC;
CREATE TRIGGER invalidate_schedule_delegations_on_membership BEFORE UPDATE OF left_at,membership_scope,role ON public.community_members
 FOR EACH ROW EXECUTE FUNCTION public.invalidate_schedule_delegations_on_membership();

CREATE FUNCTION public.invalidate_schedule_delegations_on_user() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL) OR (OLD.email_verified_at IS NOT NULL AND NEW.email_verified_at IS NULL) THEN
   UPDATE public.schedule_delegations d SET revoked_at=clock_timestamp() WHERE (d.owner_id=OLD.id OR d.delegate_id=OLD.id) AND d.revoked_at IS NULL;
 END IF;
 RETURN NEW;
END $f$;
REVOKE ALL ON FUNCTION public.invalidate_schedule_delegations_on_user() FROM PUBLIC;
CREATE TRIGGER invalidate_schedule_delegations_on_user BEFORE UPDATE OF deleted_at,email_verified_at ON public.users
 FOR EACH ROW EXECUTE FUNCTION public.invalidate_schedule_delegations_on_user();

-- Lock both memberships in a stable order before the grant row. The same
-- membership locks serialize writes with revocation caused by leaving.
CREATE FUNCTION public.lock_schedule_delegation_members(p_community uuid,p_owner uuid,p_delegate uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE n integer;
BEGIN
 IF p_owner IS NULL OR p_delegate IS NULL OR p_owner=p_delegate THEN RETURN false; END IF;
 PERFORM cm.user_id FROM public.community_members cm WHERE cm.community_id=p_community AND cm.user_id IN (p_owner,p_delegate)
   AND cm.left_at IS NULL AND cm.membership_scope='full' AND cm.role IN ('owner','editor') ORDER BY cm.user_id FOR SHARE;
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>2 THEN RETURN false; END IF;
 PERFORM 1 FROM public.communities c WHERE c.id=p_community AND c.deleted_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM u.id FROM public.users u WHERE u.id IN (p_owner,p_delegate) AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL ORDER BY u.id FOR SHARE;
 GET DIAGNOSTICS n=ROW_COUNT; RETURN n=2;
END $f$;
REVOKE ALL ON FUNCTION public.lock_schedule_delegation_members(uuid,uuid,uuid) FROM PUBLIC;

CREATE FUNCTION public.grant_schedule_delegate(p_owner uuid,p_community uuid,p_delegate uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE grant_id uuid;
BEGIN
 IF NOT public.lock_schedule_delegation_members(p_community,p_owner,p_delegate) THEN RETURN NULL; END IF;
 INSERT INTO public.schedule_delegations(community_id,owner_id,delegate_id) VALUES(p_community,p_owner,p_delegate)
 ON CONFLICT (community_id,owner_id,delegate_id) WHERE revoked_at IS NULL DO NOTHING RETURNING id INTO grant_id;
 IF grant_id IS NULL THEN SELECT d.id INTO grant_id FROM public.schedule_delegations d WHERE d.community_id=p_community AND d.owner_id=p_owner AND d.delegate_id=p_delegate AND d.revoked_at IS NULL; RETURN grant_id; END IF;
 INSERT INTO public.schedule_delegation_audit(delegation_id,actor_id,action) VALUES(grant_id,p_owner,'granted');
 RETURN grant_id;
END $f$;
REVOKE ALL ON FUNCTION public.grant_schedule_delegate(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.grant_schedule_delegate(uuid,uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.revoke_schedule_delegate(p_actor uuid,p_community uuid,p_grant uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE grant_id uuid;
BEGIN
 UPDATE public.schedule_delegations d SET revoked_at=clock_timestamp() WHERE d.id=p_grant AND d.community_id=p_community AND d.owner_id=p_actor AND d.revoked_at IS NULL RETURNING d.id INTO grant_id;
 IF grant_id IS NULL THEN RETURN false; END IF;
 INSERT INTO public.schedule_delegation_audit(delegation_id,actor_id,action) VALUES(grant_id,p_actor,'revoked');
 RETURN true;
END $f$;
REVOKE ALL ON FUNCTION public.revoke_schedule_delegate(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.revoke_schedule_delegate(uuid,uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.list_schedule_delegations(p_actor uuid,p_community uuid)
RETURNS TABLE(id uuid,owner_id uuid,delegate_id uuid,created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT d.id,d.owner_id,d.delegate_id,d.created_at FROM public.schedule_delegations d
 JOIN public.communities c ON c.id=d.community_id AND c.deleted_at IS NULL
 JOIN public.community_members o ON o.community_id=d.community_id AND o.user_id=d.owner_id AND o.left_at IS NULL AND o.membership_scope='full' AND o.role IN ('owner','editor')
 JOIN public.community_members a ON a.community_id=d.community_id AND a.user_id=d.delegate_id AND a.left_at IS NULL AND a.membership_scope='full' AND a.role IN ('owner','editor')
 JOIN public.users ou ON ou.id=d.owner_id AND ou.deleted_at IS NULL AND ou.email_verified_at IS NOT NULL
 JOIN public.users au ON au.id=d.delegate_id AND au.deleted_at IS NULL AND au.email_verified_at IS NOT NULL
 WHERE d.community_id=p_community AND d.revoked_at IS NULL AND p_actor IN (d.owner_id,d.delegate_id) ORDER BY d.created_at,d.id LIMIT 501
$f$;
REVOKE ALL ON FUNCTION public.list_schedule_delegations(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_schedule_delegations(uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.write_delegated_schedule(p_actor uuid,p_community uuid,p_owner uuid,p_date date,p_status text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE grant_id uuid;
BEGIN
 IF p_date IS NULL OR p_date < '1900-01-01'::date OR p_date > '2100-12-31'::date OR p_status IS NULL OR p_status NOT IN ('free','work','busy','unknown') THEN RETURN false; END IF;
 IF NOT public.lock_schedule_delegation_members(p_community,p_owner,p_actor) THEN RETURN false; END IF;
 SELECT d.id INTO grant_id FROM public.schedule_delegations d WHERE d.community_id=p_community AND d.owner_id=p_owner AND d.delegate_id=p_actor AND d.revoked_at IS NULL FOR UPDATE;
 IF grant_id IS NULL THEN RETURN false; END IF;
 INSERT INTO public.schedule_entries(community_id,user_id,local_date,status) VALUES(p_community,p_owner,p_date,p_status)
 ON CONFLICT(community_id,user_id,local_date) DO UPDATE SET status=EXCLUDED.status,updated_at=now();
 INSERT INTO public.schedule_delegation_audit(delegation_id,actor_id,action) VALUES(grant_id,p_actor,'schedule_changed');
 RETURN true;
END $f$;
REVOKE ALL ON FUNCTION public.write_delegated_schedule(uuid,uuid,uuid,date,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.write_delegated_schedule(uuid,uuid,uuid,date,text) TO sobralis_runtime;
