-- A bounded, atomic write of a contiguous range. Existing rows are untouched
-- until a user explicitly submits a range; this migration never rewrites data.
CREATE FUNCTION public.write_schedule_range(p_actor uuid,p_community uuid,p_owner uuid,p_from date,p_to date,p_status text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE grant_id uuid;
BEGIN
 IF p_actor IS NULL OR p_owner IS NULL OR p_from IS NULL OR p_to IS NULL
    OR p_from < '1900-01-01'::date OR p_to > '2100-12-31'::date
    OR p_to < p_from OR p_to-p_from > 30
    OR p_status IS NULL OR p_status NOT IN ('free','work','busy','unknown') THEN RETURN false; END IF;
 IF p_actor=p_owner THEN
   PERFORM 1 FROM public.community_members cm JOIN public.communities c ON c.id=cm.community_id
     JOIN public.users u ON u.id=cm.user_id WHERE cm.community_id=p_community AND cm.user_id=p_actor
     AND cm.left_at IS NULL AND cm.membership_scope='full' AND cm.role IN ('owner','editor')
     AND c.deleted_at IS NULL AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
     FOR SHARE OF cm,c,u;
   IF NOT FOUND THEN RETURN false; END IF;
 ELSE
   IF NOT public.lock_schedule_delegation_members(p_community,p_owner,p_actor) THEN RETURN false; END IF;
   SELECT d.id INTO grant_id FROM public.schedule_delegations d WHERE d.community_id=p_community
     AND d.owner_id=p_owner AND d.delegate_id=p_actor AND d.revoked_at IS NULL FOR UPDATE;
   IF grant_id IS NULL THEN RETURN false; END IF;
 END IF;
 INSERT INTO public.schedule_entries(community_id,user_id,local_date,status)
 SELECT p_community,p_owner,p_from+n,p_status FROM generate_series(0,p_to-p_from) AS n
 ON CONFLICT (community_id,user_id,local_date) DO UPDATE SET status=EXCLUDED.status,updated_at=now();
 IF grant_id IS NOT NULL THEN
   INSERT INTO public.schedule_delegation_audit(delegation_id,actor_id,action) VALUES(grant_id,p_actor,'schedule_changed');
 END IF;
 RETURN true;
END $f$;
REVOKE ALL ON FUNCTION public.write_schedule_range(uuid,uuid,uuid,date,date,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.write_schedule_range(uuid,uuid,uuid,date,date,text) TO sobralis_runtime;
