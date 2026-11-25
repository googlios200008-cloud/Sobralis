-- Leaving a trip or removing a trip member does not delete the community,
-- other trips, events, votes, messages, or historical membership records.
-- No direct membership UPDATE grant is given to the runtime role.
CREATE FUNCTION public.remove_trip_member(p_actor uuid,p_trip uuid,p_target uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE v_community uuid; actor_role text; target_role text;
BEGIN
 IF p_actor IS NULL OR p_trip IS NULL OR p_target IS NULL THEN RETURN 'not_found'; END IF;
 -- Serialize actor authorization, especially concurrent exit or demotion.
 -- Exclusive lock also prevents competing leave requests from deadlocking on
   -- a shared-to-exclusive upgrade of the actor's trip membership.
 SELECT t.community_id,tm.role INTO v_community,actor_role
 FROM public.trips t
 JOIN public.communities c ON c.id=t.community_id AND c.deleted_at IS NULL
 JOIN public.community_members cm ON cm.community_id=t.community_id AND cm.user_id=p_actor AND cm.left_at IS NULL
 JOIN public.trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL
 JOIN public.users u ON u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
 WHERE t.id=p_trip AND t.deleted_at IS NULL
 FOR UPDATE OF tm FOR SHARE OF t,c,cm,u;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF p_actor<>p_target AND actor_role<>'owner' THEN RETURN 'not_found'; END IF;
 IF p_actor=p_target AND actor_role='owner' THEN RETURN 'owner_restricted'; END IF;
 SELECT tm.role INTO target_role FROM public.trip_members tm
 WHERE tm.trip_id=p_trip AND tm.community_id=v_community AND tm.user_id=p_target AND tm.left_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 -- Ownership transfer/deletion is deliberately not implemented here.
 IF target_role='owner' THEN RETURN 'owner_restricted'; END IF;
 UPDATE public.trip_members SET left_at=clock_timestamp()
 WHERE trip_id=p_trip AND community_id=v_community AND user_id=p_target AND left_at IS NULL;
 RETURN 'removed';
END $f$;
REVOKE ALL ON FUNCTION public.remove_trip_member(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.remove_trip_member(uuid,uuid,uuid) TO sobralis_runtime;
