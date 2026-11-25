-- Serialize trip mutations in an explicit order: actor user, trip/community,
-- actor community membership, actor trip membership, target trip membership.
-- This keeps rename and departure from racing and avoids lock upgrades.
CREATE OR REPLACE FUNCTION public.remove_trip_member(p_actor uuid,p_trip uuid,p_target uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE v_community uuid; actor_role text; target_role text;
BEGIN
 IF p_actor IS NULL OR p_trip IS NULL OR p_target IS NULL THEN RETURN 'not_found'; END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT t.community_id INTO v_community FROM public.trips t JOIN public.communities c ON c.id=t.community_id
 WHERE t.id=p_trip AND t.deleted_at IS NULL AND c.deleted_at IS NULL FOR SHARE OF t,c;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 PERFORM 1 FROM public.community_members cm WHERE cm.community_id=v_community AND cm.user_id=p_actor AND cm.left_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT tm.role INTO actor_role FROM public.trip_members tm
 WHERE tm.trip_id=p_trip AND tm.community_id=v_community AND tm.user_id=p_actor AND tm.left_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF p_actor<>p_target AND actor_role<>'owner' THEN RETURN 'not_found'; END IF;
 IF p_actor=p_target AND actor_role='owner' THEN RETURN 'owner_restricted'; END IF;
 SELECT tm.role INTO target_role FROM public.trip_members tm
 WHERE tm.trip_id=p_trip AND tm.community_id=v_community AND tm.user_id=p_target AND tm.left_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF target_role='owner' THEN RETURN 'owner_restricted'; END IF;
 UPDATE public.trip_members SET left_at=clock_timestamp()
 WHERE trip_id=p_trip AND community_id=v_community AND user_id=p_target AND left_at IS NULL;
 RETURN 'removed';
END $f$;

CREATE FUNCTION public.rename_trip_for_member(p_actor uuid,p_trip uuid,p_title text)
RETURNS TABLE(result text,id uuid,title text,timezone text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE v_community uuid; actor_role text; v_trip public.trips%ROWTYPE;
BEGIN
 IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 200 THEN
   RETURN QUERY SELECT 'invalid'::text,NULL::uuid,NULL::text,NULL::text;RETURN;
 END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text;RETURN;END IF;
 SELECT t.community_id INTO v_community FROM public.trips t JOIN public.communities c ON c.id=t.community_id
 WHERE t.id=p_trip AND t.deleted_at IS NULL AND c.deleted_at IS NULL
   AND EXISTS(SELECT 1 FROM public.trip_members tm JOIN public.community_members cm
     ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
     WHERE tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL AND cm.left_at IS NULL)
 FOR UPDATE OF t FOR SHARE OF c;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text;RETURN;END IF;
 PERFORM 1 FROM public.community_members cm WHERE cm.community_id=v_community AND cm.user_id=p_actor AND cm.left_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text;RETURN;END IF;
 SELECT tm.role INTO actor_role FROM public.trip_members tm
 WHERE tm.trip_id=p_trip AND tm.community_id=v_community AND tm.user_id=p_actor AND tm.left_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text;RETURN;END IF;
 IF actor_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid,NULL::text,NULL::text;RETURN;END IF;
 UPDATE public.trips t SET title=btrim(p_title) WHERE t.id=p_trip RETURNING t.* INTO v_trip;
 RETURN QUERY SELECT 'updated'::text,v_trip.id,v_trip.title,v_trip.timezone;
END $f$;
REVOKE ALL ON FUNCTION public.rename_trip_for_member(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rename_trip_for_member(uuid,uuid,text) TO sobralis_runtime;
-- No direct title mutation: only the locked, membership-checked function above.
REVOKE UPDATE (title) ON trips FROM sobralis_runtime;
