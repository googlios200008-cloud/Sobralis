-- Trip owners can review/revoke prior invitations without exposing token hashes.
-- This is additive and leaves existing trips, members and invitations intact.
CREATE INDEX trip_invites_trip_id_id_idx ON public.trip_invites(trip_id,id);
CREATE FUNCTION public.list_trip_invites_for_owner(p_actor uuid,p_trip uuid,p_cursor uuid)
RETURNS TABLE(invite_id uuid,granted_role text,max_uses integer,uses_count integer,
              created_at timestamptz,expires_at timestamptz,disabled_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT i.id,i.granted_role,i.max_uses,i.uses_count,i.created_at,i.expires_at,i.disabled_at
 FROM public.trip_invites i
 WHERE i.trip_id=p_trip AND (p_cursor IS NULL OR i.id>p_cursor)
   AND EXISTS (SELECT 1 FROM public.trip_members tm
     JOIN public.trips t ON t.id=tm.trip_id AND t.community_id=tm.community_id
     JOIN public.communities c ON c.id=tm.community_id
     JOIN public.community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
     JOIN public.users u ON u.id=tm.user_id
     WHERE tm.trip_id=p_trip AND tm.user_id=p_actor AND tm.role='owner' AND tm.left_at IS NULL
       AND cm.left_at IS NULL AND t.deleted_at IS NULL AND c.deleted_at IS NULL
       AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL)
 ORDER BY i.id LIMIT 51
$f$;
REVOKE ALL ON FUNCTION public.list_trip_invites_for_owner(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_trip_invites_for_owner(uuid,uuid,uuid) TO sobralis_runtime;
