-- Only full active community owners/editors may create trips. Authorization and
-- creation of initial owner membership happen in a single transaction. The
-- caller obtains p_actor from the authenticated session, never the request body.
CREATE FUNCTION public.create_trip_for_member(p_community uuid, p_actor uuid, p_title text, p_timezone text)
RETURNS TABLE(result text, trip_id uuid, title text, timezone text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE member_role text; new_trip uuid;
BEGIN
  -- Match the user-first ordering used by invite redemption; never create for
  -- a deleted or unverified account if its state changed after session lookup.
  PERFORM 1 FROM public.users WHERE id=p_actor AND deleted_at IS NULL AND email_verified_at IS NOT NULL FOR SHARE;
  IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text; RETURN; END IF;
  -- Lock the parent and membership until the trip and owner row exist; departure,
  -- role changes and community deletion serialize with this creation.
  SELECT cm.role INTO member_role FROM public.community_members cm
  JOIN public.communities c ON c.id=cm.community_id
  WHERE cm.community_id=p_community AND cm.user_id=p_actor AND cm.left_at IS NULL
    AND cm.membership_scope='full' AND c.deleted_at IS NULL
  FOR SHARE OF c,cm;
  IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text; RETURN; END IF;
  IF member_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid,NULL::text,NULL::text; RETURN; END IF;
  IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 200 OR
     p_timezone IS NULL OR char_length(p_timezone) NOT BETWEEN 1 AND 100 OR
     NOT EXISTS(SELECT 1 FROM pg_catalog.pg_timezone_names tz WHERE tz.name=p_timezone) THEN
    RETURN QUERY SELECT 'invalid'::text,NULL::uuid,NULL::text,NULL::text; RETURN;
  END IF;
  INSERT INTO public.trips AS t(community_id,title,timezone,created_by)
    VALUES(p_community,btrim(p_title),p_timezone,p_actor) RETURNING t.id INTO new_trip;
  INSERT INTO public.trip_members(trip_id,community_id,user_id,role)
    VALUES(new_trip,p_community,p_actor,'owner');
  RETURN QUERY SELECT 'created'::text,t.id,t.title,t.timezone FROM public.trips t WHERE t.id=new_trip;
END
$body$;
REVOKE ALL ON FUNCTION public.create_trip_for_member(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_trip_for_member(uuid,uuid,text,text) TO sobralis_runtime;
-- Existing column-level SELECT permissions suffice for listing; no direct INSERT
-- or UPDATE grant for memberships or trip creation is introduced.
