-- Scope one retry key to an account and the complete, normalized request.
-- This table never grants access to a trip and is not available to runtime.
CREATE TABLE public.trip_creation_requests (
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  request_id uuid NOT NULL,
  community_id uuid NOT NULL REFERENCES public.communities(id) ON DELETE CASCADE,
  requested_title text NOT NULL,
  requested_timezone text NOT NULL,
  trip_id uuid REFERENCES public.trips(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, request_id)
);
REVOKE ALL ON public.trip_creation_requests FROM PUBLIC, sobralis_runtime;

CREATE FUNCTION public.create_trip_once(p_community uuid,p_actor uuid,p_request uuid,p_title text,p_timezone text)
RETURNS TABLE(result text,trip_id uuid,title text,timezone text,role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE req public.trip_creation_requests%ROWTYPE; created record;
BEGIN
 IF p_community IS NULL OR p_actor IS NULL OR p_request IS NULL OR p_title IS NULL OR
    char_length(p_title) NOT BETWEEN 1 AND 200 OR p_title<>btrim(p_title) OR
    p_timezone IS NULL OR char_length(p_timezone) NOT BETWEEN 1 AND 100 THEN
  RETURN QUERY SELECT 'invalid'::text,NULL::uuid,NULL::text,NULL::text,NULL::text; RETURN;
 END IF;
 -- Preserve the user-first locking order of create_trip_for_member.
 PERFORM 1 FROM public.users u WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text,NULL::text; RETURN; END IF;
 -- A nonexistent community must produce the same not-found result as the old
 -- route, rather than a foreign-key error or a retained request reservation.
 PERFORM 1 FROM public.communities c WHERE c.id=p_community AND c.deleted_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text,NULL::text; RETURN; END IF;
 INSERT INTO public.trip_creation_requests(user_id,request_id,community_id,requested_title,requested_timezone)
 VALUES(p_actor,p_request,p_community,p_title,p_timezone) ON CONFLICT(user_id,request_id) DO NOTHING;
 SELECT r.* INTO req FROM public.trip_creation_requests r WHERE r.user_id=p_actor AND r.request_id=p_request FOR UPDATE;
 IF req.community_id IS DISTINCT FROM p_community OR req.requested_title IS DISTINCT FROM p_title OR req.requested_timezone IS DISTINCT FROM p_timezone THEN
  RETURN QUERY SELECT 'conflict'::text,NULL::uuid,NULL::text,NULL::text,NULL::text; RETURN;
 END IF;
 IF req.trip_id IS NULL THEN
  SELECT * INTO created FROM public.create_trip_for_member(p_community,p_actor,p_title,p_timezone);
  IF created.result IS DISTINCT FROM 'created' OR created.trip_id IS NULL THEN
   -- Failed authorization/validation cannot reserve the key or create a trip.
   DELETE FROM public.trip_creation_requests r WHERE r.user_id=p_actor AND r.request_id=p_request;
   RETURN QUERY SELECT coalesce(created.result,'not_found')::text,NULL::uuid,NULL::text,NULL::text,NULL::text; RETURN;
  END IF;
  UPDATE public.trip_creation_requests r SET trip_id=created.trip_id WHERE r.user_id=p_actor AND r.request_id=p_request;
  req.trip_id:=created.trip_id;
 END IF;
 -- Replays never restore lost membership, a cancelled trip or a deleted group.
 RETURN QUERY SELECT 'created'::text,t.id,t.title,t.timezone,tm.role::text FROM public.trips t
 JOIN public.communities c ON c.id=t.community_id AND c.deleted_at IS NULL
 JOIN public.trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL
 JOIN public.community_members cm ON cm.community_id=t.community_id AND cm.user_id=p_actor AND cm.left_at IS NULL
 WHERE t.id=req.trip_id AND t.community_id=p_community AND t.deleted_at IS NULL;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::text,NULL::text,NULL::text; END IF;
END $f$;
REVOKE ALL ON FUNCTION public.create_trip_once(uuid,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_trip_once(uuid,uuid,uuid,text,text) TO sobralis_runtime;
