-- Retry keys are private bookkeeping, never a grant of access to an event.
-- Identical keys are scoped to the authenticated actor and complete request.
CREATE TABLE public.event_creation_requests (
 user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
 request_id uuid NOT NULL,
 request_hash bytea NOT NULL CHECK (octet_length(request_hash)=32),
 event_id uuid REFERENCES public.events(id) ON DELETE CASCADE,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(user_id,request_id)
);
REVOKE ALL ON public.event_creation_requests FROM PUBLIC,sobralis_runtime;

CREATE FUNCTION public.create_event_once(
 p_actor uuid,p_request uuid,p_scope text,p_scope_id uuid,p_title text,p_description text,p_location text,
 p_start timestamptz,p_timezone text,p_venue text,p_overnight text,p_capacity integer,
 p_guests text,p_alcohol text,p_food text)
RETURNS TABLE(result text,event jsonb,host_active boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE req public.event_creation_requests%ROWTYPE;created record;access_row record;current_event public.events%ROWTYPE;fingerprint bytea;
BEGIN
 IF p_actor IS NULL OR p_request IS NULL OR p_scope IS NULL OR p_scope NOT IN ('community','trip') OR p_scope_id IS NULL THEN
  RETURN QUERY SELECT 'invalid'::text,NULL::jsonb,NULL::boolean; RETURN;
 END IF;
 -- Match the existing user-first lock order. Invalid attempts are never retained.
 PERFORM 1 FROM public.users u WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::jsonb,NULL::boolean; RETURN; END IF;
 -- Canonical JSON array with UTC epoch binds every request field without
 -- retaining an extra plaintext copy of event descriptions and locations.
 -- SHA-256 is not a secret: low-entropy requests may still be guessable.
 fingerprint:=pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.jsonb_build_array(
  p_scope,p_scope_id,p_title,p_description,p_location,extract(epoch FROM p_start),p_timezone,
  p_venue,p_overnight,p_capacity,p_guests,p_alcohol,p_food)::text,'UTF8'));
 INSERT INTO public.event_creation_requests(user_id,request_id,request_hash)
 VALUES(p_actor,p_request,fingerprint) ON CONFLICT(user_id,request_id) DO NOTHING;
 SELECT r.* INTO req FROM public.event_creation_requests r WHERE r.user_id=p_actor AND r.request_id=p_request FOR UPDATE;
 IF req.request_hash IS DISTINCT FROM fingerprint THEN
  RETURN QUERY SELECT 'conflict'::text,NULL::jsonb,NULL::boolean; RETURN;
 END IF;
 IF req.event_id IS NULL THEN
  SELECT * INTO created FROM public.create_event_for_member(p_actor,p_scope,p_scope_id,p_title,p_description,p_location,p_start,p_timezone,p_venue,p_overnight,p_capacity,p_guests,p_alcohol,p_food);
  IF created.result IS DISTINCT FROM 'created' OR created.event IS NULL THEN
   DELETE FROM public.event_creation_requests r WHERE r.user_id=p_actor AND r.request_id=p_request;
   RETURN QUERY SELECT coalesce(created.result,'not_found')::text,NULL::jsonb,NULL::boolean; RETURN;
  END IF;
  UPDATE public.event_creation_requests r SET event_id=(created.event->>'id')::uuid WHERE r.user_id=p_actor AND r.request_id=p_request;
  req.event_id:=(created.event->>'id')::uuid;
 END IF;
 -- A retry is not a capability: recheck the current user, membership, event,
 -- community and trip, and serialize against cancellation and membership edits.
 SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,req.event_id);
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::jsonb,NULL::boolean; RETURN; END IF;
 SELECT e.* INTO current_event FROM public.get_event_for_member(p_actor,req.event_id) e;
 IF NOT FOUND OR (p_scope='community' AND (current_event.trip_id IS NOT NULL OR current_event.community_id IS DISTINCT FROM p_scope_id)) OR
    (p_scope='trip' AND current_event.trip_id IS DISTINCT FROM p_scope_id) THEN
  RETURN QUERY SELECT 'not_found'::text,NULL::jsonb,NULL::boolean; RETURN;
 END IF;
 RETURN QUERY SELECT 'created'::text,to_jsonb(current_event),public.event_host_currently_active(p_actor,req.event_id);
END
$body$;
REVOKE ALL ON FUNCTION public.create_event_once(uuid,uuid,text,uuid,text,text,text,timestamptz,text,text,text,integer,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_event_once(uuid,uuid,text,uuid,text,text,text,timestamptz,text,text,text,integer,text,text,text) TO sobralis_runtime;
