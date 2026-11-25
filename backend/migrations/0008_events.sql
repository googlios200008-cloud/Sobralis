-- Preserve existing events. Terms are decisions for the whole event, not votes.
-- A home host is the creator in this first stage; only the host may set their
-- own overnight decision. No API for reassigning hosts is provided yet.
ALTER TABLE public.events
  ADD COLUMN venue_type text NOT NULL DEFAULT 'other' CHECK (venue_type IN ('home','other')),
  ADD COLUMN host_id uuid,
  ADD COLUMN overnight text NOT NULL DEFAULT 'undecided' CHECK (overnight IN ('undecided','yes','no')),
  ADD COLUMN overnight_capacity integer,
  ADD COLUMN guests text NOT NULL DEFAULT 'undecided' CHECK (guests IN ('undecided','allowed','not_allowed')),
  ADD COLUMN alcohol text NOT NULL DEFAULT 'undecided' CHECK (alcohol IN ('undecided','yes','no')),
  ADD COLUMN food text NOT NULL DEFAULT '' CHECK (char_length(food)<=500),
  ADD CONSTRAINT event_host_member_fk FOREIGN KEY (community_id,host_id) REFERENCES public.community_members(community_id,user_id),
  ADD CONSTRAINT event_host_venue_check CHECK ((venue_type='home' AND host_id IS NOT NULL) OR (venue_type='other' AND host_id IS NULL)),
  ADD CONSTRAINT event_capacity_check CHECK ((overnight='yes' AND overnight_capacity BETWEEN 1 AND 99 AND overnight_capacity IS NOT NULL) OR (overnight<>'yes' AND overnight_capacity IS NULL)),
  ADD CONSTRAINT event_overnight_host_check CHECK (venue_type='home' OR overnight='undecided');
CREATE INDEX event_community_list_idx ON public.events(community_id,id) WHERE trip_id IS NULL AND deleted_at IS NULL;
CREATE INDEX event_trip_list_idx ON public.events(trip_id,id) WHERE trip_id IS NOT NULL AND deleted_at IS NULL;

-- Privileged function accepts the user ID only from the authenticated API. It
-- locks authorization rows and writes the event in one transaction. Runtime
-- has no direct SELECT/INSERT/UPDATE privilege on the events table.
CREATE FUNCTION public.create_event_for_member(
 p_actor uuid,p_scope text,p_scope_id uuid,p_title text,p_description text,p_location text,
 p_start timestamptz,p_timezone text,p_venue text,p_overnight text,p_capacity integer,
 p_guests text,p_alcohol text,p_food text)
RETURNS TABLE(result text,event jsonb) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE v_community uuid;v_trip uuid;v_role text;v_event public.events%ROWTYPE;
BEGIN
  PERFORM 1 FROM public.users WHERE id=p_actor AND deleted_at IS NULL AND email_verified_at IS NOT NULL FOR SHARE;
  IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::jsonb; RETURN; END IF;
  IF p_scope='community' THEN
    SELECT c.id,cm.role INTO v_community,v_role FROM public.communities c
      JOIN public.community_members cm ON cm.community_id=c.id AND cm.user_id=p_actor
      WHERE c.id=p_scope_id AND c.deleted_at IS NULL AND cm.left_at IS NULL AND cm.membership_scope='full'
      FOR SHARE OF c,cm;
  ELSIF p_scope='trip' THEN
    SELECT c.id,tm.role,t.id INTO v_community,v_role,v_trip FROM public.trips t
      JOIN public.communities c ON c.id=t.community_id
      JOIN public.trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_actor
      JOIN public.community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
      WHERE t.id=p_scope_id AND t.deleted_at IS NULL AND c.deleted_at IS NULL AND tm.left_at IS NULL AND cm.left_at IS NULL
      FOR SHARE OF t,c,tm,cm;
  ELSE
    RETURN QUERY SELECT 'invalid'::text,NULL::jsonb; RETURN;
  END IF;
  IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::jsonb; RETURN; END IF;
  IF v_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::jsonb; RETURN; END IF;
  IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 200 OR
     p_description IS NULL OR char_length(p_description)>5000 OR p_location IS NULL OR char_length(p_location)>500 OR
     p_start IS NULL OR p_start<'1900-01-01 00:00:00+00'::timestamptz OR p_start>='2101-01-01 00:00:00+00'::timestamptz OR
     p_timezone IS NULL OR char_length(p_timezone) NOT BETWEEN 1 AND 100 OR
     NOT EXISTS(SELECT 1 FROM pg_catalog.pg_timezone_names tz WHERE tz.name=p_timezone) OR
     p_venue IS NULL OR p_venue NOT IN ('home','other') OR p_overnight IS NULL OR p_overnight NOT IN ('undecided','yes','no') OR
     p_guests IS NULL OR p_guests NOT IN ('undecided','allowed','not_allowed') OR
     p_alcohol IS NULL OR p_alcohol NOT IN ('undecided','yes','no') OR p_food IS NULL OR char_length(p_food)>500 OR
     (p_venue='other' AND p_overnight<>'undecided') OR
     (p_overnight='yes' AND (p_capacity IS NULL OR p_capacity NOT BETWEEN 1 AND 99)) OR
     (p_overnight<>'yes' AND p_capacity IS NOT NULL) THEN
    RETURN QUERY SELECT 'invalid'::text,NULL::jsonb; RETURN;
  END IF;
  INSERT INTO public.events(community_id,trip_id,organizer_id,title,description,location,starts_at,timezone,venue_type,host_id,overnight,overnight_capacity,guests,alcohol,food)
    VALUES(v_community,v_trip,p_actor,btrim(p_title),p_description,p_location,p_start,p_timezone,p_venue,
      CASE WHEN p_venue='home' THEN p_actor ELSE NULL END,p_overnight,p_capacity,p_guests,p_alcohol,p_food)
    RETURNING * INTO v_event;
  RETURN QUERY SELECT 'created'::text,to_jsonb(v_event);
END
$body$;
REVOKE ALL ON FUNCTION public.create_event_for_member(uuid,text,uuid,text,text,text,timestamptz,text,text,text,integer,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_event_for_member(uuid,text,uuid,text,text,text,timestamptz,text,text,text,integer,text,text,text) TO sobralis_runtime;

-- Each read enforces the access rule in the SELECT itself, even when an
-- earlier parent check raced with a membership revocation.
CREATE FUNCTION public.list_events_for_member(p_actor uuid,p_scope text,p_scope_id uuid,p_cursor uuid)
RETURNS SETOF public.events LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT e.* FROM public.events e
 JOIN public.communities c ON c.id=e.community_id AND c.deleted_at IS NULL
 JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=p_actor AND cm.left_at IS NULL
 JOIN public.users u ON u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
 LEFT JOIN public.trips t ON t.id=e.trip_id AND t.community_id=e.community_id AND t.deleted_at IS NULL
 LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL
 WHERE e.deleted_at IS NULL AND (p_cursor IS NULL OR e.id>p_cursor) AND (
  (p_scope='community' AND e.community_id=p_scope_id AND e.trip_id IS NULL AND cm.membership_scope='full') OR
  (p_scope='trip' AND e.trip_id=p_scope_id AND t.id IS NOT NULL AND tm.user_id IS NOT NULL))
 ORDER BY e.id LIMIT 51
$body$;
REVOKE ALL ON FUNCTION public.list_events_for_member(uuid,text,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_events_for_member(uuid,text,uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.get_event_for_member(p_actor uuid,p_event uuid)
RETURNS SETOF public.events LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT e.* FROM public.events e
 JOIN public.communities c ON c.id=e.community_id AND c.deleted_at IS NULL
 JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=p_actor AND cm.left_at IS NULL
 JOIN public.users u ON u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
 LEFT JOIN public.trips t ON t.id=e.trip_id AND t.community_id=e.community_id AND t.deleted_at IS NULL
 LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL
 WHERE e.id=p_event AND e.deleted_at IS NULL AND ((e.trip_id IS NULL AND cm.membership_scope='full') OR
       (e.trip_id IS NOT NULL AND t.id IS NOT NULL AND tm.user_id IS NOT NULL))
$body$;
REVOKE ALL ON FUNCTION public.get_event_for_member(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_event_for_member(uuid,uuid) TO sobralis_runtime;
