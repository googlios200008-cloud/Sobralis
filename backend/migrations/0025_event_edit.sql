-- Editing never deletes history or silently renews a host's consent. Home
-- meetings cannot be changed until a future explicit re-consent workflow exists.
-- A pending proposal also blocks changes to any meeting: it was made for the old
-- time. All checks and the update are serialized with proposal/host changes.
CREATE FUNCTION public.edit_event_for_member(
 p_actor uuid,p_event uuid,p_expected_revision uuid,p_title text,p_start timestamptz,p_timezone text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE access_row record; current_event public.events%ROWTYPE; moving boolean;
BEGIN
 IF p_expected_revision IS NULL THEN RETURN 'invalid'; END IF;
 SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF access_row.member_role NOT IN ('owner','editor') THEN RETURN 'forbidden'; END IF;
 SELECT * INTO current_event FROM public.events WHERE id=p_event;
 IF current_event.revision IS DISTINCT FROM p_expected_revision THEN RETURN 'conflict'; END IF;
 IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 200 OR
    p_start IS NULL OR p_start<'1900-01-01 00:00:00+00'::timestamptz OR p_start>='2101-01-01 00:00:00+00'::timestamptz OR
    p_timezone IS NULL OR char_length(p_timezone) NOT BETWEEN 1 AND 100 OR
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_timezone_names tz WHERE tz.name=p_timezone) THEN RETURN 'invalid'; END IF;
 moving := current_event.starts_at IS DISTINCT FROM p_start OR current_event.timezone IS DISTINCT FROM p_timezone;
 IF (current_event.title IS DISTINCT FROM btrim(p_title) OR moving) AND (current_event.venue_type='home' OR EXISTS(SELECT 1 FROM public.event_host_proposals hp WHERE hp.event_id=p_event AND hp.status='pending' AND public.host_proposal_valid(hp.id))) THEN
   RETURN 'host_confirmation_required';
 END IF;
 IF current_event.title IS DISTINCT FROM btrim(p_title) OR moving THEN
   UPDATE public.events SET title=btrim(p_title),starts_at=p_start,timezone=p_timezone,updated_at=clock_timestamp() WHERE id=p_event;
 END IF;
 RETURN 'updated';
END $f$;
REVOKE ALL ON FUNCTION public.edit_event_for_member(uuid,uuid,uuid,text,timestamptz,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.edit_event_for_member(uuid,uuid,uuid,text,timestamptz,text) TO sobralis_runtime;
