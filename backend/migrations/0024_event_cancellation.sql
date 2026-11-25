-- Event cancellation is a soft delete: event data, votes, messages, host
-- consent and proposal history remain stored but no longer accessible via API.
-- Each update rotates an opaque revision for confirmation against stale views.
ALTER TABLE public.events ADD COLUMN revision uuid NOT NULL DEFAULT gen_random_uuid();
CREATE FUNCTION public.rotate_event_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 NEW.revision=gen_random_uuid();RETURN NEW;
END $f$;
CREATE TRIGGER rotate_event_revision BEFORE UPDATE ON public.events FOR EACH ROW EXECUTE FUNCTION public.rotate_event_revision();
REVOKE ALL ON FUNCTION public.rotate_event_revision() FROM PUBLIC;

CREATE FUNCTION public.cancel_event_for_member(p_actor uuid,p_event uuid,p_expected_revision uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE access_row record;event_revision uuid;
BEGIN
 IF p_expected_revision IS NULL THEN RETURN 'invalid';END IF;
 SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN 'not_found';END IF;
 IF access_row.member_role NOT IN ('owner','editor') THEN RETURN 'forbidden';END IF;
 SELECT revision INTO event_revision FROM public.events WHERE id=p_event;
 IF event_revision IS DISTINCT FROM p_expected_revision THEN RETURN 'conflict';END IF;
 UPDATE public.events SET deleted_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=p_event;
 RETURN 'cancelled';
END $f$;
REVOKE ALL ON FUNCTION public.cancel_event_for_member(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cancel_event_for_member(uuid,uuid,uuid) TO sobralis_runtime;
