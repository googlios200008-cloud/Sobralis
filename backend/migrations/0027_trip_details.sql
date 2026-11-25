-- Existing trips are preserved with unspecified dates. A revision makes
-- changes conditional on the version the editor actually saw.
ALTER TABLE public.trips ADD COLUMN starts_on date, ADD COLUMN ends_on date,
 ADD COLUMN revision uuid NOT NULL DEFAULT gen_random_uuid(),
 ADD CONSTRAINT trip_date_range CHECK (
  (starts_on IS NULL AND ends_on IS NULL) OR
  (starts_on IS NOT NULL AND ends_on IS NOT NULL AND starts_on>=DATE '1900-01-01' AND ends_on<=DATE '2100-12-31'
   AND ends_on>=starts_on AND ends_on-starts_on<=365));
GRANT SELECT (starts_on,ends_on,revision) ON public.trips TO sobralis_runtime;
CREATE FUNCTION public.rotate_trip_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN NEW.revision=gen_random_uuid(); RETURN NEW; END $f$;
CREATE TRIGGER rotate_trip_revision BEFORE UPDATE ON public.trips FOR EACH ROW EXECUTE FUNCTION public.rotate_trip_revision();
REVOKE ALL ON FUNCTION public.rotate_trip_revision() FROM PUBLIC;
-- Retain the old function for migration history, but no longer let runtime
-- invoke the unconditional rename that could overwrite another editor's work.
REVOKE EXECUTE ON FUNCTION public.rename_trip_for_member(uuid,uuid,text) FROM sobralis_runtime;

CREATE FUNCTION public.edit_trip_for_member(p_actor uuid,p_trip uuid,p_revision uuid,p_title text,p_start date,p_end date)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE v_community uuid; actor_role text; old_trip public.trips%ROWTYPE;
BEGIN
 IF p_actor IS NULL OR p_trip IS NULL THEN RETURN 'not_found'; END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT t.* INTO old_trip FROM public.trips t JOIN public.communities c ON c.id=t.community_id
 WHERE t.id=p_trip AND t.deleted_at IS NULL AND c.deleted_at IS NULL
 AND EXISTS(SELECT 1 FROM public.trip_members tm JOIN public.community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
   WHERE tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL AND cm.left_at IS NULL)
 FOR UPDATE OF t FOR SHARE OF c;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 v_community=old_trip.community_id;
 PERFORM 1 FROM public.community_members cm WHERE cm.community_id=v_community AND cm.user_id=p_actor AND cm.left_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT tm.role INTO actor_role FROM public.trip_members tm WHERE tm.trip_id=p_trip AND tm.community_id=v_community AND tm.user_id=p_actor AND tm.left_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF actor_role NOT IN ('owner','editor') THEN RETURN 'forbidden'; END IF;
 IF p_revision IS NULL OR old_trip.revision IS DISTINCT FROM p_revision THEN RETURN 'conflict'; END IF;
 IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 200 OR (p_start IS NULL)<>(p_end IS NULL) OR
 (p_start IS NOT NULL AND (p_start<DATE '1900-01-01' OR p_end>DATE '2100-12-31' OR p_end<p_start OR p_end-p_start>365)) THEN RETURN 'invalid'; END IF;
 IF old_trip.title IS DISTINCT FROM btrim(p_title) OR old_trip.starts_on IS DISTINCT FROM p_start OR old_trip.ends_on IS DISTINCT FROM p_end THEN
  UPDATE public.trips SET title=btrim(p_title),starts_on=p_start,ends_on=p_end,updated_at=clock_timestamp() WHERE id=p_trip;
 END IF;
 RETURN 'updated';
END $f$;
REVOKE ALL ON FUNCTION public.edit_trip_for_member(uuid,uuid,uuid,text,date,date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.edit_trip_for_member(uuid,uuid,uuid,text,date,date) TO sobralis_runtime;
