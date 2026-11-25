-- Cancellation is a scoped soft delete. All memberships, invitations,
-- meetings, host agreements and discussions remain stored, but inaccessible.
-- An explicit tombstone prevents accidentally reviving old invitations and
-- host consent by clearing deleted_at outside a future audited restore flow.
ALTER TABLE public.trips ADD COLUMN cancelled_by_app boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT trip_cancelled_implies_deleted CHECK (NOT cancelled_by_app OR deleted_at IS NOT NULL);
CREATE TABLE public.trip_cancellations (
 trip_id uuid PRIMARY KEY REFERENCES public.trips(id) ON DELETE CASCADE,
 cancelled_by uuid NOT NULL REFERENCES public.users(id),
 cancelled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.trip_cancellations FROM PUBLIC,sobralis_runtime;
CREATE FUNCTION public.prevent_unsafe_trip_restore() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF OLD.cancelled_by_app AND (NEW.deleted_at IS NULL OR NOT NEW.cancelled_by_app) THEN
  RAISE EXCEPTION 'Cancelled trip cannot be restored without an audited restore workflow';
 END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER prevent_unsafe_trip_restore BEFORE UPDATE OF deleted_at,cancelled_by_app ON public.trips
 FOR EACH ROW EXECUTE FUNCTION public.prevent_unsafe_trip_restore();
REVOKE ALL ON FUNCTION public.prevent_unsafe_trip_restore() FROM PUBLIC;

CREATE FUNCTION public.cancel_trip_for_owner(p_actor uuid,p_trip uuid,p_revision uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE v_trip public.trips%ROWTYPE; actor_role text;
BEGIN
 IF p_actor IS NULL OR p_trip IS NULL THEN RETURN 'not_found'; END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 -- Same order as edit_trip_for_member: user, trip/community, memberships.
 SELECT t.* INTO v_trip FROM public.trips t JOIN public.communities c ON c.id=t.community_id
 WHERE t.id=p_trip AND t.deleted_at IS NULL AND c.deleted_at IS NULL
 AND EXISTS(SELECT 1 FROM public.trip_members tm JOIN public.community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
   WHERE tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL AND cm.left_at IS NULL)
 FOR UPDATE OF t FOR SHARE OF c;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 PERFORM 1 FROM public.community_members cm WHERE cm.community_id=v_trip.community_id AND cm.user_id=p_actor AND cm.left_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT tm.role INTO actor_role FROM public.trip_members tm WHERE tm.trip_id=p_trip AND tm.community_id=v_trip.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF actor_role<>'owner' THEN RETURN 'forbidden'; END IF;
 IF p_revision IS NULL OR v_trip.revision IS DISTINCT FROM p_revision THEN RETURN 'conflict'; END IF;
 INSERT INTO public.trip_cancellations(trip_id,cancelled_by) VALUES(p_trip,p_actor);
 UPDATE public.trips SET deleted_at=clock_timestamp(),cancelled_by_app=true,updated_at=clock_timestamp() WHERE id=p_trip;
 RETURN 'cancelled';
END $f$;
REVOKE ALL ON FUNCTION public.cancel_trip_for_owner(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cancel_trip_for_owner(uuid,uuid,uuid) TO sobralis_runtime;
