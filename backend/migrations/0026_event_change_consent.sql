-- A requested change to a home meeting is a separate, expiring agreement.
-- Nothing changes until the existing host explicitly accepts the exact draft.
-- A fresh random generation prevents a withdrawn and renewed consent from
-- reviving an old request, even if timestamps happen to coincide.
CREATE TABLE public.event_host_consent_generations (
 event_id uuid PRIMARY KEY REFERENCES public.event_host_consents(event_id) ON DELETE CASCADE,
 generation uuid NOT NULL DEFAULT gen_random_uuid()
);
REVOKE ALL ON public.event_host_consent_generations FROM PUBLIC,sobralis_runtime;
INSERT INTO public.event_host_consent_generations(event_id) SELECT event_id FROM public.event_host_consents;
CREATE FUNCTION public.rotate_host_consent_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 INSERT INTO public.event_host_consent_generations(event_id,generation) VALUES(NEW.event_id,gen_random_uuid())
 ON CONFLICT(event_id) DO UPDATE SET generation=excluded.generation;
 RETURN NEW;
END $f$;
CREATE TRIGGER rotate_host_consent_generation AFTER INSERT OR UPDATE ON public.event_host_consents
 FOR EACH ROW EXECUTE FUNCTION public.rotate_host_consent_generation();
REVOKE ALL ON FUNCTION public.rotate_host_consent_generation() FROM PUBLIC;

CREATE TABLE public.event_change_proposals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 event_id uuid NOT NULL REFERENCES public.events(id) ON DELETE CASCADE,
 proposed_by uuid NOT NULL REFERENCES public.users(id),
 host_id uuid NOT NULL REFERENCES public.users(id),
 expected_revision uuid NOT NULL,
 issuer_user_generation uuid NOT NULL, issuer_community_generation uuid NOT NULL, issuer_trip_generation uuid,
 host_consent_generation uuid NOT NULL,
 title text NOT NULL CHECK(char_length(btrim(title)) BETWEEN 1 AND 200),
 starts_at timestamptz NOT NULL, timezone text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','cancelled')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '7 days',
 responded_at timestamptz,
 CHECK(expires_at>created_at),
 CHECK((status='pending' AND responded_at IS NULL) OR (status<>'pending' AND responded_at IS NOT NULL))
);
CREATE UNIQUE INDEX one_pending_event_change ON public.event_change_proposals(event_id) WHERE status='pending';
REVOKE ALL ON public.event_change_proposals FROM PUBLIC,sobralis_runtime;

CREATE FUNCTION public.event_change_valid(p_proposal uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT EXISTS(SELECT 1 FROM public.event_change_proposals p
 JOIN public.events e ON e.id=p.event_id AND e.deleted_at IS NULL AND e.revision=p.expected_revision
   AND e.venue_type='home' AND e.host_id=p.host_id
 JOIN public.event_host_consents hc ON hc.event_id=e.id AND hc.host_id=p.host_id
 JOIN public.event_host_consent_generations hg ON hg.event_id=e.id AND hg.generation=p.host_consent_generation
 JOIN public.users iu ON iu.id=p.proposed_by AND iu.deleted_at IS NULL AND iu.email_verified_at IS NOT NULL AND iu.hosting_generation=p.issuer_user_generation
 JOIN public.community_members ic ON ic.community_id=e.community_id AND ic.user_id=iu.id AND ic.left_at IS NULL AND ic.hosting_generation=p.issuer_community_generation
 LEFT JOIN public.trip_members it ON it.trip_id=e.trip_id AND it.community_id=e.community_id AND it.user_id=iu.id AND it.left_at IS NULL
 WHERE p.id=p_proposal AND p.status='pending' AND p.expires_at>now() AND public.host_consent_valid(e.id)
 AND ((e.trip_id IS NULL AND ic.membership_scope='full' AND ic.role IN ('owner','editor') AND p.issuer_trip_generation IS NULL)
 OR (e.trip_id IS NOT NULL AND it.user_id IS NOT NULL AND it.role IN ('owner','editor') AND it.hosting_generation=p.issuer_trip_generation))
 AND NOT EXISTS(SELECT 1 FROM public.event_host_proposals hp WHERE hp.event_id=e.id AND hp.status='pending' AND public.host_proposal_valid(hp.id))
 )
$f$;
REVOKE ALL ON FUNCTION public.event_change_valid(uuid) FROM PUBLIC;

CREATE FUNCTION public.propose_event_change(p_actor uuid,p_event uuid,p_expected uuid,p_title text,p_start timestamptz,p_timezone text)
RETURNS TABLE(result text,proposal_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE a record; e public.events%ROWTYPE; pending uuid; new_id uuid;
BEGIN
 SELECT * INTO a FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN; END IF;
 IF a.member_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid; RETURN; END IF;
 SELECT * INTO e FROM public.events WHERE id=p_event;
 IF p_expected IS NULL OR e.revision IS DISTINCT FROM p_expected THEN RETURN QUERY SELECT 'conflict'::text,NULL::uuid; RETURN; END IF;
 IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 200 OR p_start IS NULL OR
 p_start<'1900-01-01 00:00:00+00'::timestamptz OR p_start>='2101-01-01 00:00:00+00'::timestamptz OR
 p_timezone IS NULL OR char_length(p_timezone) NOT BETWEEN 1 AND 100 OR
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_timezone_names tz WHERE tz.name=p_timezone) THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 IF e.venue_type<>'home' OR NOT public.host_consent_valid(p_event) OR EXISTS(SELECT 1 FROM public.event_host_proposals hp WHERE hp.event_id=p_event AND hp.status='pending' AND public.host_proposal_valid(hp.id)) THEN
   RETURN QUERY SELECT 'host_unavailable'::text,NULL::uuid; RETURN;
 END IF;
 IF e.title=btrim(p_title) AND e.starts_at=p_start AND e.timezone=p_timezone THEN RETURN QUERY SELECT 'unchanged'::text,NULL::uuid; RETURN; END IF;
 SELECT p.id INTO pending FROM public.event_change_proposals p WHERE p.event_id=p_event AND p.status='pending' FOR UPDATE;
 IF FOUND AND public.event_change_valid(pending) THEN RETURN QUERY SELECT 'pending'::text,NULL::uuid; RETURN; END IF;
 IF FOUND THEN UPDATE public.event_change_proposals SET status='cancelled',responded_at=clock_timestamp() WHERE id=pending; END IF;
 INSERT INTO public.event_change_proposals(event_id,proposed_by,host_id,expected_revision,issuer_user_generation,issuer_community_generation,issuer_trip_generation,host_consent_generation,title,starts_at,timezone)
 SELECT e.id,p_actor,e.host_id,e.revision,u.hosting_generation,cm.hosting_generation,tm.hosting_generation,hg.generation,btrim(p_title),p_start,p_timezone
 FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id AND cm.community_id=e.community_id
 LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=u.id
 JOIN public.event_host_consents hc ON hc.event_id=e.id AND hc.host_id=e.host_id
 JOIN public.event_host_consent_generations hg ON hg.event_id=hc.event_id
 WHERE u.id=p_actor RETURNING id INTO new_id;
 IF new_id IS NULL THEN RAISE EXCEPTION 'Cannot capture event change authority'; END IF;
 RETURN QUERY SELECT 'created'::text,new_id;
END $f$;
REVOKE ALL ON FUNCTION public.propose_event_change(uuid,uuid,uuid,text,timestamptz,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.propose_event_change(uuid,uuid,uuid,text,timestamptz,text) TO sobralis_runtime;

CREATE FUNCTION public.get_event_change(p_actor uuid,p_event uuid)
RETURNS TABLE(id uuid,proposed_by uuid,host_id uuid,title text,starts_at timestamptz,timezone text,expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT p.id,p.proposed_by,p.host_id,p.title,p.starts_at,p.timezone,p.expires_at
 FROM public.event_change_proposals p JOIN public.get_event_for_member(p_actor,p_event) e ON e.id=p.event_id
 WHERE p.event_id=p_event AND p.status='pending' AND public.event_change_valid(p.id)
$f$;
REVOKE ALL ON FUNCTION public.get_event_change(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_event_change(uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.respond_event_change(p_actor uuid,p_event uuid,p_proposal uuid,p_decision text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE a record; p public.event_change_proposals%ROWTYPE;
BEGIN
 SELECT * INTO a FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT * INTO p FROM public.event_change_proposals WHERE id=p_proposal AND event_id=p_event FOR UPDATE;
 IF NOT FOUND OR p.host_id IS DISTINCT FROM p_actor THEN RETURN 'not_found'; END IF;
 IF p_decision NOT IN ('accept','decline') OR p_decision IS NULL THEN RETURN 'invalid'; END IF;
 IF p.expires_at<=clock_timestamp() OR NOT public.event_change_valid(p.id) THEN RETURN 'stale'; END IF;
 IF p_decision='decline' THEN UPDATE public.event_change_proposals SET status='declined',responded_at=clock_timestamp() WHERE id=p.id; RETURN 'declined'; END IF;
 -- Hold the issuer's user and memberships so revocation wins if it commits first.
 IF a.trip_id IS NULL THEN
  PERFORM 1 FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id
   WHERE u.id=p.proposed_by AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND cm.community_id=a.community_id
   AND cm.left_at IS NULL AND cm.membership_scope='full' AND cm.role IN ('owner','editor') FOR SHARE OF u,cm;
 ELSE
  PERFORM 1 FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id
   JOIN public.trip_members tm ON tm.community_id=cm.community_id AND tm.user_id=cm.user_id
   WHERE u.id=p.proposed_by AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND cm.community_id=a.community_id
   AND cm.left_at IS NULL AND tm.trip_id=a.trip_id AND tm.left_at IS NULL AND tm.role IN ('owner','editor') FOR SHARE OF u,cm,tm;
 END IF;
 IF NOT FOUND OR p.expires_at<=clock_timestamp() OR NOT public.event_change_valid(p.id) THEN RETURN 'stale'; END IF;
 UPDATE public.events SET title=p.title,starts_at=p.starts_at,timezone=p.timezone,updated_at=clock_timestamp() WHERE id=p_event;
 UPDATE public.event_host_consents SET consented_at=clock_timestamp() WHERE event_id=p_event AND host_id=p_actor;
 UPDATE public.event_change_proposals SET status='accepted',responded_at=clock_timestamp() WHERE id=p.id;
 RETURN 'accepted';
END $f$;
REVOKE ALL ON FUNCTION public.respond_event_change(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.respond_event_change(uuid,uuid,uuid,text) TO sobralis_runtime;

CREATE FUNCTION public.cancel_event_change(p_actor uuid,p_event uuid,p_proposal uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE a record;
BEGIN
 SELECT * INTO a FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF a.member_role NOT IN ('owner','editor') THEN RETURN 'forbidden'; END IF;
 UPDATE public.event_change_proposals SET status='cancelled',responded_at=clock_timestamp() WHERE id=p_proposal AND event_id=p_event AND status='pending';
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 RETURN 'cancelled';
END $f$;
REVOKE ALL ON FUNCTION public.cancel_event_change(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cancel_event_change(uuid,uuid,uuid) TO sobralis_runtime;
