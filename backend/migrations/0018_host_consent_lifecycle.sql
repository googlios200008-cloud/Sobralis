-- Host consent is scoped to a particular verified account and uninterrupted
-- membership, not merely a matching user ID. Tokens rotate on loss of access;
-- random tokens also prevent delete/recreate from reviving an earlier consent.
ALTER TABLE public.users ADD COLUMN hosting_generation uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE public.community_members ADD COLUMN hosting_generation uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE public.trip_members ADD COLUMN hosting_generation uuid NOT NULL DEFAULT gen_random_uuid();

CREATE FUNCTION public.rotate_user_hosting_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL) OR (OLD.email_verified_at IS NOT NULL AND NEW.email_verified_at IS NULL) THEN
   NEW.hosting_generation=gen_random_uuid();
 END IF; RETURN NEW;
END $f$;
CREATE TRIGGER rotate_user_hosting_generation BEFORE UPDATE OF deleted_at,email_verified_at ON public.users
 FOR EACH ROW EXECUTE FUNCTION public.rotate_user_hosting_generation();
REVOKE ALL ON FUNCTION public.rotate_user_hosting_generation() FROM PUBLIC;

CREATE FUNCTION public.rotate_community_hosting_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF OLD.left_at IS NULL AND (NEW.left_at IS NOT NULL OR (OLD.membership_scope='full' AND NEW.membership_scope<>'full') OR (OLD.role IN ('owner','editor') AND NEW.role='viewer')) THEN
   NEW.hosting_generation=gen_random_uuid();
 END IF; RETURN NEW;
END $f$;
CREATE TRIGGER rotate_community_hosting_generation BEFORE UPDATE OF left_at,membership_scope,role ON public.community_members
 FOR EACH ROW EXECUTE FUNCTION public.rotate_community_hosting_generation();
REVOKE ALL ON FUNCTION public.rotate_community_hosting_generation() FROM PUBLIC;

CREATE FUNCTION public.rotate_trip_hosting_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF OLD.left_at IS NULL AND (NEW.left_at IS NOT NULL OR (OLD.role IN ('owner','editor') AND NEW.role='viewer')) THEN
   NEW.hosting_generation=gen_random_uuid();
 END IF; RETURN NEW;
END $f$;
CREATE TRIGGER rotate_trip_hosting_generation BEFORE UPDATE OF left_at,role ON public.trip_members
 FOR EACH ROW EXECUTE FUNCTION public.rotate_trip_hosting_generation();
REVOKE ALL ON FUNCTION public.rotate_trip_hosting_generation() FROM PUBLIC;

-- No automatic backfill: an older host might have left and rejoined before
-- generation tracking existed. Preserve historical fields, but do not claim
-- that they are currently agreed. Require a fresh proposal and acceptance.
CREATE TABLE public.event_host_consents (
 event_id uuid PRIMARY KEY REFERENCES public.events(id) ON DELETE CASCADE,
 host_id uuid NOT NULL REFERENCES public.users(id),
 user_generation uuid NOT NULL, community_generation uuid NOT NULL, trip_generation uuid,
 consented_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.event_host_proposal_generations (
 proposal_id uuid PRIMARY KEY REFERENCES public.event_host_proposals(id) ON DELETE CASCADE,
 issuer_user uuid NOT NULL, issuer_community uuid NOT NULL, issuer_trip uuid,
 host_user uuid NOT NULL, host_community uuid NOT NULL, host_trip uuid
);
-- No direct privileges to runtime, even for the snapshots.

CREATE FUNCTION public.record_event_host_consent() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE ug uuid; cg uuid; tg uuid;
BEGIN
 IF NEW.venue_type='home' THEN
   SELECT u.hosting_generation,cm.hosting_generation,tm.hosting_generation INTO ug,cg,tg
   FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id AND cm.community_id=NEW.community_id AND cm.left_at IS NULL
   LEFT JOIN public.trip_members tm ON tm.community_id=cm.community_id AND tm.user_id=cm.user_id AND tm.trip_id=NEW.trip_id AND tm.left_at IS NULL
   WHERE u.id=NEW.host_id AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
    AND ((NEW.trip_id IS NULL AND cm.membership_scope='full') OR (NEW.trip_id IS NOT NULL AND tm.user_id IS NOT NULL));
   IF ug IS NULL THEN RAISE EXCEPTION 'host is not an active verified member'; END IF;
   INSERT INTO public.event_host_consents(event_id,host_id,user_generation,community_generation,trip_generation)
     VALUES(NEW.id,NEW.host_id,ug,cg,tg)
     ON CONFLICT(event_id) DO UPDATE SET host_id=excluded.host_id,user_generation=excluded.user_generation,
       community_generation=excluded.community_generation,trip_generation=excluded.trip_generation,consented_at=clock_timestamp();
 ELSE
   DELETE FROM public.event_host_consents WHERE event_id=NEW.id;
 END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER record_event_host_consent AFTER INSERT OR UPDATE OF venue_type,host_id ON public.events
 FOR EACH ROW EXECUTE FUNCTION public.record_event_host_consent();
REVOKE ALL ON FUNCTION public.record_event_host_consent() FROM PUBLIC;

CREATE FUNCTION public.host_consent_valid(p_event uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT EXISTS(
  SELECT 1 FROM public.events e JOIN public.event_host_consents hc ON hc.event_id=e.id AND hc.host_id=e.host_id
  JOIN public.users u ON u.id=hc.host_id AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND u.hosting_generation=hc.user_generation
  JOIN public.community_members cm ON cm.user_id=u.id AND cm.community_id=e.community_id AND cm.left_at IS NULL AND cm.hosting_generation=hc.community_generation
  LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=u.id AND tm.left_at IS NULL
  WHERE e.id=p_event AND e.deleted_at IS NULL AND e.venue_type='home'
    AND ((e.trip_id IS NULL AND cm.membership_scope='full' AND hc.trip_generation IS NULL) OR
         (e.trip_id IS NOT NULL AND tm.user_id IS NOT NULL AND tm.hosting_generation=hc.trip_generation))
 )
$f$;
REVOKE ALL ON FUNCTION public.host_consent_valid(uuid) FROM PUBLIC;

CREATE FUNCTION public.record_host_proposal_generations() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 INSERT INTO public.event_host_proposal_generations(proposal_id,issuer_user,issuer_community,issuer_trip,host_user,host_community,host_trip)
 SELECT NEW.id,iu.hosting_generation,ic.hosting_generation,it.hosting_generation,hu.hosting_generation,hc.hosting_generation,ht.hosting_generation
 FROM public.events e JOIN public.users iu ON iu.id=NEW.proposed_by AND iu.deleted_at IS NULL AND iu.email_verified_at IS NOT NULL
 JOIN public.community_members ic ON ic.community_id=e.community_id AND ic.user_id=iu.id AND ic.left_at IS NULL
 LEFT JOIN public.trip_members it ON it.trip_id=e.trip_id AND it.community_id=e.community_id AND it.user_id=iu.id AND it.left_at IS NULL
 JOIN public.users hu ON hu.id=NEW.proposed_host AND hu.deleted_at IS NULL AND hu.email_verified_at IS NOT NULL
 JOIN public.community_members hc ON hc.community_id=e.community_id AND hc.user_id=hu.id AND hc.left_at IS NULL
 LEFT JOIN public.trip_members ht ON ht.trip_id=e.trip_id AND ht.community_id=e.community_id AND ht.user_id=hu.id AND ht.left_at IS NULL
 WHERE e.id=NEW.event_id AND ((e.trip_id IS NULL AND ic.membership_scope='full' AND ic.role IN ('owner','editor') AND hc.membership_scope='full') OR
   (e.trip_id IS NOT NULL AND it.user_id IS NOT NULL AND it.role IN ('owner','editor') AND ht.user_id IS NOT NULL));
 IF NOT FOUND THEN RAISE EXCEPTION 'proposal participants are not active'; END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER record_host_proposal_generations AFTER INSERT ON public.event_host_proposals
 FOR EACH ROW EXECUTE FUNCTION public.record_host_proposal_generations();
REVOKE ALL ON FUNCTION public.record_host_proposal_generations() FROM PUBLIC;

CREATE FUNCTION public.host_proposal_valid(p_proposal uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT EXISTS(SELECT 1 FROM public.event_host_proposals hp
 JOIN public.event_host_proposal_generations pg ON pg.proposal_id=hp.id
 JOIN public.events e ON e.id=hp.event_id AND e.deleted_at IS NULL
 JOIN public.users iu ON iu.id=hp.proposed_by AND iu.deleted_at IS NULL AND iu.email_verified_at IS NOT NULL AND iu.hosting_generation=pg.issuer_user
 JOIN public.community_members ic ON ic.community_id=e.community_id AND ic.user_id=iu.id AND ic.left_at IS NULL AND ic.hosting_generation=pg.issuer_community
 LEFT JOIN public.trip_members it ON it.trip_id=e.trip_id AND it.community_id=e.community_id AND it.user_id=iu.id AND it.left_at IS NULL
 JOIN public.users hu ON hu.id=hp.proposed_host AND hu.deleted_at IS NULL AND hu.email_verified_at IS NOT NULL AND hu.hosting_generation=pg.host_user
 JOIN public.community_members hc ON hc.community_id=e.community_id AND hc.user_id=hu.id AND hc.left_at IS NULL AND hc.hosting_generation=pg.host_community
 LEFT JOIN public.trip_members ht ON ht.trip_id=e.trip_id AND ht.community_id=e.community_id AND ht.user_id=hu.id AND ht.left_at IS NULL
 WHERE hp.id=p_proposal AND hp.status='pending' AND hp.expires_at>now() AND
 ((e.trip_id IS NULL AND ic.membership_scope='full' AND ic.role IN ('owner','editor') AND hc.membership_scope='full' AND pg.issuer_trip IS NULL AND pg.host_trip IS NULL) OR
  (e.trip_id IS NOT NULL AND it.user_id IS NOT NULL AND it.role IN ('owner','editor') AND it.hosting_generation=pg.issuer_trip AND ht.user_id IS NOT NULL AND ht.hosting_generation=pg.host_trip)))
$f$;
REVOKE ALL ON FUNCTION public.host_proposal_valid(uuid) FROM PUBLIC;

-- A host can withdraw without deleting the event or its historical fields.
-- Participant-facing reads below no longer expose old location/overnight terms.
CREATE FUNCTION public.withdraw_event_host_consent(p_actor uuid,p_event uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE a record;
BEGIN
 SELECT * INTO a FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF a.venue_type<>'home' OR a.host_id IS DISTINCT FROM p_actor THEN RETURN 'forbidden'; END IF;
 DELETE FROM public.event_host_consents WHERE event_id=p_event;
 RETURN 'revoked';
END $f$;
REVOKE ALL ON FUNCTION public.withdraw_event_host_consent(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.withdraw_event_host_consent(uuid,uuid) TO sobralis_runtime;

CREATE OR REPLACE FUNCTION public.propose_event_host(p_actor uuid,p_event uuid,p_host uuid)
RETURNS TABLE(result text,proposal_id uuid,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record;existing public.event_host_proposals%ROWTYPE; new_row public.event_host_proposals%ROWTYPE;
BEGIN
  IF p_host IS NULL THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid,NULL::timestamptz; RETURN; END IF;
  -- Lock both users in deterministic order before the event to avoid cross-request deadlocks.
  PERFORM 1 FROM public.users WHERE id IN (p_actor,p_host) AND deleted_at IS NULL AND email_verified_at IS NOT NULL ORDER BY id FOR SHARE;
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
  IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::timestamptz; RETURN; END IF;
  IF access_row.member_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid,NULL::timestamptz; RETURN; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.users WHERE id=p_host AND deleted_at IS NULL AND email_verified_at IS NOT NULL) THEN
    RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::timestamptz; RETURN;
  END IF;
  IF access_row.trip_id IS NULL THEN
    PERFORM 1 FROM public.community_members cm WHERE cm.community_id=access_row.community_id AND cm.user_id=p_host
      AND cm.left_at IS NULL AND cm.membership_scope='full' FOR SHARE;
  ELSE
    PERFORM 1 FROM public.community_members cm JOIN public.trip_members tm ON tm.community_id=cm.community_id AND tm.user_id=cm.user_id
      WHERE cm.community_id=access_row.community_id AND cm.user_id=p_host AND cm.left_at IS NULL
        AND tm.trip_id=access_row.trip_id AND tm.left_at IS NULL FOR SHARE OF cm,tm;
  END IF;
  IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid,NULL::timestamptz; RETURN; END IF;
  IF access_row.venue_type='home' AND access_row.host_id=p_host AND public.host_consent_valid(p_event) THEN RETURN QUERY SELECT 'already_host'::text,NULL::uuid,NULL::timestamptz; RETURN; END IF;
  SELECT * INTO existing FROM public.event_host_proposals hp WHERE hp.event_id=p_event AND hp.status='pending' FOR UPDATE;
  IF FOUND AND existing.proposed_host=p_host AND existing.expires_at>clock_timestamp() AND public.host_proposal_valid(existing.id) THEN
    RETURN QUERY SELECT 'pending'::text,existing.id,existing.expires_at; RETURN;
  END IF;
  UPDATE public.event_host_proposals hp SET status='cancelled',responded_at=now() WHERE hp.event_id=p_event AND hp.status='pending';
  INSERT INTO public.event_host_proposals(event_id,proposed_by,proposed_host) VALUES(p_event,p_actor,p_host) RETURNING * INTO new_row;
  RETURN QUERY SELECT 'pending'::text,new_row.id,new_row.expires_at;
END
$body$;

CREATE OR REPLACE FUNCTION public.respond_event_host(p_actor uuid,p_event uuid,p_proposal uuid,p_decision text,p_clear_location boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record; proposal public.event_host_proposals%ROWTYPE;
BEGIN
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  SELECT * INTO proposal FROM public.event_host_proposals hp WHERE hp.id=p_proposal AND hp.event_id=p_event FOR UPDATE;
  IF NOT FOUND OR proposal.proposed_host<>p_actor THEN RETURN 'not_found'; END IF;
  IF proposal.status<>'pending' OR proposal.expires_at<=clock_timestamp() OR NOT public.host_proposal_valid(proposal.id) THEN RETURN 'stale'; END IF;
  IF p_decision IS NULL OR p_decision NOT IN ('accept','decline') OR p_clear_location IS NULL THEN RETURN 'invalid'; END IF;
  IF p_decision='decline' THEN
    UPDATE public.event_host_proposals SET status='declined',responded_at=now() WHERE id=p_proposal;
    RETURN 'declined';
  END IF;
  -- An editor's authority must remain active until acceptance; hold the rows
  -- during the transition so membership/role revocation cannot race it.
  IF access_row.trip_id IS NULL THEN
    PERFORM 1 FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id
      WHERE u.id=proposal.proposed_by AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
        AND cm.community_id=access_row.community_id AND cm.left_at IS NULL
        AND cm.membership_scope='full' AND cm.role IN ('owner','editor') FOR SHARE OF u,cm;
  ELSE
    PERFORM 1 FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id
      JOIN public.trip_members tm ON tm.community_id=cm.community_id AND tm.user_id=cm.user_id
      WHERE u.id=proposal.proposed_by AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
        AND cm.community_id=access_row.community_id AND cm.left_at IS NULL AND tm.trip_id=access_row.trip_id
        AND tm.left_at IS NULL AND tm.role IN ('owner','editor') FOR SHARE OF u,cm,tm;
  END IF;
  IF NOT FOUND THEN
    UPDATE public.event_host_proposals SET status='cancelled',responded_at=now() WHERE id=p_proposal;
    RETURN 'stale';
  END IF;
  IF proposal.expires_at<=clock_timestamp() OR NOT public.host_proposal_valid(proposal.id) THEN RETURN 'stale'; END IF;
  -- The old location may belong to another host or place. Do not silently
  -- erase it; the new host explicitly confirms removal before transition.
  IF access_row.location<>'' AND NOT p_clear_location THEN RETURN 'location_confirmation_required'; END IF;
  UPDATE public.events SET venue_type='home',host_id=p_actor,overnight='undecided',overnight_capacity=NULL,
    location='',updated_at=now() WHERE id=p_event;
  UPDATE public.event_host_proposals SET status='accepted',responded_at=now() WHERE id=p_proposal;
  RETURN 'accepted';
END
$body$;

CREATE OR REPLACE FUNCTION public.set_event_host_conditions(p_actor uuid,p_event uuid,p_overnight text,p_capacity integer)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record;
BEGIN
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  IF access_row.venue_type<>'home' OR access_row.host_id IS DISTINCT FROM p_actor OR NOT public.host_consent_valid(p_event) THEN RETURN 'forbidden'; END IF;
  IF p_overnight IS NULL OR p_overnight NOT IN ('undecided','yes','no') OR
    (p_overnight='yes' AND (p_capacity IS NULL OR p_capacity NOT BETWEEN 1 AND 99)) OR
    (p_overnight<>'yes' AND p_capacity IS NOT NULL) THEN RETURN 'invalid'; END IF;
  UPDATE public.events SET overnight=p_overnight,overnight_capacity=p_capacity,updated_at=now() WHERE id=p_event;
  RETURN 'updated';
END
$body$;

CREATE OR REPLACE FUNCTION public.get_pending_event_host(p_actor uuid,p_event uuid)
RETURNS TABLE(id uuid,proposed_by uuid,proposed_host uuid,created_at timestamptz,expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
  SELECT hp.id,hp.proposed_by,hp.proposed_host,hp.created_at,hp.expires_at
  FROM public.event_host_proposals hp
  JOIN public.get_event_for_member(p_actor,p_event) e ON e.id=hp.event_id
  JOIN public.users issuer ON issuer.id=hp.proposed_by AND issuer.deleted_at IS NULL AND issuer.email_verified_at IS NOT NULL
  JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=hp.proposed_by AND cm.left_at IS NULL
  LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=hp.proposed_by AND tm.left_at IS NULL
  WHERE hp.event_id=p_event AND hp.status='pending' AND hp.expires_at>now() AND public.host_proposal_valid(hp.id)
    AND ((e.trip_id IS NULL AND cm.membership_scope='full' AND cm.role IN ('owner','editor')) OR
         (e.trip_id IS NOT NULL AND tm.role IN ('owner','editor')))
$body$;

CREATE OR REPLACE FUNCTION public.event_host_currently_active(p_actor uuid,p_event uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT CASE WHEN e.venue_type<>'home' THEN NULL ELSE public.host_consent_valid(e.id) END
 FROM public.get_event_for_member(p_actor,p_event) e
$body$;

-- Return unchanged event rows except for stale home-only terms. Stored values
-- remain intact for recovery/audit; no stale address or overnight promise is
-- presented to participants as current. Apply this at SQL authorization
-- boundary, not just in a specific HTTP view.
CREATE OR REPLACE FUNCTION public.get_event_for_member(p_actor uuid,p_event uuid)
RETURNS SETOF public.events LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE v public.events%ROWTYPE;
BEGIN
 FOR v IN
 SELECT e.* FROM public.events e
 JOIN public.communities c ON c.id=e.community_id AND c.deleted_at IS NULL
 JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=p_actor AND cm.left_at IS NULL
 JOIN public.users u ON u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
 LEFT JOIN public.trips t ON t.id=e.trip_id AND t.community_id=e.community_id AND t.deleted_at IS NULL
 LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL
 WHERE e.id=p_event AND e.deleted_at IS NULL AND ((e.trip_id IS NULL AND cm.membership_scope='full') OR
       (e.trip_id IS NOT NULL AND t.id IS NOT NULL AND tm.user_id IS NOT NULL))
 LOOP
   IF v.venue_type='home' AND NOT public.host_consent_valid(v.id) THEN v.location='';v.overnight='undecided';v.overnight_capacity=NULL; END IF;
   RETURN NEXT v;
 END LOOP;
END $body$;

CREATE OR REPLACE FUNCTION public.list_events_for_member(p_actor uuid,p_scope text,p_scope_id uuid,p_cursor uuid)
RETURNS SETOF public.events LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE v public.events%ROWTYPE;
BEGIN
 FOR v IN
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
 LOOP
   IF v.venue_type='home' AND NOT public.host_consent_valid(v.id) THEN v.location='';v.overnight='undecided';v.overnight_capacity=NULL; END IF;
   RETURN NEXT v;
 END LOOP;
END $body$;
