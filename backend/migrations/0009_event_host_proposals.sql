-- Proposals are separate from the confirmed host on the event. A request does
-- not change who hosts or claim consent. One outstanding request per event.
CREATE TABLE public.event_host_proposals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES public.events(id),
  proposed_by uuid NOT NULL REFERENCES public.users(id),
  proposed_host uuid NOT NULL REFERENCES public.users(id),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','cancelled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now()+interval '7 days',
  responded_at timestamptz,
  CHECK(expires_at>created_at),
  CHECK((status='pending' AND responded_at IS NULL) OR (status<>'pending' AND responded_at IS NOT NULL))
);
CREATE UNIQUE INDEX one_pending_event_host_proposal ON public.event_host_proposals(event_id) WHERE status='pending';

-- Internal helper: actor first, then lock event and scope authorization rows.
-- Not exposed to runtime; the caller holds these locks until its transaction ends.
CREATE FUNCTION public.lock_event_for_member(p_actor uuid,p_event uuid)
RETURNS TABLE(member_role text,community_id uuid,trip_id uuid,host_id uuid,venue_type text,location text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE v_trip uuid;
BEGIN
  PERFORM 1 FROM public.users WHERE id=p_actor AND deleted_at IS NULL AND email_verified_at IS NOT NULL FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT e.trip_id INTO v_trip FROM public.events e WHERE e.id=p_event AND e.deleted_at IS NULL;
  IF NOT FOUND THEN RETURN; END IF;
  IF v_trip IS NULL THEN
    RETURN QUERY SELECT cm.role,e.community_id,e.trip_id,e.host_id,e.venue_type,e.location FROM public.events e
      JOIN public.communities c ON c.id=e.community_id
      JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=p_actor
      WHERE e.id=p_event AND e.trip_id IS NULL AND e.deleted_at IS NULL AND c.deleted_at IS NULL
        AND cm.left_at IS NULL AND cm.membership_scope='full'
      FOR UPDATE OF e FOR SHARE OF c,cm;
  ELSE
    RETURN QUERY SELECT tm.role,e.community_id,e.trip_id,e.host_id,e.venue_type,e.location FROM public.events e
      JOIN public.communities c ON c.id=e.community_id
      JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=p_actor
      JOIN public.trips t ON t.id=e.trip_id AND t.community_id=e.community_id
      JOIN public.trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_actor
      WHERE e.id=p_event AND e.trip_id=v_trip AND e.deleted_at IS NULL AND c.deleted_at IS NULL
        AND t.deleted_at IS NULL AND cm.left_at IS NULL AND tm.left_at IS NULL
      FOR UPDATE OF e FOR SHARE OF c,cm,t,tm;
  END IF;
END
$body$;
REVOKE ALL ON FUNCTION public.lock_event_for_member(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION public.propose_event_host(p_actor uuid,p_event uuid,p_host uuid)
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
  IF access_row.venue_type='home' AND access_row.host_id=p_host THEN RETURN QUERY SELECT 'already_host'::text,NULL::uuid,NULL::timestamptz; RETURN; END IF;
  SELECT * INTO existing FROM public.event_host_proposals hp WHERE hp.event_id=p_event AND hp.status='pending' FOR UPDATE;
  IF FOUND AND existing.proposed_host=p_host AND existing.expires_at>clock_timestamp() THEN
    RETURN QUERY SELECT 'pending'::text,existing.id,existing.expires_at; RETURN;
  END IF;
  UPDATE public.event_host_proposals hp SET status='cancelled',responded_at=now() WHERE hp.event_id=p_event AND hp.status='pending';
  INSERT INTO public.event_host_proposals(event_id,proposed_by,proposed_host) VALUES(p_event,p_actor,p_host) RETURNING * INTO new_row;
  RETURN QUERY SELECT 'pending'::text,new_row.id,new_row.expires_at;
END
$body$;
REVOKE ALL ON FUNCTION public.propose_event_host(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.propose_event_host(uuid,uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.respond_event_host(p_actor uuid,p_event uuid,p_proposal uuid,p_decision text,p_clear_location boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record; proposal public.event_host_proposals%ROWTYPE;
BEGIN
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  SELECT * INTO proposal FROM public.event_host_proposals hp WHERE hp.id=p_proposal AND hp.event_id=p_event FOR UPDATE;
  IF NOT FOUND OR proposal.proposed_host<>p_actor THEN RETURN 'not_found'; END IF;
  IF proposal.status<>'pending' OR proposal.expires_at<=clock_timestamp() THEN RETURN 'stale'; END IF;
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
  IF proposal.expires_at<=clock_timestamp() THEN RETURN 'stale'; END IF;
  -- The old location may belong to another host or place. Do not silently
  -- erase it; the new host explicitly confirms removal before transition.
  IF access_row.location<>'' AND NOT p_clear_location THEN RETURN 'location_confirmation_required'; END IF;
  UPDATE public.events SET venue_type='home',host_id=p_actor,overnight='undecided',overnight_capacity=NULL,
    location='',updated_at=now() WHERE id=p_event;
  UPDATE public.event_host_proposals SET status='accepted',responded_at=now() WHERE id=p_proposal;
  RETURN 'accepted';
END
$body$;
REVOKE ALL ON FUNCTION public.respond_event_host(uuid,uuid,uuid,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.respond_event_host(uuid,uuid,uuid,text,boolean) TO sobralis_runtime;

CREATE FUNCTION public.cancel_event_host(p_actor uuid,p_event uuid,p_proposal uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record;
BEGIN
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  IF access_row.member_role NOT IN ('owner','editor') THEN RETURN 'forbidden'; END IF;
  UPDATE public.event_host_proposals hp SET status='cancelled',responded_at=now()
    WHERE hp.id=p_proposal AND hp.event_id=p_event AND hp.status='pending';
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  RETURN 'cancelled';
END
$body$;
REVOKE ALL ON FUNCTION public.cancel_event_host(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cancel_event_host(uuid,uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.set_event_host_conditions(p_actor uuid,p_event uuid,p_overnight text,p_capacity integer)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record;
BEGIN
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  IF access_row.venue_type<>'home' OR access_row.host_id IS DISTINCT FROM p_actor THEN RETURN 'forbidden'; END IF;
  IF p_overnight IS NULL OR p_overnight NOT IN ('undecided','yes','no') OR
    (p_overnight='yes' AND (p_capacity IS NULL OR p_capacity NOT BETWEEN 1 AND 99)) OR
    (p_overnight<>'yes' AND p_capacity IS NOT NULL) THEN RETURN 'invalid'; END IF;
  UPDATE public.events SET overnight=p_overnight,overnight_capacity=p_capacity,updated_at=now() WHERE id=p_event;
  RETURN 'updated';
END
$body$;
REVOKE ALL ON FUNCTION public.set_event_host_conditions(uuid,uuid,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_event_host_conditions(uuid,uuid,text,integer) TO sobralis_runtime;

-- Visible to existing event participants only; expired or completed requests
-- are not returned. Rechecks event access in the same query as proposal read.
CREATE FUNCTION public.get_pending_event_host(p_actor uuid,p_event uuid)
RETURNS TABLE(id uuid,proposed_by uuid,proposed_host uuid,created_at timestamptz,expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
  SELECT hp.id,hp.proposed_by,hp.proposed_host,hp.created_at,hp.expires_at
  FROM public.event_host_proposals hp
  JOIN public.get_event_for_member(p_actor,p_event) e ON e.id=hp.event_id
  JOIN public.users issuer ON issuer.id=hp.proposed_by AND issuer.deleted_at IS NULL AND issuer.email_verified_at IS NOT NULL
  JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=hp.proposed_by AND cm.left_at IS NULL
  LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=hp.proposed_by AND tm.left_at IS NULL
  WHERE hp.event_id=p_event AND hp.status='pending' AND hp.expires_at>now()
    AND ((e.trip_id IS NULL AND cm.membership_scope='full' AND cm.role IN ('owner','editor')) OR
         (e.trip_id IS NOT NULL AND tm.role IN ('owner','editor')))
$body$;
REVOKE ALL ON FUNCTION public.get_pending_event_host(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_pending_event_host(uuid,uuid) TO sobralis_runtime;

-- Current membership status is informative, not fresh consent: historical
-- conditions must not be treated as reconfirmed after a member rejoins.
CREATE FUNCTION public.event_host_currently_active(p_actor uuid,p_event uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT CASE WHEN e.venue_type<>'home' THEN NULL ELSE
   (u.id IS NOT NULL AND cm.user_id IS NOT NULL AND
     ((e.trip_id IS NULL AND cm.membership_scope='full') OR (e.trip_id IS NOT NULL AND tm.user_id IS NOT NULL))) END
 FROM public.get_event_for_member(p_actor,p_event) e
 LEFT JOIN public.users u ON u.id=e.host_id AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
 LEFT JOIN public.community_members cm ON cm.community_id=e.community_id AND cm.user_id=e.host_id AND cm.left_at IS NULL
 LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=e.host_id AND tm.left_at IS NULL
$body$;
REVOKE ALL ON FUNCTION public.event_host_currently_active(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.event_host_currently_active(uuid,uuid) TO sobralis_runtime;
