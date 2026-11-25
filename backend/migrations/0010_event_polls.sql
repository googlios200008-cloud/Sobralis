-- Retain existing polls/votes; limit direct table access as before. UUID cursor
-- index supports scoped listing without reading other events.
CREATE INDEX event_polls_list_idx ON public.event_polls(event_id,id) WHERE deleted_at IS NULL;
CREATE INDEX event_poll_votes_option_idx ON public.event_poll_votes(poll_id,option_id,user_id);

CREATE FUNCTION public.create_event_poll(p_actor uuid,p_event uuid,p_question text,p_options text[])
RETURNS TABLE(result text,poll_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record;new_poll uuid;
BEGIN
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
  IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN; END IF;
  IF access_row.member_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid; RETURN; END IF;
  IF p_question IS NULL OR char_length(btrim(p_question)) NOT BETWEEN 1 AND 500 OR
     p_options IS NULL OR cardinality(p_options) NOT BETWEEN 2 AND 10 OR
     EXISTS(SELECT 1 FROM unnest(p_options) o(label) WHERE o.label IS NULL OR char_length(btrim(o.label)) NOT BETWEEN 1 AND 500) OR
     (SELECT count(DISTINCT lower(btrim(o.label))) FROM unnest(p_options) o(label))<>cardinality(p_options) THEN
    RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN;
  END IF;
  INSERT INTO public.event_polls AS ep(event_id,community_id,question)
    VALUES(p_event,access_row.community_id,btrim(p_question)) RETURNING ep.id INTO new_poll;
  INSERT INTO public.event_poll_options(poll_id,label,position)
    SELECT new_poll,btrim(v.label),(v.ord-1)::integer FROM unnest(p_options) WITH ORDINALITY AS v(label,ord);
  RETURN QUERY SELECT 'created'::text,new_poll;
END
$body$;
REVOKE ALL ON FUNCTION public.create_event_poll(uuid,uuid,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_event_poll(uuid,uuid,text,text[]) TO sobralis_runtime;

-- Each poll has one mutable choice per user. NULL means withdraw the vote.
-- The event lock serializes authorization, poll writes and concurrent changes.
CREATE FUNCTION public.set_event_poll_vote(p_actor uuid,p_poll uuid,p_option uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE v_event_id uuid;access_row record;
BEGIN
  SELECT ep.event_id INTO v_event_id FROM public.event_polls ep WHERE ep.id=p_poll AND ep.deleted_at IS NULL;
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,v_event_id);
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  IF access_row.member_role NOT IN ('owner','editor') THEN RETURN 'forbidden'; END IF;
  PERFORM 1 FROM public.event_polls ep WHERE ep.id=p_poll AND ep.event_id=v_event_id AND ep.deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  IF p_option IS NULL THEN
    DELETE FROM public.event_poll_votes WHERE poll_id=p_poll AND user_id=p_actor;
    RETURN 'withdrawn';
  END IF;
  PERFORM 1 FROM public.event_poll_options o WHERE o.id=p_option AND o.poll_id=p_poll AND o.deleted_at IS NULL FOR SHARE;
  IF NOT FOUND THEN RETURN 'invalid_option'; END IF;
  INSERT INTO public.event_poll_votes AS v(poll_id,community_id,user_id,option_id)
    VALUES(p_poll,access_row.community_id,p_actor,p_option)
    ON CONFLICT(poll_id,user_id) DO UPDATE SET option_id=EXCLUDED.option_id,updated_at=now();
  RETURN 'voted';
END
$body$;
REVOKE ALL ON FUNCTION public.set_event_poll_vote(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_event_poll_vote(uuid,uuid,uuid) TO sobralis_runtime;

-- Match the prototype's named votes: active event participants can see voter
-- display names and ids, never emails. Do not market these polls as anonymous.
CREATE FUNCTION public.list_event_polls(p_actor uuid,p_event uuid,p_cursor uuid)
RETURNS TABLE(id uuid,question text,created_at timestamptz,options jsonb,my_option_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT p.id,p.question,p.created_at,
   COALESCE((SELECT jsonb_agg(jsonb_build_object('id',o.id,'label',o.label,'position',o.position,
       'votes',totals.votes,'voters',totals.voters,'votersTruncated',totals.votes>50) ORDER BY o.position)
     FROM public.event_poll_options o
     CROSS JOIN LATERAL (
       WITH eligible AS MATERIALIZED (
         SELECT u.id,u.display_name FROM public.event_poll_votes v
         JOIN public.users u ON u.id=v.user_id AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
         JOIN public.community_members cm ON cm.community_id=v.community_id AND cm.user_id=v.user_id AND cm.left_at IS NULL
         LEFT JOIN public.trip_members tm ON tm.trip_id=e.trip_id AND tm.community_id=e.community_id AND tm.user_id=v.user_id AND tm.left_at IS NULL
         WHERE v.poll_id=p.id AND v.option_id=o.id AND
           ((e.trip_id IS NULL AND cm.membership_scope='full') OR (e.trip_id IS NOT NULL AND tm.user_id IS NOT NULL))
       )
       SELECT (SELECT count(*) FROM eligible) AS votes,
         COALESCE((SELECT jsonb_agg(jsonb_build_object('id',sample.id,'displayName',sample.display_name)
           ORDER BY sample.display_name,sample.id) FROM
           (SELECT id,display_name FROM eligible ORDER BY display_name,id LIMIT 50) sample),'[]'::jsonb) AS voters
     ) totals WHERE o.poll_id=p.id AND o.deleted_at IS NULL),'[]'::jsonb),
   (SELECT v.option_id FROM public.event_poll_votes v JOIN public.event_poll_options o ON o.id=v.option_id AND o.poll_id=v.poll_id AND o.deleted_at IS NULL
     WHERE v.poll_id=p.id AND v.user_id=p_actor)
 FROM public.get_event_for_member(p_actor,p_event) e
 JOIN public.event_polls p ON p.event_id=e.id AND p.community_id=e.community_id AND p.deleted_at IS NULL
 WHERE p_cursor IS NULL OR p.id>p_cursor ORDER BY p.id LIMIT 51
$body$;
REVOKE ALL ON FUNCTION public.list_event_polls(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_event_polls(uuid,uuid,uuid) TO sobralis_runtime;
