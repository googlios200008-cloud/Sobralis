-- Existing historical messages are preserved; assign an internal sequence in
-- chronological order, before enabling the new API. Existing unpaired direct
-- conversations remain untouched and unavailable until explicitly migrated.
ALTER TABLE public.conversation_messages ADD COLUMN client_message_id uuid;
ALTER TABLE public.conversation_messages ADD COLUMN seq bigint;
CREATE SEQUENCE public.conversation_message_order_seq AS bigint;
WITH ordered AS MATERIALIZED (
 SELECT id FROM public.conversation_messages ORDER BY conversation_id,created_at,id
), assigned AS MATERIALIZED (
 SELECT id,nextval('public.conversation_message_order_seq') AS value FROM ordered
)
UPDATE public.conversation_messages m SET seq=a.value FROM assigned a WHERE a.id=m.id;
ALTER TABLE public.conversation_messages ALTER COLUMN seq SET NOT NULL;
ALTER TABLE public.conversation_messages ALTER COLUMN seq SET DEFAULT nextval('public.conversation_message_order_seq');
ALTER SEQUENCE public.conversation_message_order_seq OWNED BY public.conversation_messages.seq;
CREATE UNIQUE INDEX conversation_message_seq_unique ON public.conversation_messages(seq);
CREATE UNIQUE INDEX conversation_message_client_unique ON public.conversation_messages(conversation_id,author_id,client_message_id) WHERE client_message_id IS NOT NULL;
CREATE INDEX conversation_message_seq_timeline ON public.conversation_messages(conversation_id,seq) WHERE deleted_at IS NULL;

-- Only pairs explicitly created by the new API are available. Composite FKs
-- ensure the two listed users actually belong to the exact conversation.
CREATE TABLE public.direct_conversation_pairs (
 community_id uuid NOT NULL,
 user_low uuid NOT NULL,
 user_high uuid NOT NULL,
 conversation_id uuid NOT NULL,
 PRIMARY KEY(community_id,user_low,user_high),
 UNIQUE(conversation_id,community_id),
 CHECK(user_low<user_high),
 FOREIGN KEY(conversation_id,community_id,user_low) REFERENCES public.conversation_participants(conversation_id,community_id,user_id),
 FOREIGN KEY(conversation_id,community_id,user_high) REFERENCES public.conversation_participants(conversation_id,community_id,user_id)
);
CREATE INDEX direct_pair_low_idx ON public.direct_conversation_pairs(user_low,conversation_id);
CREATE INDEX direct_pair_high_idx ON public.direct_conversation_pairs(user_high,conversation_id);

CREATE FUNCTION public.create_direct_conversation(p_actor uuid,p_community uuid,p_peer uuid)
RETURNS TABLE(result text,conversation_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE actor_role text; low_id uuid;high_id uuid;existing uuid;new_id uuid;
BEGIN
 IF p_actor IS NULL OR p_peer IS NULL OR p_actor=p_peer THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 low_id=LEAST(p_actor,p_peer);high_id=GREATEST(p_actor,p_peer);
 PERFORM 1 FROM public.users u WHERE u.id IN(p_actor,p_peer) AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL ORDER BY u.id FOR SHARE;
 SELECT cm.role INTO actor_role FROM public.communities c JOIN public.community_members cm ON cm.community_id=c.id
 JOIN public.users u ON u.id=cm.user_id
 WHERE c.id=p_community AND cm.user_id=p_actor AND c.deleted_at IS NULL AND cm.left_at IS NULL AND cm.membership_scope='full'
   AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE OF c,cm,u;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN; END IF;
 IF actor_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid; RETURN; END IF;
 PERFORM 1 FROM public.community_members cm JOIN public.users u ON u.id=cm.user_id
 WHERE cm.community_id=p_community AND cm.user_id=p_peer AND cm.left_at IS NULL AND cm.membership_scope='full'
 AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE OF cm,u;
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN; END IF;
 -- The same unordered pair always locks the same key. Hash collisions only
 -- reduce concurrency; pair uniqueness is enforced independently by the PK.
 PERFORM pg_advisory_xact_lock(hashtextextended('direct:'||p_community::text||':'||low_id::text||':'||high_id::text,0));
 SELECT p.conversation_id INTO existing FROM public.direct_conversation_pairs p JOIN public.conversations c
   ON c.id=p.conversation_id AND c.community_id=p.community_id
 WHERE p.community_id=p_community AND p.user_low=low_id AND p.user_high=high_id AND c.kind='direct' AND c.deleted_at IS NULL;
 IF FOUND THEN
   -- Do not silently restore a participant who has left the conversation.
   IF NOT EXISTS(SELECT 1 FROM public.conversation_participants cp WHERE cp.conversation_id=existing AND cp.user_id=p_actor AND cp.left_at IS NULL)
      OR NOT EXISTS(SELECT 1 FROM public.conversation_participants cp WHERE cp.conversation_id=existing AND cp.user_id=p_peer AND cp.left_at IS NULL)
      OR EXISTS(SELECT 1 FROM public.conversation_participants cp WHERE cp.conversation_id=existing AND cp.user_id NOT IN(low_id,high_id)) THEN
     RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN;
   END IF;
   RETURN QUERY SELECT 'existing'::text,existing; RETURN;
 END IF;
 IF EXISTS(SELECT 1 FROM public.direct_conversation_pairs p WHERE p.community_id=p_community AND p.user_low=low_id AND p.user_high=high_id) THEN
   RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN;
 END IF;
 INSERT INTO public.conversations AS c(community_id,kind) VALUES(p_community,'direct') RETURNING c.id INTO new_id;
 INSERT INTO public.conversation_participants(conversation_id,community_id,user_id) VALUES(new_id,p_community,p_actor),(new_id,p_community,p_peer);
 INSERT INTO public.direct_conversation_pairs(community_id,user_low,user_high,conversation_id) VALUES(p_community,low_id,high_id,new_id);
 RETURN QUERY SELECT 'created'::text,new_id;
END
$body$;
REVOKE ALL ON FUNCTION public.create_direct_conversation(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_direct_conversation(uuid,uuid,uuid) TO sobralis_runtime;

-- The caller may read only their own active pair; peer availability does not
-- suppress the existing history but is required before sending new messages.
CREATE FUNCTION public.get_visible_direct_conversation(p_actor uuid,p_conversation uuid)
RETURNS TABLE(id uuid,community_id uuid,actor_role text,peer_id uuid,peer_display_name text,peer_available boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT c.id,c.community_id,cm.role,
   CASE WHEN peer.deleted_at IS NULL THEN peer.id ELSE NULL END,
   CASE WHEN peer.deleted_at IS NULL THEN peer.display_name ELSE 'Удалённый участник' END,
   (peer.deleted_at IS NULL AND peer.email_verified_at IS NOT NULL AND pcm.user_id IS NOT NULL AND pp.user_id IS NOT NULL)
 FROM public.direct_conversation_pairs pair
 JOIN public.conversations c ON c.id=pair.conversation_id AND c.community_id=pair.community_id AND c.kind='direct' AND c.deleted_at IS NULL
 JOIN public.communities comm ON comm.id=c.community_id AND comm.deleted_at IS NULL
 JOIN public.users actor ON actor.id=p_actor AND actor.deleted_at IS NULL AND actor.email_verified_at IS NOT NULL
 JOIN public.community_members cm ON cm.community_id=c.community_id AND cm.user_id=p_actor AND cm.left_at IS NULL AND cm.membership_scope='full'
 JOIN public.conversation_participants cp ON cp.conversation_id=c.id AND cp.community_id=c.community_id AND cp.user_id=p_actor AND cp.left_at IS NULL
 JOIN public.users peer ON peer.id=CASE WHEN pair.user_low=p_actor THEN pair.user_high ELSE pair.user_low END
 LEFT JOIN public.community_members pcm ON pcm.community_id=c.community_id AND pcm.user_id=peer.id AND pcm.left_at IS NULL AND pcm.membership_scope='full'
 LEFT JOIN public.conversation_participants pp ON pp.conversation_id=c.id AND pp.community_id=c.community_id AND pp.user_id=peer.id AND pp.left_at IS NULL
 WHERE c.id=p_conversation AND p_actor IN(pair.user_low,pair.user_high)
   AND NOT EXISTS(SELECT 1 FROM public.conversation_participants other WHERE other.conversation_id=c.id AND other.user_id NOT IN(pair.user_low,pair.user_high))
$body$;
REVOKE ALL ON FUNCTION public.get_visible_direct_conversation(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_visible_direct_conversation(uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.list_direct_conversations(p_actor uuid,p_cursor uuid)
RETURNS TABLE(id uuid,community_id uuid,actor_role text,peer_id uuid,peer_display_name text,peer_available boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT v.* FROM public.direct_conversation_pairs p
 CROSS JOIN LATERAL public.get_visible_direct_conversation(p_actor,p.conversation_id) v
 WHERE p_actor IN(p.user_low,p.user_high) AND (p_cursor IS NULL OR v.id>p_cursor)
 ORDER BY v.id LIMIT 51
$body$;
REVOKE ALL ON FUNCTION public.list_direct_conversations(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_direct_conversations(uuid,uuid) TO sobralis_runtime;

-- Internal mutation helper locks the authenticated participant and parent
-- conversation before making any write; not granted to runtime directly.
CREATE FUNCTION public.lock_direct_conversation(p_actor uuid,p_conversation uuid)
RETURNS TABLE(community_id uuid,actor_role text,peer_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
BEGIN
 PERFORM 1 FROM public.users WHERE id=p_actor AND deleted_at IS NULL AND email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN; END IF;
 RETURN QUERY SELECT c.community_id,cm.role,CASE WHEN pair.user_low=p_actor THEN pair.user_high ELSE pair.user_low END
 FROM public.direct_conversation_pairs pair
 JOIN public.conversations c ON c.id=pair.conversation_id AND c.community_id=pair.community_id
 JOIN public.communities comm ON comm.id=c.community_id
 JOIN public.community_members cm ON cm.community_id=c.community_id AND cm.user_id=p_actor
 JOIN public.conversation_participants cp ON cp.conversation_id=c.id AND cp.community_id=c.community_id AND cp.user_id=p_actor
 WHERE c.id=p_conversation AND p_actor IN(pair.user_low,pair.user_high) AND c.kind='direct' AND c.deleted_at IS NULL
   AND comm.deleted_at IS NULL AND cm.left_at IS NULL AND cm.membership_scope='full' AND cp.left_at IS NULL
   AND NOT EXISTS(SELECT 1 FROM public.conversation_participants other WHERE other.conversation_id=c.id AND other.user_id NOT IN(pair.user_low,pair.user_high))
 FOR UPDATE OF c FOR SHARE OF comm,cm,cp;
END
$body$;
REVOKE ALL ON FUNCTION public.lock_direct_conversation(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION public.send_direct_message(p_actor uuid,p_conversation uuid,p_client_id uuid,p_body text)
RETURNS TABLE(result text,message_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE a record;previous public.conversation_messages%ROWTYPE;new_id uuid;
BEGIN
 SELECT * INTO a FROM public.lock_direct_conversation(p_actor,p_conversation);
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN; END IF;
 IF a.actor_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid; RETURN; END IF;
 IF p_client_id IS NULL OR p_body IS NULL OR char_length(btrim(p_body)) NOT BETWEEN 1 AND 5000 THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 -- Safe retry succeeds even if the peer subsequently became unavailable.
 SELECT * INTO previous FROM public.conversation_messages m WHERE m.conversation_id=p_conversation AND m.author_id=p_actor AND m.client_message_id=p_client_id;
 IF FOUND THEN
   IF previous.deleted_at IS NOT NULL OR previous.body<>btrim(p_body) THEN RETURN QUERY SELECT 'conflict'::text,NULL::uuid; RETURN; END IF;
   RETURN QUERY SELECT 'existing'::text,previous.id; RETURN;
 END IF;
 PERFORM 1 FROM public.users peer
 JOIN public.community_members cm ON cm.community_id=a.community_id AND cm.user_id=peer.id
 JOIN public.conversation_participants cp ON cp.conversation_id=p_conversation AND cp.community_id=a.community_id AND cp.user_id=peer.id
 WHERE peer.id=a.peer_id AND peer.deleted_at IS NULL AND peer.email_verified_at IS NOT NULL
   AND cm.left_at IS NULL AND cm.membership_scope='full' AND cp.left_at IS NULL FOR SHARE OF peer,cm,cp;
 IF NOT FOUND THEN RETURN QUERY SELECT 'peer_unavailable'::text,NULL::uuid; RETURN; END IF;
 INSERT INTO public.conversation_messages AS m(conversation_id,community_id,author_id,client_message_id,body,created_at)
 VALUES(p_conversation,a.community_id,p_actor,p_client_id,btrim(p_body),clock_timestamp()) RETURNING m.id INTO new_id;
 RETURN QUERY SELECT 'created'::text,new_id;
END
$body$;
REVOKE ALL ON FUNCTION public.send_direct_message(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.send_direct_message(uuid,uuid,uuid,text) TO sobralis_runtime;

CREATE FUNCTION public.delete_direct_message(p_actor uuid,p_conversation uuid,p_message uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE a record;msg public.conversation_messages%ROWTYPE;
BEGIN
 SELECT * INTO a FROM public.lock_direct_conversation(p_actor,p_conversation);
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT * INTO msg FROM public.conversation_messages m WHERE m.id=p_message AND m.conversation_id=p_conversation FOR UPDATE;
 IF NOT FOUND OR msg.deleted_at IS NOT NULL THEN RETURN 'not_found'; END IF;
 IF msg.author_id<>p_actor THEN RETURN 'forbidden'; END IF;
 UPDATE public.conversation_messages SET deleted_at=clock_timestamp() WHERE id=p_message;
 RETURN 'deleted';
END
$body$;
REVOKE ALL ON FUNCTION public.delete_direct_message(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.delete_direct_message(uuid,uuid,uuid) TO sobralis_runtime;

CREATE FUNCTION public.list_direct_messages(p_actor uuid,p_conversation uuid,p_after uuid)
RETURNS TABLE(result text,messages jsonb,next_cursor uuid,has_more boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE after_seq bigint;data jsonb;last_id uuid;more boolean;
BEGIN
 PERFORM 1 FROM public.get_visible_direct_conversation(p_actor,p_conversation);
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::jsonb,NULL::uuid,false; RETURN; END IF;
 IF p_after IS NOT NULL THEN
   SELECT m.seq INTO after_seq FROM public.conversation_messages m WHERE m.id=p_after AND m.conversation_id=p_conversation;
   IF NOT FOUND THEN RETURN QUERY SELECT 'invalid_cursor'::text,NULL::jsonb,NULL::uuid,false; RETURN; END IF;
 END IF;
 WITH batch AS MATERIALIZED (
   SELECT m.id,m.seq,m.body,m.created_at,u.id AS user_id,u.display_name,u.deleted_at AS user_deleted_at
   FROM public.conversation_messages m JOIN public.users u ON u.id=m.author_id
   WHERE m.conversation_id=p_conversation AND m.deleted_at IS NULL AND (after_seq IS NULL OR m.seq>after_seq)
   ORDER BY m.seq LIMIT 51
 ), page AS MATERIALIZED (SELECT * FROM batch ORDER BY seq LIMIT 50)
 SELECT COALESCE((SELECT jsonb_agg(jsonb_build_object('id',b.id,'body',CASE WHEN b.user_deleted_at IS NULL THEN b.body ELSE '' END,
   'createdAt',b.created_at,'author',CASE WHEN b.user_deleted_at IS NULL THEN jsonb_build_object('id',b.user_id,'displayName',b.display_name)
   ELSE jsonb_build_object('id',NULL,'displayName','Удалённый участник') END) ORDER BY b.seq) FROM page b),'[]'::jsonb),
   COALESCE((SELECT b.id FROM page b ORDER BY b.seq DESC LIMIT 1),p_after),(SELECT count(*)>50 FROM batch)
 INTO data,last_id,more;
 RETURN QUERY SELECT 'ok'::text,data,last_id,more;
END
$body$;
REVOKE ALL ON FUNCTION public.list_direct_messages(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_direct_messages(uuid,uuid,uuid) TO sobralis_runtime;
