-- Scoped event discussion; direct runtime access is deliberately not granted.
CREATE TABLE public.event_comments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 event_id uuid NOT NULL,community_id uuid NOT NULL,author_id uuid NOT NULL,client_message_id uuid NOT NULL,
 seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 body text NOT NULL CHECK(char_length(body) BETWEEN 1 AND 5000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),deleted_at timestamptz,
 UNIQUE(event_id,author_id,client_message_id),
 FOREIGN KEY(event_id,community_id) REFERENCES public.events(id,community_id),
 FOREIGN KEY(community_id,author_id) REFERENCES public.community_members(community_id,user_id)
);
CREATE INDEX event_comments_timeline_idx ON public.event_comments(event_id,seq) WHERE deleted_at IS NULL;
CREATE FUNCTION public.create_event_comment(p_actor uuid,p_event uuid,p_client_id uuid,p_body text)
RETURNS TABLE(result text,comment_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record;prev public.event_comments%ROWTYPE;new_id uuid;
BEGIN
 SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::uuid; RETURN; END IF;
 IF access_row.member_role NOT IN ('owner','editor') THEN RETURN QUERY SELECT 'forbidden'::text,NULL::uuid; RETURN; END IF;
 IF p_client_id IS NULL OR p_body IS NULL OR char_length(btrim(p_body)) NOT BETWEEN 1 AND 5000 THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 SELECT * INTO prev FROM public.event_comments c WHERE c.event_id=p_event AND c.author_id=p_actor AND c.client_message_id=p_client_id;
 IF FOUND THEN
   IF prev.deleted_at IS NOT NULL OR prev.body<>btrim(p_body) THEN RETURN QUERY SELECT 'conflict'::text,NULL::uuid; RETURN; END IF;
   RETURN QUERY SELECT 'existing'::text,prev.id; RETURN;
 END IF;
 INSERT INTO public.event_comments AS c(event_id,community_id,author_id,client_message_id,body)
 VALUES(p_event,access_row.community_id,p_actor,p_client_id,btrim(p_body)) RETURNING c.id INTO new_id;
 RETURN QUERY SELECT 'created'::text,new_id;
END
$body$;
REVOKE ALL ON FUNCTION public.create_event_comment(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_event_comment(uuid,uuid,uuid,text) TO sobralis_runtime;

-- A member may delete their own comment even after role downgrade to viewer.
CREATE FUNCTION public.delete_event_comment(p_actor uuid,p_event uuid,p_comment uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE access_row record;comment_row public.event_comments%ROWTYPE;
BEGIN
 SELECT * INTO access_row FROM public.lock_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 SELECT * INTO comment_row FROM public.event_comments c WHERE c.event_id=p_event AND c.id=p_comment FOR UPDATE;
 IF NOT FOUND OR comment_row.deleted_at IS NOT NULL THEN RETURN 'not_found'; END IF;
 IF comment_row.author_id<>p_actor THEN RETURN 'forbidden'; END IF;
 UPDATE public.event_comments SET deleted_at=clock_timestamp() WHERE id=p_comment;
 RETURN 'deleted';
END
$body$;
REVOKE ALL ON FUNCTION public.delete_event_comment(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.delete_event_comment(uuid,uuid,uuid) TO sobralis_runtime;

-- Cursor UUID references a message in this event, including soft-deleted ones.
CREATE FUNCTION public.list_event_comments(p_actor uuid,p_event uuid,p_after uuid)
RETURNS TABLE(result text,comments jsonb,next_cursor uuid,has_more boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE after_seq bigint;output_comments jsonb;last_id uuid;more boolean;
BEGIN
 PERFORM 1 FROM public.get_event_for_member(p_actor,p_event);
 IF NOT FOUND THEN RETURN QUERY SELECT 'not_found'::text,NULL::jsonb,NULL::uuid,false; RETURN; END IF;
 IF p_after IS NOT NULL THEN
   SELECT c.seq INTO after_seq FROM public.event_comments c WHERE c.id=p_after AND c.event_id=p_event;
   IF NOT FOUND THEN RETURN QUERY SELECT 'invalid_cursor'::text,NULL::jsonb,NULL::uuid,false; RETURN; END IF;
 END IF;
 WITH batch AS MATERIALIZED (
   SELECT c.id,c.seq,c.body,c.created_at,u.id AS user_id,u.display_name,u.deleted_at AS user_deleted_at
   FROM public.event_comments c JOIN public.users u ON u.id=c.author_id
   WHERE c.event_id=p_event AND c.deleted_at IS NULL AND (after_seq IS NULL OR c.seq>after_seq)
   ORDER BY c.seq LIMIT 51
 ), page AS MATERIALIZED (SELECT * FROM batch ORDER BY seq LIMIT 50)
 SELECT COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'id',b.id,'body',CASE WHEN b.user_deleted_at IS NULL THEN b.body ELSE '' END,
    'createdAt',b.created_at,
    'author',CASE WHEN b.user_deleted_at IS NULL THEN jsonb_build_object('id',b.user_id,'displayName',b.display_name)
                  ELSE jsonb_build_object('id',NULL,'displayName','Удалённый участник') END
   ) ORDER BY b.seq) FROM page b),'[]'::jsonb),
   COALESCE((SELECT b.id FROM page b ORDER BY b.seq DESC LIMIT 1),p_after),
   (SELECT count(*)>50 FROM batch)
 INTO output_comments,last_id,more;
 RETURN QUERY SELECT 'ok'::text,output_comments,last_id,more;
END
$body$;
REVOKE ALL ON FUNCTION public.list_event_comments(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_event_comments(uuid,uuid,uuid) TO sobralis_runtime;
