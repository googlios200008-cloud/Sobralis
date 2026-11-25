-- A retry key identifies one creation attempt by one account. Keep no access
-- grants here; replay must recheck the user's current community membership.
CREATE TABLE public.community_creation_requests (
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  request_id uuid NOT NULL,
  requested_name text NOT NULL,
  community_id uuid REFERENCES public.communities(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, request_id)
);
REVOKE ALL ON public.community_creation_requests FROM PUBLIC, sobralis_runtime;

CREATE FUNCTION public.create_community_once(p_owner uuid,p_request uuid,p_name text)
RETURNS TABLE (status text,id uuid,name text,role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
DECLARE req public.community_creation_requests%ROWTYPE; created uuid;
BEGIN
 IF p_owner IS NULL OR p_request IS NULL OR p_name IS NULL OR length(p_name)<1 OR length(p_name)>120 OR p_name<>btrim(p_name) THEN
  RETURN QUERY SELECT 'invalid'::text,NULL::uuid,NULL::text,NULL::text; RETURN;
 END IF;
 PERFORM 1 FROM public.users u WHERE u.id=p_owner AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'unavailable'::text,NULL::uuid,NULL::text,NULL::text; RETURN; END IF;
 -- The unique constraint makes simultaneous retries wait for the first
 -- transaction; a rollback also rolls back its reservation and community.
 INSERT INTO public.community_creation_requests(user_id,request_id,requested_name)
 VALUES(p_owner,p_request,p_name) ON CONFLICT(user_id,request_id) DO NOTHING;
 SELECT r.* INTO req FROM public.community_creation_requests r
 WHERE r.user_id=p_owner AND r.request_id=p_request FOR UPDATE;
 IF req.requested_name IS DISTINCT FROM p_name THEN
  RETURN QUERY SELECT 'conflict'::text,NULL::uuid,NULL::text,NULL::text; RETURN;
 END IF;
 IF req.community_id IS NULL THEN
  SELECT c.id INTO created FROM public.create_community_for_owner(p_name,p_owner) c;
  UPDATE public.community_creation_requests r SET community_id=created WHERE r.user_id=p_owner AND r.request_id=p_request;
  req.community_id:=created;
 END IF;
 RETURN QUERY SELECT 'ok'::text,c.id,c.name,cm.role::text FROM public.communities c
 JOIN public.community_members cm ON cm.community_id=c.id AND cm.user_id=p_owner
 WHERE c.id=req.community_id AND c.deleted_at IS NULL AND cm.left_at IS NULL AND cm.membership_scope='full';
 IF NOT FOUND THEN RETURN QUERY SELECT 'unavailable'::text,NULL::uuid,NULL::text,NULL::text; END IF;
END $f$;
REVOKE ALL ON FUNCTION public.create_community_once(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_community_once(uuid,uuid,text) TO sobralis_runtime;
