-- Manage invitations without exposing or granting access to token hashes.
-- This adds an index and a read-only capability; existing invitations are untouched.
CREATE INDEX community_invites_community_id_id_idx ON public.community_invites(community_id,id);

CREATE FUNCTION public.list_community_invites_for_owner(p_actor uuid,p_community uuid,p_cursor uuid)
RETURNS TABLE(invite_id uuid,granted_role text,max_uses integer,uses_count integer,
              created_at timestamptz,expires_at timestamptz,disabled_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT i.id,i.granted_role,i.max_uses,i.uses_count,i.created_at,i.expires_at,i.disabled_at
 FROM public.community_invites i
 WHERE i.community_id=p_community AND (p_cursor IS NULL OR i.id>p_cursor)
   AND EXISTS (
     SELECT 1 FROM public.users u
     JOIN public.community_members cm ON cm.user_id=u.id
     JOIN public.communities c ON c.id=cm.community_id
     WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
       AND c.id=p_community AND c.deleted_at IS NULL AND cm.left_at IS NULL
       AND cm.membership_scope='full' AND cm.role='owner'
   )
 ORDER BY i.id LIMIT 51
$body$;
REVOKE ALL ON FUNCTION public.list_community_invites_for_owner(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_community_invites_for_owner(uuid,uuid,uuid) TO sobralis_runtime;
