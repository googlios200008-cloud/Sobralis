-- Full-community invitations are separate from trip-only invitations.
CREATE TABLE public.community_invites (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),community_id uuid NOT NULL REFERENCES public.communities(id),
 token_hash char(64) NOT NULL UNIQUE CHECK(token_hash ~ '^[a-f0-9]{64}$'),created_by uuid NOT NULL,
 granted_role text NOT NULL CHECK(granted_role IN ('editor','viewer')),max_uses integer NOT NULL CHECK(max_uses BETWEEN 1 AND 50),
 uses_count integer NOT NULL DEFAULT 0 CHECK(uses_count BETWEEN 0 AND max_uses),
 created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL,disabled_at timestamptz,
 CHECK(expires_at>created_at),FOREIGN KEY(community_id,created_by) REFERENCES public.community_members(community_id,user_id)
);
CREATE TABLE public.community_invite_redemptions (
 invite_id uuid NOT NULL REFERENCES public.community_invites(id),user_id uuid NOT NULL REFERENCES public.users(id),
 redeemed_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(invite_id,user_id)
);
CREATE FUNCTION public.create_community_invite(p_actor uuid,p_community uuid,p_hash text,p_role text,p_hours integer,p_max integer)
RETURNS TABLE(invite_id uuid,expires_at timestamptz) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
BEGIN
 IF p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' OR p_role IS NULL OR p_role NOT IN('viewer','editor') OR p_hours IS NULL OR p_hours NOT BETWEEN 1 AND 720 OR p_max IS NULL OR p_max NOT BETWEEN 1 AND 50 THEN RETURN; END IF;
 PERFORM 1 FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id JOIN public.communities c ON c.id=cm.community_id
 WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND c.id=p_community AND c.deleted_at IS NULL
 AND cm.left_at IS NULL AND cm.membership_scope='full' AND cm.role='owner' FOR SHARE OF u,cm,c;
 IF NOT FOUND THEN RETURN; END IF;
 RETURN QUERY INSERT INTO public.community_invites AS i(community_id,token_hash,created_by,granted_role,max_uses,expires_at)
 VALUES(p_community,p_hash,p_actor,p_role,p_max,now()+p_hours*interval '1 hour') RETURNING i.id,i.expires_at;
END
$body$;
REVOKE ALL ON FUNCTION public.create_community_invite(uuid,uuid,text,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_community_invite(uuid,uuid,text,text,integer,integer) TO sobralis_runtime;

CREATE FUNCTION public.preview_community_invite(p_hash text)
RETURNS TABLE(community_name text,granted_role text,expires_at timestamptz) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT c.name,i.granted_role,i.expires_at FROM public.community_invites i JOIN public.communities c ON c.id=i.community_id
 JOIN public.community_members cm ON cm.community_id=i.community_id AND cm.user_id=i.created_by
 JOIN public.users u ON u.id=i.created_by
 WHERE i.token_hash=p_hash AND i.disabled_at IS NULL AND i.expires_at>now() AND i.uses_count<i.max_uses
 AND c.deleted_at IS NULL AND cm.left_at IS NULL AND cm.membership_scope='full' AND cm.role='owner'
 AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
$body$;
REVOKE ALL ON FUNCTION public.preview_community_invite(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.preview_community_invite(text) TO sobralis_runtime;

CREATE FUNCTION public.redeem_community_invite(p_actor uuid,p_hash text)
RETURNS TABLE(result text,community_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE inv public.community_invites%ROWTYPE;member public.community_members%ROWTYPE;
BEGIN
 PERFORM 1 FROM public.users WHERE id=p_actor AND deleted_at IS NULL AND email_verified_at IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 SELECT * INTO inv FROM public.community_invites WHERE token_hash=p_hash FOR UPDATE;
 IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 -- An idempotent replay is valid only if full membership is still active.
 IF EXISTS(SELECT 1 FROM public.community_invite_redemptions r JOIN public.community_members cm ON cm.community_id=inv.community_id AND cm.user_id=r.user_id
 JOIN public.communities c ON c.id=cm.community_id AND c.deleted_at IS NULL
 WHERE r.invite_id=inv.id AND r.user_id=p_actor AND cm.left_at IS NULL AND cm.membership_scope='full') THEN
 RETURN QUERY SELECT 'already_member'::text,inv.community_id; RETURN; END IF;
 IF inv.disabled_at IS NOT NULL OR inv.expires_at<=clock_timestamp() OR inv.uses_count>=inv.max_uses OR
 EXISTS(SELECT 1 FROM public.community_invite_redemptions WHERE invite_id=inv.id AND user_id=p_actor) THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 PERFORM 1 FROM public.communities c JOIN public.community_members cm ON cm.community_id=c.id AND cm.user_id=inv.created_by
 JOIN public.users u ON u.id=cm.user_id WHERE c.id=inv.community_id AND c.deleted_at IS NULL AND cm.left_at IS NULL
 AND cm.membership_scope='full' AND cm.role='owner' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE OF c,cm,u;
 IF NOT FOUND OR inv.expires_at<=clock_timestamp() THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
 SELECT cm.* INTO member FROM public.community_members cm WHERE cm.community_id=inv.community_id AND cm.user_id=p_actor FOR UPDATE;
 IF FOUND AND member.left_at IS NULL AND member.membership_scope='full' THEN RETURN QUERY SELECT 'already_member'::text,inv.community_id; RETURN; END IF;
 IF FOUND AND member.left_at IS NOT NULL THEN
   -- Rejoining a community must not revive previously active trip roles.
   UPDATE public.trip_members tm SET left_at=now() WHERE tm.community_id=inv.community_id AND tm.user_id=p_actor AND tm.left_at IS NULL;
 END IF;
 INSERT INTO public.community_members AS cm(community_id,user_id,role,membership_scope) VALUES(inv.community_id,p_actor,inv.granted_role,'full')
 ON CONFLICT ON CONSTRAINT community_members_pkey DO UPDATE SET left_at=NULL,role=EXCLUDED.role,membership_scope='full';
 INSERT INTO public.community_invite_redemptions(invite_id,user_id) VALUES(inv.id,p_actor);
 UPDATE public.community_invites SET uses_count=uses_count+1 WHERE id=inv.id;
 RETURN QUERY SELECT 'joined'::text,inv.community_id;
END
$body$;
REVOKE ALL ON FUNCTION public.redeem_community_invite(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_community_invite(uuid,text) TO sobralis_runtime;

CREATE FUNCTION public.disable_community_invite(p_actor uuid,p_community uuid,p_invite uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
BEGIN
 -- Same lock order as redemption: invitation before creator's membership.
 PERFORM 1 FROM public.community_invites i WHERE i.id=p_invite AND i.community_id=p_community FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.users u JOIN public.community_members cm ON cm.user_id=u.id JOIN public.communities c ON c.id=cm.community_id
 WHERE u.id=p_actor AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND c.id=p_community AND c.deleted_at IS NULL
 AND cm.left_at IS NULL AND cm.membership_scope='full' AND cm.role='owner' FOR SHARE OF u,cm,c;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE public.community_invites SET disabled_at=now() WHERE id=p_invite AND community_id=p_community AND disabled_at IS NULL;
 RETURN FOUND;
END
$body$;
REVOKE ALL ON FUNCTION public.disable_community_invite(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.disable_community_invite(uuid,uuid,uuid) TO sobralis_runtime;
