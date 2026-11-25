-- A trip invite must not silently grant access to community-wide calendars.
-- Existing memberships stay full; new or reactivated invitees are trip-only.
ALTER TABLE community_members ADD COLUMN membership_scope text NOT NULL DEFAULT 'full'
  CHECK (membership_scope IN ('full','trip_only'));
GRANT SELECT (membership_scope) ON community_members TO sobralis_runtime;

-- Tokens are 256-bit random values; only their hashes are stored.
CREATE TABLE trip_invites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  trip_id uuid NOT NULL,
  community_id uuid NOT NULL,
  token_hash char(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  created_by uuid NOT NULL,
  granted_role text NOT NULL CHECK (granted_role IN ('viewer','editor')),
  max_uses integer NOT NULL CHECK (max_uses BETWEEN 1 AND 50),
  uses_count integer NOT NULL DEFAULT 0 CHECK (uses_count >= 0 AND uses_count <= max_uses),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  disabled_at timestamptz,
  CHECK (expires_at > created_at),
  UNIQUE (id, trip_id, community_id),
  FOREIGN KEY (trip_id, community_id) REFERENCES trips(id, community_id),
  FOREIGN KEY (community_id, created_by) REFERENCES community_members(community_id, user_id)
);
CREATE INDEX trip_invites_trip_idx ON trip_invites(trip_id);
CREATE TABLE trip_invite_redemptions (
  invite_id uuid NOT NULL,
  trip_id uuid NOT NULL,
  community_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id),
  redeemed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(invite_id,user_id),
  FOREIGN KEY (invite_id, trip_id, community_id) REFERENCES trip_invites(id, trip_id, community_id)
);

-- Invite creators must be current trip owners and active community members.
-- Lock owner/membership rows so a concurrent role revocation cannot race issuance.
CREATE FUNCTION public.create_trip_invite(p_user uuid,p_trip uuid,p_hash text,p_role text,p_hours int,p_max int)
RETURNS TABLE(invite_id uuid,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE v_community uuid;
BEGIN
  IF p_hash !~ '^[a-f0-9]{64}$' OR p_role NOT IN ('viewer','editor') OR p_hours NOT BETWEEN 1 AND 720 OR p_max NOT BETWEEN 1 AND 50 THEN RETURN; END IF;
  SELECT t.community_id INTO v_community FROM public.trips t
    JOIN public.communities c ON c.id=t.community_id
    JOIN public.trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id
    JOIN public.community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
    JOIN public.users u ON u.id=tm.user_id
    WHERE t.id=p_trip AND tm.user_id=p_user AND tm.role='owner' AND tm.left_at IS NULL
      AND cm.left_at IS NULL AND t.deleted_at IS NULL AND c.deleted_at IS NULL AND u.deleted_at IS NULL
    FOR SHARE OF t,c,tm,cm,u;
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY INSERT INTO public.trip_invites AS i(trip_id,community_id,token_hash,created_by,granted_role,max_uses,expires_at)
    VALUES(p_trip,v_community,p_hash,p_user,p_role,p_max,now()+(p_hours*interval '1 hour')) RETURNING i.id,i.expires_at;
END
$body$;
REVOKE ALL ON FUNCTION public.create_trip_invite(uuid,uuid,text,text,int,int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_trip_invite(uuid,uuid,text,text,int,int) TO sobralis_runtime;

-- Only a minimal preview is returned; invalid, expired, exhausted or revoked
-- invitations all produce no rows. Creator must remain an active trip owner.
CREATE FUNCTION public.preview_trip_invite(p_hash text)
RETURNS TABLE(trip_title text,community_name text,granted_role text,expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
 SELECT t.title,c.name,i.granted_role,i.expires_at FROM public.trip_invites i
 JOIN public.trips t ON t.id=i.trip_id AND t.community_id=i.community_id
 JOIN public.communities c ON c.id=i.community_id
 JOIN public.trip_members tm ON tm.trip_id=i.trip_id AND tm.community_id=i.community_id AND tm.user_id=i.created_by
 JOIN public.community_members cm ON cm.community_id=i.community_id AND cm.user_id=i.created_by
 JOIN public.users u ON u.id=i.created_by
 WHERE i.token_hash=p_hash AND i.disabled_at IS NULL AND i.expires_at>now() AND i.uses_count<i.max_uses
   AND t.deleted_at IS NULL AND c.deleted_at IS NULL AND tm.role='owner' AND tm.left_at IS NULL AND cm.left_at IS NULL AND u.deleted_at IS NULL
$body$;
REVOKE ALL ON FUNCTION public.preview_trip_invite(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.preview_trip_invite(text) TO sobralis_runtime;

CREATE FUNCTION public.redeem_trip_invite(p_user uuid,p_hash text)
RETURNS TABLE(result text,trip_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE inv public.trip_invites%ROWTYPE;
BEGIN
  -- Match lock ordering used for other grants: user, then invitation.
  PERFORM 1 FROM public.users WHERE id=p_user AND deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
  SELECT * INTO inv FROM public.trip_invites i WHERE i.token_hash=p_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
  -- An already-redeemed token is idempotent only while membership remains active.
  IF EXISTS(SELECT 1 FROM public.trip_invite_redemptions r
            JOIN public.trip_members tm ON tm.trip_id=r.trip_id AND tm.user_id=r.user_id AND tm.left_at IS NULL
            JOIN public.community_members cm ON cm.community_id=r.community_id AND cm.user_id=r.user_id AND cm.left_at IS NULL
            JOIN public.trips t ON t.id=r.trip_id AND t.deleted_at IS NULL
            JOIN public.communities c ON c.id=r.community_id AND c.deleted_at IS NULL
            WHERE r.invite_id=inv.id AND r.user_id=p_user) THEN
    RETURN QUERY SELECT 'already_member'::text,inv.trip_id; RETURN;
  END IF;
  IF inv.disabled_at IS NOT NULL OR inv.expires_at<=now() OR inv.uses_count>=inv.max_uses OR
     EXISTS(SELECT 1 FROM public.trip_invite_redemptions r WHERE r.invite_id=inv.id AND r.user_id=p_user) THEN
    RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN;
  END IF;
  -- Lock all records affecting issuer authority and deletion state until commit.
  PERFORM 1 FROM public.trips t JOIN public.communities c ON c.id=t.community_id
    JOIN public.trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=inv.created_by
    JOIN public.community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
    JOIN public.users issuer ON issuer.id=tm.user_id
    WHERE t.id=inv.trip_id AND t.community_id=inv.community_id AND t.deleted_at IS NULL AND c.deleted_at IS NULL
      AND tm.role='owner' AND tm.left_at IS NULL AND cm.left_at IS NULL AND issuer.deleted_at IS NULL
    FOR SHARE OF t,c,tm,cm,issuer;
  IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text,NULL::uuid; RETURN; END IF;
  -- An existing active member is not downgraded and consumes no use.
  IF EXISTS(SELECT 1 FROM public.trip_members tm JOIN public.community_members cm
       ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
       WHERE tm.trip_id=inv.trip_id AND tm.user_id=p_user AND tm.left_at IS NULL AND cm.left_at IS NULL) THEN
    RETURN QUERY SELECT 'already_member'::text,inv.trip_id; RETURN;
  END IF;
  INSERT INTO public.community_members AS cm(community_id,user_id,role,membership_scope)
    VALUES(inv.community_id,p_user,inv.granted_role,'trip_only')
    ON CONFLICT ON CONSTRAINT community_members_pkey
    DO UPDATE SET left_at=NULL,role=EXCLUDED.role,membership_scope='trip_only' WHERE cm.left_at IS NOT NULL;
  INSERT INTO public.trip_members AS tm(trip_id,community_id,user_id,role)
    VALUES(inv.trip_id,inv.community_id,p_user,inv.granted_role)
    -- Community membership may have ended while a historical trip row stayed active.
    -- Reactivation must always apply the invite role, not revive an older higher role.
    ON CONFLICT ON CONSTRAINT trip_members_pkey DO UPDATE SET left_at=NULL,role=EXCLUDED.role;
  INSERT INTO public.trip_invite_redemptions(invite_id,trip_id,community_id,user_id) VALUES(inv.id,inv.trip_id,inv.community_id,p_user);
  UPDATE public.trip_invites SET uses_count=uses_count+1 WHERE id=inv.id;
  RETURN QUERY SELECT 'joined'::text,inv.trip_id;
END
$body$;
REVOKE ALL ON FUNCTION public.redeem_trip_invite(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_trip_invite(uuid,text) TO sobralis_runtime;

CREATE FUNCTION public.disable_trip_invite(p_user uuid,p_trip uuid,p_invite uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
BEGIN
  PERFORM 1 FROM public.trips t JOIN public.communities c ON c.id=t.community_id
    JOIN public.trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=p_user
    JOIN public.community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id
    JOIN public.users u ON u.id=p_user
    WHERE t.id=p_trip AND t.deleted_at IS NULL AND c.deleted_at IS NULL AND tm.role='owner'
      AND tm.left_at IS NULL AND cm.left_at IS NULL AND u.deleted_at IS NULL FOR SHARE OF t,c,tm,cm,u;
  IF NOT FOUND THEN RETURN false; END IF;
  UPDATE public.trip_invites SET disabled_at=now() WHERE id=p_invite AND trip_id=p_trip AND disabled_at IS NULL;
  RETURN FOUND;
END
$body$;
REVOKE ALL ON FUNCTION public.disable_trip_invite(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.disable_trip_invite(uuid,uuid,uuid) TO sobralis_runtime;
