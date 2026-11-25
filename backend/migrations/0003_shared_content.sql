-- Preserve historical references while making departure an immediate access revocation.
ALTER TABLE community_members ADD COLUMN left_at timestamptz;
ALTER TABLE trip_members ADD COLUMN left_at timestamptz;
GRANT SELECT (left_at) ON community_members TO sobralis_runtime;
GRANT SELECT (left_at) ON trip_members TO sobralis_runtime;

-- A workday is a calendar DATE, not an instant shifted to UTC.
CREATE TABLE schedule_entries (
  community_id uuid NOT NULL,
  user_id uuid NOT NULL,
  local_date date NOT NULL,
  status text NOT NULL CHECK (status IN ('free','work','busy','unknown')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (community_id, user_id, local_date),
  FOREIGN KEY (community_id, user_id) REFERENCES community_members(community_id, user_id)
);
CREATE INDEX schedule_entries_date_idx ON schedule_entries (community_id, local_date);

-- An event may be community-wide or restricted to an associated trip.
-- Access to these tables is deliberately not granted to the runtime role yet.
CREATE TABLE events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id uuid NOT NULL REFERENCES communities(id),
  trip_id uuid,
  organizer_id uuid NOT NULL,
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 5000),
  location text NOT NULL DEFAULT '' CHECK (char_length(location) <= 500),
  starts_at timestamptz NOT NULL,
  timezone text NOT NULL CHECK (char_length(timezone) BETWEEN 1 AND 100),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE (id, community_id),
  FOREIGN KEY (trip_id, community_id) REFERENCES trips(id, community_id),
  FOREIGN KEY (community_id, organizer_id) REFERENCES community_members(community_id, user_id)
);
CREATE INDEX events_community_start_idx ON events (community_id, starts_at) WHERE deleted_at IS NULL;

CREATE TABLE event_polls (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL,
  community_id uuid NOT NULL,
  question text NOT NULL CHECK (char_length(question) BETWEEN 1 AND 500),
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE (id, community_id),
  FOREIGN KEY (event_id, community_id) REFERENCES events(id, community_id)
);
CREATE TABLE event_poll_options (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  poll_id uuid NOT NULL REFERENCES event_polls(id),
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 500),
  position integer NOT NULL CHECK (position >= 0),
  deleted_at timestamptz,
  UNIQUE (id, poll_id),
  UNIQUE (poll_id, position)
);
CREATE TABLE event_poll_votes (
  poll_id uuid NOT NULL,
  community_id uuid NOT NULL,
  user_id uuid NOT NULL,
  option_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (poll_id, user_id),
  FOREIGN KEY (poll_id, community_id) REFERENCES event_polls(id, community_id),
  FOREIGN KEY (option_id, poll_id) REFERENCES event_poll_options(id, poll_id),
  FOREIGN KEY (community_id, user_id) REFERENCES community_members(community_id, user_id)
);

-- These tables have no runtime privileges or endpoints until private/group
-- participant checks, retention and legal basis are implemented and tested.
CREATE TABLE conversations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id uuid NOT NULL REFERENCES communities(id),
  kind text NOT NULL CHECK (kind IN ('group','direct')),
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE (id, community_id)
);
CREATE TABLE conversation_participants (
  conversation_id uuid NOT NULL,
  community_id uuid NOT NULL,
  user_id uuid NOT NULL,
  joined_at timestamptz NOT NULL DEFAULT now(),
  left_at timestamptz,
  PRIMARY KEY (conversation_id, user_id),
  UNIQUE (conversation_id, community_id, user_id),
  FOREIGN KEY (conversation_id, community_id) REFERENCES conversations(id, community_id),
  FOREIGN KEY (community_id, user_id) REFERENCES community_members(community_id, user_id)
);
CREATE TABLE conversation_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id uuid NOT NULL,
  community_id uuid NOT NULL,
  author_id uuid NOT NULL,
  body text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  FOREIGN KEY (conversation_id, community_id, author_id)
    REFERENCES conversation_participants(conversation_id, community_id, user_id)
);
CREATE INDEX conversation_messages_timeline_idx ON conversation_messages (conversation_id, created_at) WHERE deleted_at IS NULL;

-- Only endpoints already implemented below receive DB permissions.
GRANT SELECT (name) ON communities TO sobralis_runtime;
GRANT SELECT (role) ON community_members TO sobralis_runtime;

-- Narrow privileged operation: create a NEW community and its initial owner as
-- one statement. Runtime has no general INSERT/UPDATE/DELETE membership rights.
-- The caller still derives p_owner from the authenticated server session.
CREATE FUNCTION public.create_community_for_owner(p_name text, p_owner uuid)
RETURNS TABLE (id uuid, name text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $body$
DECLARE new_id uuid;
BEGIN
  INSERT INTO public.communities AS c(name, created_by)
  VALUES (p_name, p_owner) RETURNING c.id INTO new_id;
  INSERT INTO public.community_members(community_id, user_id, role)
  VALUES (new_id, p_owner, 'owner');
  RETURN QUERY SELECT c.id, c.name FROM public.communities c WHERE c.id = new_id;
END
$body$;
REVOKE ALL ON FUNCTION public.create_community_for_owner(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_community_for_owner(text, uuid) TO sobralis_runtime;
GRANT SELECT (community_id, user_id, local_date, status, updated_at) ON schedule_entries TO sobralis_runtime;
GRANT INSERT (community_id, user_id, local_date, status) ON schedule_entries TO sobralis_runtime;
GRANT UPDATE (status, updated_at) ON schedule_entries TO sobralis_runtime;
