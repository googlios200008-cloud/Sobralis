-- Foundational schema only. No existing browser data is imported automatically.
-- Day-based schedules and birthdays will use DATE, not artificial UTC timestamps.
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  password_hash text,
  display_name text NOT NULL,
  account_role text NOT NULL DEFAULT 'user' CHECK (account_role IN ('user', 'admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT users_email_length CHECK (char_length(email) BETWEEN 3 AND 320),
  CONSTRAINT users_name_length CHECK (char_length(display_name) BETWEEN 1 AND 120)
);
CREATE UNIQUE INDEX users_active_email_unique ON users (lower(email)) WHERE deleted_at IS NULL;

CREATE TABLE communities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE TABLE community_members (
  community_id uuid NOT NULL REFERENCES communities(id),
  user_id uuid NOT NULL REFERENCES users(id),
  role text NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (community_id, user_id)
);
CREATE INDEX community_members_user_idx ON community_members(user_id);

CREATE TABLE trips (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id uuid NOT NULL REFERENCES communities(id),
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
  timezone text NOT NULL DEFAULT 'Europe/Moscow' CHECK (char_length(timezone) BETWEEN 1 AND 100),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE (id, community_id)
);
CREATE INDEX trips_community_idx ON trips (community_id) WHERE deleted_at IS NULL;

CREATE TABLE trip_members (
  trip_id uuid NOT NULL,
  community_id uuid NOT NULL,
  user_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (trip_id, user_id),
  FOREIGN KEY (trip_id, community_id) REFERENCES trips(id, community_id),
  FOREIGN KEY (community_id, user_id) REFERENCES community_members(community_id, user_id)
);
CREATE INDEX trip_members_user_idx ON trip_members(user_id);
-- Intentionally no GRANT to the application runtime role: authenticated routes
-- and explicit per-table privileges are introduced together in a later stage.
