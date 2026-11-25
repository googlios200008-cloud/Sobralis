-- Only one-way token hashes are stored. Revocation and expiry are enforced server-side.
ALTER TABLE users ADD COLUMN email_verified_at timestamptz;
CREATE TABLE user_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  token_hash char(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > created_at)
);
CREATE INDEX user_sessions_user_idx ON user_sessions(user_id);
CREATE INDEX user_sessions_expiry_idx ON user_sessions(expires_at);

-- Store acceptance as separate, versioned events; do not log submitted content.
CREATE TABLE user_consents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  consent_type text NOT NULL CHECK (consent_type IN ('personal_data', 'terms')),
  document_version text NOT NULL CHECK (char_length(document_version) BETWEEN 1 AND 80),
  document_url text NOT NULL CHECK (char_length(document_url) BETWEEN 1 AND 500),
  accepted_at timestamptz NOT NULL DEFAULT now(),
  ip inet
);
CREATE INDEX user_consents_user_idx ON user_consents(user_id);

-- Column-level access only for the specific authenticated operations implemented now.
-- No UPDATE privilege on account_role, deleted_at, membership, or consent records.
GRANT SELECT (id, email, password_hash, display_name, account_role, deleted_at, email_verified_at) ON users TO sobralis_runtime;
GRANT INSERT (email, password_hash, display_name) ON users TO sobralis_runtime;
GRANT SELECT (id, user_id, token_hash, expires_at, revoked_at) ON user_sessions TO sobralis_runtime;
GRANT INSERT (user_id, token_hash, expires_at) ON user_sessions TO sobralis_runtime;
GRANT UPDATE (revoked_at) ON user_sessions TO sobralis_runtime;
GRANT INSERT (user_id, consent_type, document_version, document_url, ip) ON user_consents TO sobralis_runtime;
GRANT SELECT (id, community_id, title, timezone, deleted_at) ON trips TO sobralis_runtime;
GRANT UPDATE (title) ON trips TO sobralis_runtime;
GRANT SELECT (trip_id, community_id, user_id, role) ON trip_members TO sobralis_runtime;
GRANT SELECT (community_id, user_id) ON community_members TO sobralis_runtime;
GRANT SELECT (id, deleted_at) ON communities TO sobralis_runtime;
