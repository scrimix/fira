-- Auth: Google OAuth identities + cookie-based sessions.
--
-- google_sub is Google's stable user id (the JWT `sub` claim). Email can
-- change; sub cannot, so it's the lookup key on login.

ALTER TABLE users
    ADD COLUMN google_sub TEXT,
    ADD COLUMN avatar_url TEXT;

CREATE UNIQUE INDEX idx_users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL;

-- Projects get an owner. Personal mode = single owner; the project_members
-- table stays around for future sharing.
ALTER TABLE projects
    ADD COLUMN owner_id UUID REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX idx_projects_owner ON projects(owner_id);

-- Sessions: opaque random token in an HTTP-only cookie maps to a row here.
-- Lookup is one indexed PK fetch per request — fine at our scale, and gives
-- us instant revocation on logout.
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
