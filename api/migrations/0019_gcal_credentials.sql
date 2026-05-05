-- Per-user Google Calendar OAuth credentials.
--
-- Separate from user_settings (which is preferences) because these are
-- server-managed credentials, not user-editable knobs. One row per
-- connected user; missing row = "not connected". Disconnect deletes the
-- row.
--
-- The refresh_token is the long-lived credential; access_token + expiry
-- get rotated by the sync routine. calendar_email is captured at
-- connect time so the UI can show "Connected as alice@gmail.com"
-- without a re-fetch. last_sync_at / last_sync_error surface the
-- background sync's health to the UI.

CREATE TABLE gcal_credentials (
    user_id            UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    refresh_token      TEXT NOT NULL,
    access_token       TEXT,
    access_expires_at  TIMESTAMPTZ,
    calendar_id        TEXT NOT NULL DEFAULT 'primary',
    calendar_email     TEXT,
    last_sync_at       TIMESTAMPTZ,
    last_sync_error    TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
