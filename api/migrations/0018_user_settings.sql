-- Per-user, account-scoped settings. Independent of any workspace.
--
-- Today the only field is `account_badge` (the personal/work mode chip
-- shown in the topbar), but the table is the right home for future
-- preferences too: theme, default-view, gcal connection metadata, etc.
-- Keyed on user_id so the row exists at most once per account; a
-- missing row means "no preferences set yet" and the client falls back
-- to defaults.

CREATE TABLE user_settings (
    user_id       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    account_badge TEXT CHECK (account_badge IN ('personal','work')),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
