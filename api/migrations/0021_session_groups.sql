-- Account switcher: group every session created on the same physical
-- browser under one `session_group_id`, surfaced as a non-HttpOnly `sg`
-- cookie. The login picker reads the group, lists every active session
-- in it, and lets the user swap which one is active without a Google
-- round-trip.
--
-- Pre-existing sessions get NULL — they stay individually valid until
-- they expire or the user logs out, but they're invisible to the
-- picker. The next login on a given browser mints a fresh group and
-- enrolls subsequent logins into it.
--
-- The partial index keeps the picker lookup cheap without paying for
-- the long tail of legacy NULL rows.
ALTER TABLE sessions
    ADD COLUMN session_group_id TEXT;

CREATE INDEX idx_sessions_group ON sessions(session_group_id)
    WHERE session_group_id IS NOT NULL;
