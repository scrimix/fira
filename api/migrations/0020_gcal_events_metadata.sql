-- Extend the placeholder gcal_events table with the fields needed for
-- real Google Calendar sync.
--
-- google_event_id: stable id from Google's API, used as the upsert key
-- so re-running sync doesn't churn rows. Nullable + partial unique
-- index so legacy seeded rows (no google id) don't block the index.
--
-- description: long text, surfaced in a click-to-view popover on the
-- calendar. NULL means "not provided".
--
-- html_link: deep link back into Google Calendar so the popover can
-- offer "Open in Google Calendar" without us reconstructing URLs.
--
-- updated_at_remote: Google's last-modified timestamp; not used yet
-- but cheap to capture and useful for incremental sync later.

ALTER TABLE gcal_events
    ADD COLUMN description       TEXT,
    ADD COLUMN google_event_id   TEXT,
    ADD COLUMN html_link         TEXT,
    ADD COLUMN updated_at_remote TIMESTAMPTZ;

CREATE UNIQUE INDEX uq_gcal_user_google_evt
    ON gcal_events(user_id, google_event_id)
    WHERE google_event_id IS NOT NULL;
