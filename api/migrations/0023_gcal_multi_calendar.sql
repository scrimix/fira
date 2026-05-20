-- Multi-calendar sync. Previously every event was assumed to come
-- from the user's `primary` calendar; sync only hit that endpoint, so
-- events living on secondary calendars (work, shared, subscribed) were
-- silently missing. Now we sync every calendar in calendarList.list,
-- which means the unique-by-google_event_id constraint has to grow
-- to include calendar_id — Google guarantees ids are unique *within*
-- a calendar, not across them.
--
-- Existing rows were all sourced from `primary`, so the column gets a
-- default of `primary` for backfill.

ALTER TABLE gcal_events
    ADD COLUMN calendar_id TEXT NOT NULL DEFAULT 'primary';

DROP INDEX IF EXISTS uq_gcal_user_google_evt;

CREATE UNIQUE INDEX uq_gcal_user_cal_google_evt
    ON gcal_events(user_id, calendar_id, google_event_id)
    WHERE google_event_id IS NOT NULL;
