-- Track who created each task and when it finished.
--
-- created_by: lost information today — a task in someone else's group
-- with no assignee gives no signal about who put it there, so the modal
-- can't surface "ask the creator". Backfill defaults the creator to the
-- assignee, since that's the closest proxy we have for pre-migration rows.
--
-- finished_at: today the inbox sorts the Done section by created_at,
-- which only approximates "most recently finished" (the row was
-- finished some time after it was created). Stamping a real finish
-- timestamp on the status flip into 'done' lets the Done section sort
-- newest-finished-first instead of newest-created-first. Cleared when
-- the task transitions back out of 'done', so undo restores accuracy.
-- Backfill leaves it NULL on existing rows; client falls back to
-- created_at when finished_at is missing.

ALTER TABLE tasks
    ADD COLUMN created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN finished_at TIMESTAMPTZ;

UPDATE tasks SET created_by = assignee_id WHERE created_by IS NULL;
