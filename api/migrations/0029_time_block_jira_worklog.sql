-- Jira worklog tracking for time blocks. `jira_worklog_id` is set on first
-- push and reused on every subsequent push (create vs. update against
-- Jira's worklog API); `jira_sync_error` surfaces the last failure so the
-- UI can show "sync failed" instead of just going quiet, particularly for
-- the background resync path (see ops.rs's block.update hook) which has no
-- synchronous caller to report an error to directly.

ALTER TABLE time_blocks
    ADD COLUMN jira_worklog_id TEXT,
    ADD COLUMN jira_sync_error TEXT;
