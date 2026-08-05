-- Per-(user, workspace) opt-in: push a new time block's Jira worklog as
-- soon as it's created, instead of waiting for the manual "Log to Jira"
-- click. Lives on jira_credentials since it's a per-connection preference,
-- same scope as the credentials themselves. Defaults off — auto-creating
-- worklogs the user didn't explicitly ask for would be a surprising
-- default for a brand-new connection.
ALTER TABLE jira_credentials
    ADD COLUMN auto_sync_new_blocks BOOLEAN NOT NULL DEFAULT false;
