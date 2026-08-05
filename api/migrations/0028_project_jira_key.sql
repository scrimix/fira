-- Jira project key: which Jira project (within the workspace's configured
-- Jira site, see 0026) this Fira project pushes issues to. Nullable — most
-- projects won't use Jira. Same authorization posture as
-- external_url_template (project lead or workspace owner).

ALTER TABLE projects ADD COLUMN jira_project_key TEXT;
