-- Jira site moves from a global JIRA_SITE_URL env var to a per-workspace
-- setting: different workspaces (different teams/companies) may run
-- different Jira Cloud instances, and Fira already models workspace as the
-- tenancy boundary everywhere else (projects, members, roles).
--
-- Nullable — most workspaces won't use Jira. Owner-editable, same
-- authorization posture as the workspace title (see workspaces::rename).

ALTER TABLE workspaces ADD COLUMN jira_site_url TEXT;
