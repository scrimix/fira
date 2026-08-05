-- Per-user Jira API token credentials, scoped per workspace.
--
-- Unlike gcal_credentials, there's no OAuth grant here: Jira Cloud's REST
-- API takes plain Basic Auth (account email + a personal API token from
-- id.atlassian.com/manage-profile/security/api-tokens), so one static
-- secret is the whole credential — no refresh_token/access_token/expiry
-- dance to model.
--
-- Composite (user_id, workspace_id) key, not user_id alone: the Jira site
-- itself is a workspace setting (workspaces.jira_site_url, see the next
-- migration), and different workspaces can point at different Jira Cloud
-- instances — a user who belongs to two workspaces with two different
-- sites connects separately in each. Per-user (not a single shared token)
-- because Jira attributes a worklog's author to whichever credential made
-- the call, with no override — a shared token would misattribute every
-- teammate's logged time to one account.
--
-- One row per (user, workspace) connection; missing row = "not connected
-- in this workspace". Disconnect deletes the row (no revoke call to
-- Jira — tokens are revoked from the user's own Atlassian account
-- settings).

CREATE TABLE jira_credentials (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    api_token       TEXT NOT NULL,
    last_sync_error TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, workspace_id)
);
