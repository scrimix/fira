# Sprint 28 — Jira integration: connect, create issue, log time

**Status:** shipped
**Date:** 2026-08-05

## Goal

Full write-path Jira integration: connect a Jira account, create issues
from tasks, and push time blocks as worklogs. Scope decided up front and
held for the whole sprint: **write-only**. No pull sync, no status
mapping, no content sync (attachments/estimate/description), no
Jira→Fira issue browser — each of those is a reconciliation-shaped
problem that deserves its own design pass, not an add-on to this one.

## Decision: per-user token, per-workspace site

Landed here after two reversals, both worth keeping on record since they
shaped everything downstream:

1. **Single shared env token** (first idea, simplest possible thing) —
   rejected because Jira's worklog API sets `author` from whichever
   credential made the call, with no override. A shared token would
   attribute every teammate's logged time to one Jira account, defeating
   the entire point of time-logging by person.
2. **Per-user token, but account-wide** (`JIRA_SITE_URL` as a global env
   var, `jira_credentials` keyed by `user_id` alone) — shipped, then
   reworked the same day once it was clear the *site* itself needed to
   follow the workspace, not the account: Fira already treats workspace as
   the tenancy boundary for everything else (projects, roles, invites),
   and different workspaces can legitimately point at different Jira Cloud
   instances.

Final shape: `workspaces.jira_site_url` (owner-editable) is the shared
site for everyone in that workspace; `jira_credentials` is keyed by
`(user_id, workspace_id)` — each member connects their own email + API
token per workspace. A user in two workspaces with two different Jira
sites connects separately in each. Every outbound Jira call — connect
validation, issue create, worklog push — authenticates as the *relevant*
user's own token, never a shared one.

The two migrations this went through (create account-wide, then drop and
recreate workspace-scoped) were squashed into one `jira_credentials`
migration once the shape settled — it was a design bug caught within the
same session, not a schema change worth preserving step-by-step, and
nothing outside local dev had run the intermediate shape.

## Schema

```sql
-- 0025_jira_credentials.sql
CREATE TABLE jira_credentials (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    api_token       TEXT NOT NULL,
    last_sync_error TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, workspace_id)
);

-- 0026_workspace_jira_site.sql
ALTER TABLE workspaces ADD COLUMN jira_site_url TEXT;

-- 0028_project_jira_key.sql
ALTER TABLE projects ADD COLUMN jira_project_key TEXT;

-- 0029_time_block_jira_worklog.sql
ALTER TABLE time_blocks
    ADD COLUMN jira_worklog_id TEXT,
    ADD COLUMN jira_sync_error TEXT;
```

No `access_token`/`expires_at` pair anywhere — Jira API tokens are static
secrets with no refresh cycle, unlike gcal's OAuth grant.

## Connect / disconnect

No OAuth redirect — Basic Auth means "connecting" is a form submit:

- `POST /api/jira/connect` `{ email, api_token }` — resolves the caller's
  active workspace's `jira_site_url` (error if unset: "set one in
  workspace settings first"), validates the pasted credentials against
  `GET /rest/api/3/myself` *before* persisting (the only signal the token
  is real — there's no prior OAuth consent screen that could have already
  failed), then upserts into `jira_credentials`.
- `POST /api/jira/disconnect` — deletes the row for the caller's active
  workspace. No revoke call; tokens are managed from the user's own
  Atlassian account settings.

Status (`connected`, `email`, `last_sync_error`) is **not** on
`UserSettings` — it lives on `Bootstrap.jira` (a new `JiraStatus` struct),
because unlike gcal it varies with `X-Workspace-Id`. `UserSettings` is
documented as "independent of workspace"; Jira status genuinely isn't.

**UI:** `WorkspaceModal` gets an owner-only "Jira site" field (three-state
PATCH alongside the title, same convention as everywhere else nullable
fields get cleared vs. left alone). `AccountSettingsModal`'s Jira section
is workspace-aware — titled "Jira — {workspace}", showing a connect form
when the workspace has a site but the caller hasn't connected, or a hint
to "ask the workspace owner" when the workspace has no site at all.

## Reusing the manual issue-link fields for issue create

`projects.jira_project_key` maps a Fira project to a Jira one (set via a
`ProjectModal` field with a "Check" button that resolves the key against
`GET /rest/api/3/project/:key` before saving). `POST
/api/jira/tasks/:task_id`:

1. Loads the caller's credentials + the workspace's site (same
   `require_workspace_jira` helper the connect flow uses).
2. Confirms the task is in scope and reads its project's
   `jira_project_key`.
3. `POST /rest/api/3/issue` with `project.key`, `summary`, `issuetype:
   "Task"`, and — if an epic was picked — `parent: { key }` (Jira Cloud's
   unified-hierarchy epic link field; doesn't handle legacy
   company-managed projects that still use a custom field instead).
4. Writes the returned key + a `{site}/browse/{key}` URL straight into
   `tasks.external_id` / `tasks.external_url` — the same fields a user
   fills in by hand for any manual tracker link. `TaskModal`'s existing
   `ExternalLinkEditor` needed zero changes; it was already rendering
   whatever's in those two fields.
5. Propagates via **two synthesized ops** — `task.set_external_id` and
   `task.set_external_url` — reusing the client's existing handlers
   instead of inventing a new op kind.

**UI:** a "Create in Jira" button next to the Issue link field, shown only
when the project has a key and the task doesn't have a link yet. Opens
`JiraCreateIssueModal` — a real modal (backdrop + `.np-modal` +
head/body/actions, same shape as `ConfirmDelete`), not an inline
expansion in the sidebar field. That distinction came from direct
feedback partway through: a first pass expanded the epic picker in place
and it was rejected outright ("create a separate modal view, not this
inline shit"). Epics load lazily on modal mount via `GET
/api/jira/epics?project_key=` (JQL search, newest-first) — not preloaded,
since most tasks never get pushed.

## Worklog push — shared core, block-owner attribution

A time block has no Jira reference of its own; it logs against whatever
`tasks.external_id` holds. Push-eligible = `project.jira_project_key` set
**and** `task.external_id` set (a soft heuristic — nothing stops
`external_id` from holding an unrelated manually-pasted value on a project
that also has a Jira key; not validated).

`push_block_worklog(pool, workspace_id, block_id)` is shared by the manual
button and the automatic resync:

1. Loads the block's owner, start/end, existing `jira_worklog_id`, owner
   name.
2. Resolves the linked issue key via the heuristic above.
3. Loads the ***block owner's*** Jira credentials — not whoever triggered
   the call. This matters specifically when someone edits a teammate's
   time block: the worklog must still be attributed to the actual
   time-owner, using their token, not the editor's.
4. Builds the worklog body (`timeSpentSeconds` floored to Jira's 60s
   minimum, `started` via chrono's `%z` bare-offset format, a comment
   naming the real Fira user since Jira's `author` field is always the
   token owner).
5. `POST .../worklog` on first push, `PUT .../worklog/{id}` after.
6. **Regardless of outcome**, updates `time_blocks` (worklog id on
   success, error message on failure) and emits a synthesized
   `block.update` op carrying just `{ jira_worklog_id, jira_sync_error }`
   as the patch — a third reuse of an existing client-applied op kind
   (its generic `{ ...b, ...op.patch }` merge needed no new dispatch
   code).

First push is manual only (`BlockRow` gets a status button: muted
Ticket/green/red-with-error-in-title depending on never-pushed/synced/
failed). Once a worklog exists, further edits resync automatically:
`ops.rs`'s `apply_one` captures the block id from a `block.update` op
before it moves into `apply_payload`, and — only if the op committed and
the block was already linked — spawns the resync fire-and-forget, logging
a warning on failure. Same posture as gcal's background sync: never let
Jira's latency sit on the `/ops` response path.

## Bugs found and fixed during manual testing

- **410 Gone on epic search.** `GET /rest/api/3/search` is deprecated;
  Atlassian's replacement is `GET /rest/api/3/search/jql` — same params,
  same response shape. This fired on every open of the create-issue
  modal regardless of which epic (or none) got picked, since epics load
  on mount.
- **Button text overflow.** `.icon-btn` is a fixed 26×26 icon-only square;
  "Create in Jira" text inside it overflowed. Root cause was a wrong CSS
  class, but the real fix was structural: moved the whole epic picker into
  its own modal (see above) rather than patching the class in place.
- **Modal action row flush against the corner.** `.np-actions` carries no
  padding of its own — every other modal nests it *inside* `.np-body`
  (which has `20px 28px 24px` padding) as the last child. The new modal
  had it as a sibling. Only obvious by diffing DOM nesting against an
  existing modal, since both render "inside the modal" visually.

## Decisions worth remembering

- **Reuse over invention, three times over.** Task push reuses
  `task.set_external_id`/`set_external_url`; worklog push reuses
  `block.update`. Both are cases where a server-authored write lands in
  fields an existing client op already knows how to apply — no new
  dispatch code needed. Worth generalizing: before adding an op kind, check
  whether the target fields are already covered by one.
- **Attribute to the resource owner, not the actor.** Both issue-create
  (implicitly, via per-user tokens) and worklog push (explicitly, by
  looking up `time_blocks.user_id` rather than `ctx.user.id`) authenticate
  as whoever the data belongs to, not whoever clicked. This is the whole
  reason per-user/per-workspace tokens exist in the first place.
- **REST response merge, not outbox, for server-computed results.**
  `pushTaskToJira` / `pushBlockToJira` call a plain endpoint and merge the
  response directly (like `renameWorkspace`/`addProject`) — the outbox
  pattern is for optimistic local-then-sync writes, and there's nothing to
  optimistically guess about a Jira key or worklog id that doesn't exist
  until the round-trip completes.
- **Persist + propagate on both success and failure**, specifically for
  the worklog path — the background resync has no HTTP caller to report a
  failure to, so `jira_sync_error` has to be as durable and visible as
  `jira_worklog_id`.
- **Modal over inline for gather-then-confirm UI.** Single-click actions
  (worklog push button) are fine inline; anything that needs the user to
  review or choose something first (epic picker) gets a real modal.
- **`sqlx::FromRow` matches by column name — breaks at runtime, not
  compile time.** Adding a field to `Workspace`, `Project`, or `TimeBlock`
  meant hunting down every hand-written query that hydrates one; the
  compiler catches none of it.

## What we noticed but didn't fix

- **Legacy epic-link custom field.** Company-managed Jira Cloud projects
  that never migrated to the unified hierarchy use a custom field (often
  `customfield_10014`, varies per site) instead of `parent`. An epic pick
  on such a project silently creates the issue without the link.
- **Linked-issue heuristic is soft.** No validation that a task's
  `external_id` is actually a real Jira key on the configured site before
  a worklog push targets it.
- **No retry-all for failed worklog syncs**, unlike the local outbox sync
  pill's popover — a failed block just sits with a red icon until clicked
  again.
- **API tokens stored in plaintext**, matching `gcal_credentials`'
  existing convention (its OAuth tokens aren't encrypted either) — not a
  new gap, but worth revisiting for both integrations together if this
  ever leaves a single-tenant/trusted deployment.
- **Playground fixture** (`web/src/playground/bootstrap.json`) predates
  every Jira field and wasn't regenerated — harmless (loader casts through
  `unknown`, store has `??` fallbacks), just shows Jira as unconfigured in
  playground mode until `cargo run --bin dump-bootstrap` regenerates it.
- **Status mapping, content sync (attachments/estimate/description),
  pull-from-Jira** — out of scope by design, not oversight.
