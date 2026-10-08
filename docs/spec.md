# Fira — working spec

> Authoritative spec for what's actually being built. The original
> [brief_description.md](brief_description.md) and [fira_design_doc.md](fira_design_doc.md)
> are the *long-form vision*; this document is the *current contract* between
> what the code does and what it's supposed to do. When the two diverge, this
> file wins — update it as decisions change.

---

## 1. The product, in one paragraph

Fira is a task tool where the unit of planning is the **time block** —
a discrete scheduled work session attached to a real task on a real day.
A task accrues N blocks across the week; the plan is the set of blocks
on the calendar; reality is the set of blocks marked complete. Capture
happens in a sectioned document (Now / Later / Someday / Done), not a board.
Prioritization is manual ordering. The product is two screens — List
and Calendar — over a single shared task model, scoped by **workspace**
(the company-level tenant) and project.

The user we optimize for is a senior IC split across 3–5 projects, who
needs to see their *own* week colored by project. Standup-friendly
behavior comes free from the same data: scrub the list by date, see
who finished what.

The app is live at <https://usefira.app>.

## 2. Architecture

```
┌──────────────┐  GET /api/bootstrap (initial hydrate)  ┌──────────────┐    sqlx    ┌──────────┐
│  web (Vite)  │ ─────────────────────────────────────▶ │  api (Axum)  │ ─────────▶ │ postgres │
│  React + TS  │  POST /api/ops      (push outbox)      │  Rust 1.x    │            │   16     │
│  Zustand     │  GET  /api/changes  (fallback poll)    │              │            │          │
│              │  WS   /api/ws       (real-time nudges) │              │            │          │
│              │  WS   /api/ws/user  (membership events)│              │            │          │
└──────────────┘ ◀───────────────────────────────────── └──────────────┘            └──────────┘
```

**Local-first, closed round-trip.** The web app hydrates once from
`/api/bootstrap` (which also returns the current change-log cursor),
then every mutation updates the in-memory store synchronously *and*
appends an intent-shaped op to an outbox.

- **Push**: a 2 s tick (plus opportunistic ticks on `focus`/`online`)
  flushes the outbox via `POST /api/ops`, batches of up to 50. The
  server applies each in its own transaction, idempotent on `op_id`
  via the `processed_ops` PK. Cross-tenant writes are rejected per-op
  via `project_scope` / workspace scope.
- **Pull on nudge** (sprint 10): when a write commits, the server
  issues `pg_notify('ops_changes', '<workspace>:<seq>')` from inside
  the same transaction. A per-process `PgListener` task forwards every
  notification into an in-process `Hub`
  (`Mutex<HashMap<workspace_id, broadcast::Sender<seq>>>`) that
  fans out to local WS subscribers. The client's `/api/ws` socket
  triggers `syncOutbox().then(pollChanges)` on every nudge — the WS
  is a *signal*, not a delivery channel.
- **Pull as fallback**: a 60 s `/api/changes?since=cursor` poll covers
  missed nudges (reconnect window, `PgListener` crash window).
- **Per-user channel** (sprint 13): `/api/ws/user` and
  `pg_notify('user_changes')` carry membership / role / workspace
  events that decide *who* can subscribe to the workspace ops feed.
  Without this, the very op that adds a user to a workspace has
  nowhere to be delivered (the receiver isn't subscribed yet).
  Workspace and link mutations fan out user nudges after commit.

The TopBar pill (`Synced` / `N pending` / `Syncing…` / `Offline · N` /
`Error · N`) makes the sync state visible. Click to force a tick or
open the failed-ops popover.

**Why not TanStack Query**: this isn't CRUD with occasional optimistic
updates — every drag, tick, retype is a mutation. A request-per-keystroke
model is the wrong shape. The Linear/Replicache pattern of "local store as
source of truth, outbox as audit log, op log as change feed" composes;
per-mutation `useMutation` hooks don't.

## 3. Data model — current

Authoritative SQL: [api/migrations/](../api/migrations/) (0001–0015,
applied in order on boot via `sqlx::migrate!`).

| table              | purpose                                            |
|--------------------|----------------------------------------------------|
| `users`            | identity. `google_sub` is the unique lookup key; seeded fixtures use `dev-{slug}`. |
| `sessions`         | opaque 32-byte tokens, 30-day TTL, server-stored. The `sid` cookie names a row. |
| `workspaces`       | id, title, `is_personal`, `created_by`. Every user has one personal workspace, auto-created on Google OAuth callback and in the seeder. |
| `workspace_members`| M:N user↔workspace, `role text check (role in ('owner','member'))`, `removed_at` for soft-delete. |
| `projects`         | id, title, icon, color, source (`local`/`jira`/`notion`), `owner_id`, `external_url_template`, `workspace_id NOT NULL`. |
| `project_members`  | M:N user↔project, `workspace_id` mirrored from parent project by trigger, `role text check (role in ('owner','lead','member','inactive'))`, `removed_at` for soft-delete. Composite FK `(workspace_id, user_id) → workspace_members(workspace_id, user_id)` makes it structurally impossible to add a user to a project who isn't in the workspace. |
| `tracks`           | a plan-board row — a workstream. `(id, project_id, title, color, sort_key, created_at)`. Renamed from `epics` in migration 0034; the word "epic" is spoken for by Jira's. |
| `sprints`          | a plan-board card: a titled span of weeks on one track. `track_id` (nullable — "No track"), `starts_on`/`ends_on` as week-aligned Monday `DATE`s with `ends_on` **exclusive**, `sort_key`. Three CHECKs enforce the geometry. `dates TEXT` is legacy and unwritten; `active` is unread by the board (the "now" marker makes it redundant). |
| `tasks`            | section (`now`/`later`/`recurring`/`someday`/`done`), status, estimate, assignee, sort_key, optional `external_id`, optional per-task `external_url`. |
| `tags`             | per-project, identity-bearing label: `(id, project_id, title, color)`. Case-insensitive unique on `(project_id, lower(title))`. Renaming is a `set_title` op against the row, no rewrite of attached tasks. |
| `task_tags`        | M:N task ↔ tag, PK `(task_id, tag_id)`, FK cascades on tag delete. |
| `subtasks`         | flat under a task. The "checkbox tree in a description" doesn't exist yet — subtasks are first-class rows. |
| `time_blocks`      | start_at, end_at, state (`planned`/`completed`/`skipped`), `user_id` (whose calendar the block lives on, independent of `task.assignee_id`). |
| `processed_ops`    | accepted-op log: `op_id` PK (idempotency) + `seq BIGSERIAL` (the global change-feed cursor) + `payload JSONB` (verbatim wire op) + `project_id` (nullable, for project-scope filtering) + `workspace_id` (nullable, for workspace-scope filtering). FKs to projects/workspaces were dropped in migration 0010 so log rows survive entity deletion. |
| `user_links`       | account-pair table; `(user_a, user_b)` canonicalized so `a < b`, `requested_by` distinguishes initiator, `status in ('pending','accepted')`. Two partial unique indexes (one per side, scoped to `status='accepted'`) cap each user to one accepted link. |
| `workspace_invites`| email-based pending invites for joining a workspace. `(workspace_id, email, role, status, invited_by, created_at, resolved_at)`. `email` is canonicalized lower+trim. `status in ('pending','accepted','declined','cancelled')`. Partial unique index `(workspace_id, email) WHERE status = 'pending'` makes invite-create idempotent — re-sending returns the existing pending row. |
| `gcal_events`      | placeholder table — no GCal sync yet, no UI rendering. |

**Two role axes** (sprints 08, 12, 15) gate authorization:

- **Workspace role** (`workspace_members.role`): `owner` | `member`.
  Workspace owners manage the workspace title, members, and roles, and
  can create / edit / delete any project in the workspace. Members
  see only projects they're explicitly added to.
- **Project role** (`project_members.role`):
  `owner` | `lead` | `member` | `inactive`. Workspace owners get
  `owner` on every project (auto-backfilled by migration 0012). `owner`
  and `inactive` are *passive* — hidden from list assignee groups
  unless they have a Now task assigned to them. `lead` can edit the
  project but not delete it; only the workspace owner can promote to
  `lead` or change project roles. `member` is the default.

**Personal workspace invariant.** Every user has exactly one workspace
where `is_personal = true` and they are the sole owner. Created on
signup and on the dev fixture. Cannot be deleted, cannot have other
members added.

**Workspace membership comes via invites only.** A workspace owner
can't add members directly anymore (sprint 19 removed the global
user-search picker — it was an onboarding wall for any user not yet
in the system). The only paths into a workspace's `workspace_members`
table are: the workspace's own creator at create time, and the
`accept_workspace_invite_tx` insert that runs when a recipient
accepts a pending invite. Removal is a single-user soft-delete
through the `DELETE /api/workspaces/:id/members/:user_id` endpoint
which also cascades the soft-delete into `project_members` rows for
that user in this workspace's projects (the FK has `ON DELETE
CASCADE` but `workspace_members` is soft-deleted, so the cascade
doesn't fire on its own). Tasks and time blocks owned by ex-members
stay as historical record.

**Things in the design doc that are NOT in the schema yet:**
- `task_type` (`regular`/`recurring`/`instance`) + `recurring_parent_id`
  — there's no template/instance machinery. The `recurring` section
  exists (migration 0022) for ongoing commitments whose unit of work is
  the time block, but tasks in it are still plain rows; no auto-spawn
  of per-cycle instances.
- `sync_state`, `source_updated_at`, `last_synced_at`, `raw_payload`,
  `external_workspace`, `section_history` — no Jira/Notion write-back
  yet. Manual issue links exist via `task.external_id` +
  `project.external_url_template`, but not automated sync.
- `integration_tokens` for Jira/Notion API access — none.
- `snapshots` — no snapshot table; plan history replays `processed_ops`.

## 4. API — current

All routes live under `/api` except `/health`. Most require a session
cookie (`sid`); scoped routes additionally require an `X-Workspace-Id`
header pointing at a workspace the caller is a member of (validated
per request — invalid header → 403). WS handlers can't set custom
headers, so the workspace ID rides on the query string for
`/api/ws?workspace_id=…`. Reads and writes are scoped by workspace
membership and, where applicable, project membership.

| route                                  | method | what                                                  |
|----------------------------------------|--------|-------------------------------------------------------|
| `/health`                              | GET    | liveness                                              |
| `/api/auth/config`                     | GET    | `{ dev_auth }` — gates the dev-login button on the SPA |
| `/api/auth/google/login`               | GET    | start Google OAuth (state cookie + consent redirect)  |
| `/api/auth/google/callback`            | GET    | OAuth callback, upserts user, creates personal workspace, sets `sid` |
| `/api/auth/logout`                     | POST   | drop session row + cookie                             |
| `/api/auth/dev-login?email=…`          | GET    | dev bypass (`dev_auth` cargo feature)                 |
| `/api/auth/dev-seed`                   | POST   | wipe + reseed fixture, sign in as Maya (`dev_auth`)   |
| `/api/me`                              | GET    | the authenticated user (or 401)                       |
| `/api/bootstrap`                       | GET    | one-shot hydrate for the active workspace, scoped     |
| `/api/workspaces`                      | GET    | the caller's workspaces (incl. personal)              |
| `/api/workspaces`                      | POST   | create a non-personal workspace; caller becomes owner |
| `/api/workspaces/:id`                  | PATCH  | rename (workspace owner only)                         |
| `/api/workspaces/:id`                  | DELETE | delete (owner only; personal workspaces rejected)     |
| `/api/workspaces/:id/members`          | PUT    | replace member set + roles (owner only) — kept for completeness, no longer used by the web UI |
| `/api/workspaces/:id/members/:user_id` | PATCH  | change a single member's role (owner only)            |
| `/api/workspaces/:id/members/:user_id` | DELETE | remove one member from the workspace + cascade project memberships (owner only; can't remove self) |
| `/api/workspaces/:id/users`            | GET    | directory listing scoped to one workspace             |
| `/api/workspaces/:id/all-users`        | GET    | every user in the system (owner only) — for adding a Google user not yet in any workspace |
| `/api/projects`                        | POST   | create a project (workspace owner only)               |
| `/api/projects/:id`                    | PATCH  | update title / icon / color / `external_url_template` (workspace owner OR project lead) |
| `/api/projects/:id`                    | DELETE | delete (workspace owner only)                         |
| `/api/projects/:id/members`            | PUT    | replace project member set + per-row role             |
| `/api/tasks/:id/move`                  | POST   | move a task to another project in the same workspace; 409 unless `acknowledge_access_loss` covers everyone stranded |
| `/api/links`                           | GET    | list every link involving me                          |
| `/api/links`                           | POST   | `{ email }` → create pending link                     |
| `/api/links/:id`                       | DELETE | cancel sent / decline received / unlink               |
| `/api/links/:id/accept`                | POST   | accept (only the non-requester)                       |
| `/api/invites`                         | GET    | list pending workspace invites involving me (sent + received) |
| `/api/invites`                         | POST   | `{ workspace_id, email, role? }` → create pending invite (workspace owner only; idempotent per (workspace, email) while pending) |
| `/api/invites/:id`                     | DELETE | cancel a pending invite (sender or workspace owner)   |
| `/api/invites/:id/accept`              | POST   | accept — recipient-only, matched on canonical email   |
| `/api/invites/:id/decline`             | POST   | decline — recipient-only                              |
| `/api/linked/calendar`                 | GET    | partner's blocks + `LinkedTask` projection (read-only overlay) |
| `/api/personal/calendar`               | GET    | personal-workspace blocks + `LinkedTask` projection — empty when active workspace is already personal |
| `/api/plan/at?project_id=…&t=…&seq=…`         | GET    | authorized historical plan entities, genesis and exact revisions |
| `/api/ops`                             | POST   | push outbox ops, idempotent per `op_id`, per-op tx    |
| `/api/changes?since=N`                 | GET    | pull change feed, scope-filtered, ≤ 500 rows          |
| `/api/ws?workspace_id=…`               | WS     | nudge socket for the workspace's change feed; 30 s server ping |
| `/api/ws/user`                         | WS     | per-user channel for membership / role / workspace events |

**What `/api/bootstrap` returns** (for the active workspace; arrays
non-null):

```ts
{
  me, users, projects, tracks, sprints, tasks, tags, blocks,
  workspace, links, workspace_invites, cursor
}
```

`workspace_invites` is the caller's pending invites (both `sent` and
`received` directions); resolved invites — accepted / declined /
cancelled — are terminal and don't surface.

`cursor` is the current `MAX(seq)` from `processed_ops`. Fresh clients
start polling `/api/changes` from there, not from 0. The shape
otherwise mirrors `web/src/types.ts`; no pagination, no filtering —
the dataset is small enough to send in one shot.

**Op kinds accepted by `/api/ops`** (~40):
`task.create`, `task.tick`, `task.set_section`, `task.set_title`,
`task.set_description`, `task.set_estimate`, `task.set_assignee`,
`task.set_status`, `task.set_external_id`, `task.set_external_url`,
`task.set_tags`, `task.set_sprint`, `task.reorder`, `task.delete`,
`subtask.create`, `subtask.tick`, `subtask.set_title`,
`subtask.delete`, `subtask.reorder`, `block.create`, `block.update`,
`block.delete`, `tag.create`, `tag.set_title`, `tag.set_color`,
`tag.delete`, `track.create`, `track.set_title`, `track.set_color`,
`track.reorder`, `track.delete`, `sprint.create`, `sprint.set_title`,
`sprint.set_dates`, `sprint.set_track`, `sprint.delete`, plus the
three private `goal.*` kinds.

The plan-board family (sprint 31) is all **narrow per-field setters**,
following `task.set_assignee`: `track_id` on a sprint is meaningfully
nullable ("No track" is reachable, not an error), so `block.update`'s
`patch: Partial<T>` shape would need `Option<Option<Uuid>>` to tell
absent from null, and `goal.update`'s whole-entity shape would mean
reconstructing an entity from a drag. `sprint.set_dates` carries both
columns because a span is one value — move and resize both emit it,
and the two are never independently null. `track.reorder` authorizes
through its WHERE clause (`AND project_id = $3`) exactly as
`task.reorder` does, so ids inside `ordered` are never trusted.

Because `processed_ops` is never pruned and must stay replayable,
`TaskInput.track_id` carries `#[serde(alias = "epic_id")]`: every
`task.create` written before migration 0034 still says `epic_id` on
the wire, and dropping the alias would null the track link of every
task the version scrubber replays from before that point.

`task.create.tag_ids` is a `Vec<Uuid>` of tag ids to attach atomically;
the tag rows must already exist (the outbox pushes `tag.create` first
when the user creates a tag inline from the picker). `task.set_tags`
replaces the whole tag set in one op — set-shaped is the right
LWW-friendly intent shape, per-add / per-remove diverges under
concurrent edits.

**Moving a task between projects** (`POST /api/tasks/:id/move`) is REST
rather than an op for two reasons: it needs a confirm gate the user sees
*before* the write, and it spans two project scopes, which an op
envelope's single `project_id` can't carry. It clears `track_id` /
`sprint_id`, deletes the task's `task_tags` (tags are identity-bearing
rows scoped to a project, so they don't travel), re-keys `sort_key` to
the tail of the target's same section, and materializes the resolved
issue URL into `external_url` when the two projects' templates differ.

It writes **two** `task.move_project` rows to the change log in one
transaction — one scoped to the source project, one to the target —
because the move has two audiences with opposite needs and
`processed_ops.project_id` is a single column: source members must drop
the task, target members must gain it. Both rows carry the same payload
(the post-move task *and* its time blocks, since blocks are reached
through `task → project` and a target-only member has never seen them);
the client branches on whether it can see `to_project_id`, so a client in
both projects applies the same idempotent upsert twice.

Visibility loss here is recoverable and worth stating as such: blocks are
never deleted, and adding someone to the target project restores them on
the next hydrate. The irreversible part is the tags / track / sprint.

Workspace, project, and link mutations write synthesized
`workspace.create` / `workspace.update` / `workspace.set_members` /
`workspace.set_member_role` / `workspace.delete` / `project.create` /
`project.update` / `project.set_members` / `project.delete` rows onto
the same log so peer clients converge through one apply path. Account
linking events ride the per-user channel only — there is no
workspace-scoped `link.*` op (the partners might not share a
workspace). Workspace invites do the same: `workspace_invite.*`
events fire only on the per-user channel (the recipient may not be
in *any* shared workspace yet), but the *acceptance side-effect* —
inserting / un-soft-deleting `workspace_members` — surfaces as a
`workspace.set_members` op on the workspace's change feed so existing
members see the new colleague appear without a manual reload.

### Workspace invites

Sender (workspace owner) types an email and clicks Send invite. The
server canonicalizes the email (lower + trim), checks it isn't
already an active member of that workspace (`removed_at IS NULL`
filter — re-inviting a previously-removed user is a happy path), and
creates a `workspace_invites` row with `status = 'pending'`. The
partial unique index `(workspace_id, email) WHERE status = 'pending'`
makes the call idempotent: a second create with the same email
returns the existing row instead of inserting a duplicate.

The recipient is matched by *email*, not user_id — invites for
not-yet-registered emails sit in pending until someone signs in
under that email and `/api/bootstrap` surfaces it. Once visible to
the recipient, a sticky modal pops (the only dismissals are Accept /
Decline; same UX pattern as account-link's received-pending state).
Accept inserts into `workspace_members` with
`ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role,
removed_at = NULL` so re-accepting after a prior removal cleanly
un-soft-deletes the row instead of leaving it as a tombstone.

Notification fan-out on each state change goes through the per-user
WS channel (`Hub::notify_user`) and reaches:

- **Create:** inviter (their pending list updates) and any user
  whose registered email matches the invitee.
- **Cancel:** inviter and recipient (recipient's modal disappears
  in real time).
- **Accept:** inviter, the accepting user, *and* every existing
  member of the workspace — so workspace member lists everywhere
  reflect the new colleague immediately.
- **Decline:** inviter and the declining user.

The accept handler also records a `workspace.set_members` op on the
workspace's change feed (in the same transaction as the invite
status flip), so the workspace WS path is a deterministic backstop
for the user-channel reload.

## 5. Time anchoring

The fixture is reproducible, not live. **Mon Apr 27 2026 00:00 PT** is
hardcoded as the visible week's start; **Wed Apr 29 2026** is "today".
The seeder writes timestamps in UTC (PDT = UTC-7) and the web client
converts back via [web/src/time.ts](../web/src/time.ts). The
playground (sprint 11) uses the same frozen anchor via `setFrozenNow`
so wallclock-independent block state stays stable across sessions.

When real users land on a fresh workspace, the calendar computes the
visible week from `Date.now()` in the user's TZ.

## 6. Outbox / sync seam

Every store mutation in [web/src/store/index.ts](../web/src/store/index.ts)
appends an `Op` to `state.outbox`. Op shape is **intent**, not diff:
`{ kind: 'task.tick', task_id, done: true }` rather than
`subtasks[2].done = true`. This matches Linear/Replicache and survives
concurrent edits better than diff replay. The full op-kind list is
in §4. Both push and pull use the same shapes; `applyRemoteOp` runs
ops returned by `/api/changes` through the same handlers as local
mutations.

**Push.** `syncOutbox()` runs every 2 s (and on `focus`/`online`):

- Bails if a sync is in flight (re-entrant safe).
- Bails if any op is in `error` state — server-rejected ops block the
  queue (preserve intent ordering, since later ops typically depend
  on earlier ones). User-driven Retry / Discard from the SyncPill
  popover unblocks.
- Picks up to 50 queued ops, marks them `syncing`, POSTs to
  `/api/ops`.
- On per-op `ok`: drops the op from the outbox; the op's `op_id` was
  already added to `appliedOpIds` at enqueue time so the echo via
  `/api/changes` is suppressed.
- On per-op `error`: flips the op to `error` (kept for visibility),
  records the server's actual error message in `syncStatus`, and
  fires a toast.
- On network failure: reverts the batch to `queued`, flips
  `syncStatus` to `offline`, retries on the next tick.
- After a previously-erroring queue fully drains, calls `hydrate()` to
  re-fetch from `/api/bootstrap` so any phantom local mutation
  (caused by Discard) gets reconciled to ground truth.

**Pull.** `pollChanges()` runs after every push (2 s) AND on every WS
nudge AND on the 60 s fallback timer:

- Hits `/api/changes?since=cursor`.
- For each returned op: skip if `op_id ∈ appliedOpIds` (it's our own
  echo); otherwise dispatch through `applyRemoteOp`.
- Advances `cursor` to the response's high-water mark.
- GCs `appliedOpIds` entries older than 5 min.

**Server invariants.** `processed_ops` is the single source of truth
for both idempotency (PK on `op_id`) and the change feed (monotonic
`seq BIGSERIAL`). Per-op transactions: a stale `task_id` in op #3
doesn't poison ops #1, #2, #4. The wire payload is stored verbatim
as `JSONB` so peer clients replay it through the same handlers
without a re-encode. `pg_notify` fires from the same transaction as
the insert, so a rolled-back op never nudges anyone.

**Conflict policy today is last-write-wins on intent.** With
set-shaped ops (`set_title`, `set_section`) that's almost always
right — the user who typed later expressed the more recent intent.
Divergence display for genuinely concurrent typing is future work.

**Reload-while-offline.** The store persists to `localStorage` via
`zustand/middleware/persist` with a custom replacer for the
`Map`-typed `appliedOpIds`. `hydrate()` distinguishes three cases on
`/api/me` failure:

1. **401** → session expired; clear cached state, show login.
2. **Network / 5xx with cached `meId`** → boot from cache, set
   `syncStatus: { kind: 'offline' }`. The 2 s ticker keeps trying;
   recovery is automatic.
3. **Network failure with no cache** → error page (still need network
   for the first-ever load).

`logout()` removes the persisted snapshot so the next user's reload
doesn't see leftovers.

## 7. UI — what's implemented

**Login** ([web/src/components/Login.tsx](../web/src/components/Login.tsx)):
- Rendered when `/api/me` returns 401. Editorial layout: `BrandMark`
  gradient-F glyph + Instrument Serif "Fira" wordmark + tagline +
  "Continue with Google" button.
- When `/api/auth/config` reports `dev_auth: true`, two
  dashed-bordered buttons render below: "Sign in as Maya"
  (`/api/auth/dev-login?email=maya@fira.dev`) and "Try as Maya in
  your browser" (enters playground mode — see §7.5).

**TopBar.** Workspace switcher in the breadcrumb chain
(`Fira / <Workspace> ⌄ / <Project> / <Title>`) opens a popover with
the caller's workspaces + `+ New workspace`. Trailing trio: sync pill
→ paired identity chip (or standalone avatar) → Log out. On phones
the breadcrumb collapses to a hamburger and the trio prunes to sync
pill + Log out (avatar shown, link button hidden).

**Sidebar** (web/src/components/Sidebar.tsx). 56 px icon-rail width on
desktop. Order: brand → Calendar / List toggle → project icons →
`+ New project` (workspace owner only) → spacer → settings cog
(workspace owner only). On phones the sidebar is a slide-over behind
the topbar hamburger.

**Calendar view** ([web/src/components/CalendarView.tsx](../web/src/components/CalendarView.tsx)):
- Weekly Mon–Sun grid on desktop; 3-day view centered on today on
  mobile (sprint 17), with single-day prev/next stepping driven by an
  independent `dayOffset` cursor.
- Blocks render with project color, completed = solid +
  strikethrough, tick button on each block toggles complete.
- Overlap layout: blocks split width into lanes per-day.
- "Now line" on today.
- Person switcher in the head — pin/unpin teammates, toggle which
  person's week is rendered. `block.user_id` is whose calendar the
  block lives on, independent of `task.assignee_id`.
- Right rail (≥ 1000 px): schedulable tasks for the active project
  filter, with silent-blocker dot, **All/My toggle** (All shows every
  project task, including Later, non-yours dimmed and prefixed with
  `↗`), **title filter** (matches title or `external_id`), sort
  matches the list (Now first, then sort_key).
- **Drag from rail onto a day column** to create a block
  (`block.create`).
- **Drag-to-move blocks** across days/times (`block.update`).
- **Drag-resize from the top or bottom edge** of a block
  (`block.update`).
- **Touch parity** (sprint 16): pointer events drive lifecycle, a
  document-level non-passive `touchmove` suppresses scroll
  mid-gesture. Block drag and resize work on mobile; tap-a-block →
  reveals actions, tap-again → opens task modal. Drag-to-create on
  empty grid is desktop-only (gated off on touch to avoid scroll
  conflict).
- **Show linked / Show personal toggles** in the toolbar (sprint 14).
  Render the partner's blocks (dashed border, opacity 0.55) or the
  personal-workspace blocks (left project-color stripe, opacity 0.7).
  Both overlays are full-column-width, lower z-index, read-only.

**List view** ([web/src/components/ListView.tsx](../web/src/components/ListView.tsx)):
- Per-project document. Project switcher in left sidebar.
- Now / Later / Recurring / Someday / Done sections. Now is grouped by
  assignee when the project has >1 member; the caller's group floats
  to the top. "(you)" is keyed off `meId`. Workspace `owner` and
  project-role `owner`/`inactive` members are hidden from assignee
  groups unless they have a Now task assigned (sprint 15).
- **Unassigned bucket** (sprint 15) renders at the bottom of Now when
  there are unassigned now-tasks. `setTaskAssignee(id, null)` on a
  Now task auto-flips it to Later — without an owner, a Now task has
  no group to render under.
- Drag a task between sections (`task.set_section`); drag onto an
  assignee subsection in Now also reassigns
  (`task.set_assignee`). HTML5 drag on desktop, long-press
  (220 ms / 8 px cancel threshold) on touch via `useLongPress`.
- Tick task or subtask to toggle done; `Archive done` button bulk-
  moves ticked Now tasks into Done.
- Click row → task modal. New-task button opens `TaskModalDraft`
  (no default project — tap-through guard, sprint 15).
- **Mobile** (sprint 17): row stripped to grip · check · title.
  `external_id`, "Xh over" hidden at phone widths. Subtasks blend
  into the parent row for tap/long-press purposes; subtask edits
  move to the modal.
- **Tag chips in the row trail** (sprint 21): up to 3 chips on
  desktop, 1 on phones, plus a quiet `+N` overflow chip. Sort
  prioritizes filter-matched ids first so the cap surfaces the
  active-filter tags regardless of how the task was tagged. With
  an active filter, unmatched chips fade to opacity 0.45 and
  matched chips get a stronger color-mix outline.
- **Sticky tag filter strip** (sprint 21) at the top of the list
  scroll container: chip toggles for every project tag, a 2-segment
  OR/AND mode pill, and a Clear button. Both controls are always
  rendered (Clear goes `disabled` at zero selection) so toggling
  chips doesn't cause the strip to jump. Chips inside the strip are
  sorted by title length descending so longer chips lead each row
  and shorter ones slot into the trailing whitespace. Filter state
  (`tag_ids`, `tag_mode`) lives on `listFilter` and is persisted
  via `partialize`. Phantom ids are pruned on bootstrap and on
  `tag.delete`.
- **Quick-add seeds the active filter** (sprint 21): a task created
  through any list add-row attaches `listFilter.tag_ids` so it
  doesn't immediately disappear from the row it was typed into.

**Task modal** ([web/src/components/TaskModal.tsx](../web/src/components/TaskModal.tsx)):
- Title, description, subtask checkboxes (with grip drag on desktop,
  long-press on touch), time-block history with the block-owner
  avatar (`data-me` highlights yours).
- Right side: project, assignee, status, estimate, time-left, **tags
  multi-select picker** (sprint 21 — selected chips with × to
  remove, `+` opens a portal-anchored popover with search + chip-
  style toggle rows + inline "Create *<query>*" footer; toggle
  fires a single `task.set_tags` op), source, **section dropdown**
  (now / later / recurring / someday / done — `task.set_section`), **Issue link**
  (renders `[external_id]` as a link when the project has an
  `external_url_template`, muted text otherwise; pencil icon arms
  the editor). On phones the Tags section moves to the main pane
  (under the estimate bar) since the side pane is closed by default.
- Estimate bar showing spent / planned / left.
- Trash icon in the header opens `ConfirmDelete` (plain confirm).
- **Copy as markdown** affordance (sprint 11) writes
  `# title` + description + `## Subtasks` checklist via
  `navigator.clipboard.writeText`.

**Project modal** ([web/src/components/ProjectModal.tsx](../web/src/components/ProjectModal.tsx)):
- Create or edit: title, Lucide icon picker, color swatches, issue
  URL template (`{key}` placeholder, validated as `http(s)://…` ≤ 512 chars).
- Members section: search popover to add (one click, auto-closes);
  two-step remove (× chip → red Remove button) since losing access is
  heavier than gaining it.
- **Tags section** (sprint 21): bordered list of project tags with a
  swatch dot, title, usage count, pencil to expand into an inline
  rename / recolor row, and a trash button that opens a single-step
  `ConfirmDelete` warning of how many tasks will lose the tag. Each
  mutation fires immediately — no batching with the project's Save
  Changes button.
- Per-row role `<Select>` (`owner` / `lead` / `member` / `inactive`)
  — readable by everyone with edit access, but only **interactive
  for the workspace owner**; project leads see a static role tag
  with a hint line.
- Workspace-owner caller can edit their own role; backend force-
  includes them at minimum-`owner` so accidental self-removal is
  blocked.
- Trash icon (workspace owner only) opens `ConfirmDelete` with
  type-to-confirm.

**Workspace modal** ([web/src/components/WorkspaceModal.tsx](../web/src/components/WorkspaceModal.tsx)):
- Owner-only. Title field; member table with per-row role `<Select>`
  (`owner` / `member`); same one-click-add / two-step-remove pattern
  as the project modal. Personal workspaces hide the member section.
- Trash icon on non-personal workspaces opens `ConfirmDelete` with
  type-to-confirm.

**Link Account modal** ([web/src/components/LinkAccountModal.tsx](../web/src/components/LinkAccountModal.tsx)):
- One shell, four states driven by the link row: **none** (email
  input + Send invite), **sent** (Waiting for X + Cancel),
  **received** (Accept / Decline — sticky, can't be dismissed),
  **accepted** (Linked with X + Unlink). Soft-amber privacy callout
  on both invite and received-pending views.

**Custom `<Select>`** ([web/src/components/Select.tsx](../web/src/components/Select.tsx)):
- Replaces native `<select>` everywhere. Generic over value type;
  `sm`/`md` sizes; renders the menu with `position: fixed` so it
  escapes ancestor `overflow: auto` containers. Mobile-friendly
  (`pointerdown` for outside-click, `touch-action: manipulation` to
  defeat iOS double-tap-zoom delay) — sprint 15.

**Sync pill + failed-ops popover** ([web/src/components/SyncPill.tsx](../web/src/components/SyncPill.tsx)):
- Combined labels: `Synced` / `N pending` / `Syncing…` /
  `Offline · N` / `Error · N`. 300 ms grace before the spinner label
  appears so fast round-trips don't surface "Syncing…".
- Click → popover with the failed-ops list; per-op Retry / Discard
  plus Retry all / Discard all.

**Toasts** ([web/src/components/Toasts.tsx](../web/src/components/Toasts.tsx)):
- Bottom-right stack. Errors auto-dismiss after 6 s, info after 3 s,
  click X to dismiss early. Used for surfacing server-rejected op
  messages and workspace/project save/delete failures.

### 7.4b Plan view — the project roadmap board

([web/src/components/PlanView.tsx](../web/src/components/PlanView.tsx),
[PlanSprintCard.tsx](../web/src/components/PlanSprintCard.tsx),
[plan.ts](../web/src/plan.ts), [plan.css](../web/src/styles/plan.css))

The fourth surface, reached with `p` or the sidebar button. X axis is
weeks grouped under month headers with ISO `W38` labels and a "now"
marker; Y axis is tracks. Project-scoped; a workspace roll-up is later.

- **Cards** span a week range on one track, carry a derived `A1`/`A2`
  badge, a title and a checklist of real tasks. Tick one on the board
  and it ticks in List and Calendar — same `task.tick`. A checklist row
  opens the task modal on click, reorders by drag (the list's own
  section-scoped `task.reorder`), and carries an arrow back to the rail
  that clears `sprint_id`. **Finished rows sink to the foot of the card
  and take no part in ordering** — `task.tick` sets `status` and leaves
  `section` alone, so section rank alone would float a ticked task to
  the top of its own card, and honouring a cross-section drop for a
  done row would silently un-archive it.
- **Completeness is dullness, not a readout.** A card whose every task
  is ticked is dimmed, exactly as a done row is in the list and a
  completed block is on the calendar. There is no `3/4` counter, no
  progress bar, and no marking of the "running" sprint — a card's
  position on the week axis already says when it runs, beside the
  axis's own now marker.
- **The now marker is the calendar's today marker**, token for token
  (`--accent-soft` fill, 2px `--accent` underscore, `--accent` label,
  and a 1px `--accent` line down the column). A week board and a day
  board disagreeing about where "now" is would be absurd. This is the
  only `--accent` on the board; the cards speak in track colour.
- **Membership is single-valued**: `task.sprint_id → sprint.track_id →
  track`. Nothing can render twice, so no validation rule is needed to
  stop it. Tags are orthogonal and untouched.
- **A task's track** is its sprint's track if it has a sprint, else its
  own `tasks.track_id` (the per-track backlog). Resolved at render time,
  so it can't drift.
- **The rail** holds unplanned, not-done project tasks. Its *frame* is
  the calendar's (`.cal-rail`, `.rail-head`, `.rail-body`); its
  **groups** are the list's `.section-head` — all four sections, always
  shown, always counted, even at zero, because a section that vanishes
  when it empties makes the rail's shape jump as you plan. Headings sit
  flush with the left gutter and the rows indent under them, with no
  trailing rule: the list's wide columns can carry one as an underline,
  but in 220px it reads as a line *closing* the group above. The filter
  is **tags**, specifically the list's `ListTagFilter` extracted to
  [TagFilter.tsx](../web/src/components/TagFilter.tsx) and shared.
  (The calendar groups by project and filters by project, both
  meaningless on a board already scoped to one.)
  **A rail row is one line: its title.** It is the same object as a
  card's checklist row sitting a few hundred pixels away, so it is
  built to the same `--plan-task-h`. The estimate, external id and tag
  dots that used to ride along doubled its height to answer questions
  this view doesn't ask — a plan board asks *where does this go*. Both
  are still carried on `PlanTask` for the filter box and the tag chips,
  just not drawn.
  Drag onto a card to plan, drag back out to unplan. `+ Add task`
  inside a card is the ListView quick-add pattern (`task.create` into
  `later`, then `task.set_sprint`).
- **Orphan row.** Deleting a track SET NULLs its sprints, which then
  render in a "No track" row at the foot of the board. SET NULL
  *without* that row would be data loss by invisibility; with it the
  state is self-healing. No plan-view gesture destroys a task — the
  board offers "remove from sprint", never delete; deletion stays in
  the task modal behind its existing confirm.
- **The "Unplanned" band.** A brand-new board would be empty, which is the
  usual reason a roadmap feature is never adopted, so the past is
  reconstructed: fortnight buckets (anchored to even ISO weeks, so
  every project in a workspace agrees where a fortnight starts) over
  finished work **that was never planned into a sprint**. That last
  clause is load-bearing. Without it a finished task rendered both in
  its card and in the band — the exact double-render the single-valued
  `task.sprint_id` model exists to make impossible — and the band had
  no rule by which anything ever left it.
  The splitter is best-evidence-first: completed block span →
  `finished_at` → `created_at`.
  **Derived, never materialized**, and recomputed on every render, so
  there is no generation step and nothing to refresh: work finished
  today lands in today's fortnight by itself, whether or not anyone is
  using sprints. It is named for the toolbar switch that shows it, and
  rendered muted in its own full-width row outside every track, because
  a record is not a plan and the two must not share a visual slot.
  It is read-only *as a record* but not a dead end — the two ways out
  are the two ways it empties: drag a row onto a card
  (`task.set_sprint`), or **Promote** the bucket, which materializes it
  as a real sprint over the computed span plus one `task.set_sprint`
  per member. Promote lands the card on "No track" rather than guessing
  one, and is offered only for a bucket wholly inside the window, since
  promoting a clipped one would invent a span from the visible part.
- **Creating a sprint** is `+ Sprint` in the toolbar, which *arms* the
  board: the grid lights up, the cursor becomes a crosshair, and you
  drag across the weeks the sprint should cover. A live dashed band
  shows the span and its week count; Esc cancels. The span is the whole
  point of a card, so picking it is the create gesture rather than
  something you fix up afterwards.
- **Moving a card is one pointer drag carrying both axes** — week span
  (x) and track row (y) — like the calendar's block drag carrying time
  and day. It commits `sprint.set_dates` and/or `sprint.set_track`.
  Resizing is a full-height grip at each card edge, which
  `preventDefault`s on pointerdown — otherwise the native selection
  starts there and the drag paints every checklist it crosses. The
  header can't do the same without killing its own click, so the board
  also sets `user-select: none` for the duration of a drag.
  **The title is plain text, not a click-to-edit control.** The header
  is the move handle and the title fills most of it, so anything
  clickable there fights the drag: either it swallows pointerdown and
  the card won't move from the place everyone grabs it, or it doesn't
  and every short drag ends in an edit box. Renaming is a pencil button;
  deleting is a trash button behind `ConfirmDelete`, which counts the
  tasks that will return to the rail.
  **The card is deliberately not an HTML5 drag source.** It is already a
  *drop target* for tasks, and making it a native drag source too meant
  `dragstart` fired on the first pointermove and killed the pointer
  stream — move and resize both silently did nothing. HTML5 DnD is used
  only where the card is the target: tasks, via
  `application/x-fira-plan-task`.
- **No time figures on a card.** `taskTimeLeft` filters against the real
  clock, so any such number would read "as of now" inside a board
  scrubbed to an earlier week. The rail shows an estimate, not time
  left, for the same reason.
- **A handful of layout tokens are the whole rhythm.**
  `--plan-week-w` is the column width, so the toolbar's S·M·L control is
  a single variable write. `--plan-axis-month-h` / `--plan-axis-week-h`
  are the two axis rows, declared rather than left to fall out of font
  metrics because the rail's header has to close on exactly the same
  line as the board's axis — and that constraint is why the axis stays
  two rows: the rail's filter box sets a floor on the header's height,
  so folding the month into the week row would buy ~20px at the cost of
  the alignment. The saving came from type size instead. A rule under
  the month strip gives the week columns' verticals something to start
  from; without it they began in mid-air at the row junction. Axis labels
  are `--plan-axis-label-fs` (10px × `--fs-scale`), deliberately
  *smaller* than the task text they label; they had been
  `--fs-xs × --label-size`, which is 15.8px in modern against 13.8px of
  content — scaffolding outranking the thing standing on it. Week
  numbers take the mono face and tabular figures, being codes; the
  month strip is shorter than the week row and carries the only strong
  rule on the axis, because grouping is all it does. `--plan-task-h` / `--plan-task-fs` are one task line, used by a
  card's checklist, its add-task row, the Unplanned band's rows **and** the
  rail — every place a task appears. They were drifting badly: an 18px
  `--fs-xs` checklist sliver beside a 44px two-line rail row, on the
  same screen, for the same object.
  Both row tokens are **line box + density-scaled padding**, never
  `calc(Npx * var(--density))`: `--density` is defined as "padding /
  gaps that are allowed to breathe", and multiplying a whole row by it
  made modern 45% taller rather than 30% roomier. `--plan-rail-w` and
  `--plan-head-w` are **fixed per style** (220/180 classic, 248/200
  modern) for the same reason `--side-w` is 220/248 and the calendar's
  rail is a flat 320px — scaling panel widths by density put the rail
  at 319px while the week columns, a JS constant, didn't move at all.
- **Neither scroll container reserves a scrollbar gutter.** The calendar
  reserves one on its rail so rows keep the head's content edge, and
  subtracts `--scrollbar-w` from every row to compensate; the plan rail
  does neither, so `stable` only parked 15px of dead space between the
  last character of a task and the board. The week grid is the same: it
  always scrolls horizontally and almost never vertically.
- The project title appears in the breadcrumb; the Plan toolbar does not
  repeat it.
- **Every toolbar control is a segment of a `week-nav` pill** — pan,
  resize, window size, the three view switches, the two add actions —
  and the height is *inherited* from `.cal-toolbar .week-nav-btn`, a
  flat 22px in both styles, so the plan bar lands on exactly the
  calendar bar's metrics. The bar previously mixed 24px segmented pills
  with 26px standalone chips, then briefly took `--control-h`, which is
  `calc(26px * var(--density))` and so 37.7px in modern for a row of
  12.65px labels.
- **Desktop only** below 700px: a week-column board is inherently wide
  and a three-week window on a phone answers nothing the list doesn't
  answer better. Renders a short panel with a button back to the list.
- **`PlanView` renders only `PlanSnapshot`** — no component reads
  `s.sprints` during rendering. Live store entities and replayed entities
  share `buildPlanSnapshot`; replay displays only the selected historical
  entities. Projection lives in Rust
  ([api/src/plan.rs](../api/src/plan.rs)) because the client doesn't
  have the op log; assembly stays in `plan.ts` with one implementation
  serving both modes.
- **History scrubber (sprint 32).** `GET /api/plan/at?project_id=…&t=…&seq=…`
  returns projected entities, the effective timestamp, earliest recorded
  plan op, selected revision, and changes with sequence, kind and timestamp,
  requiring current project access. Optional `seq` selects an exact revision,
  distinguishing changes that share a timestamp; optional `t` selects a time.
  The **Past** toggle opens a separate history panel below the board (hidden
  by default). Its continuous time axis has its own zoom and pan, independent
  of the roadmap's weeks and horizontal scrolling. Click to select a time,
  drag the timeline to pan, or drag the playhead to scrub continuously. Scroll
  or use zoom buttons to zoom from years down to seconds. Tick labels adapt
  to seconds, days, calendar months and years; Fit shows all recorded history
  from genesis to the browsing session's current-time boundary. That boundary
  stays stable during zoom and pan, extending only when new recorded changes
  arrive. Zoom stops at Fit and at a one-second window. No state is
  reconstructible before genesis. Change
  markers, a revision picker and
  previous/next controls select exact operations. Left/Right keys step to
  earlier/later revisions whether the picker or timeline has focus, independent
  of the picker's newest-first list order. The picker displays the selected
  revision/time; the duplicate footer timestamp and date input are removed.
  The range runs from genesis to now. **Live plan**
  restores editing; hiding Past also returns to live immediately.
  **Unplanned** controls the reconstructed finished-work band and its
  identically named row. Panel visibility persists, historical selection
  does not. The board shows only the selected revision, without live cards
  or drift labels overlaid. Scrubbing reveals changes by moving the cards
  through their historical states. Deleted tasks reappear in historical
  checklists. Replay is read-only, including the inbox;
  Unplanned remains available using creation and completion dates reconstructed
  from task ops, with promotion, dragging and live task editing disabled.
  Historical Unplanned uses recorded finish dates (creation dates as fallback),
  since completed calendar block spans are not replayed. Tag filters are hidden
  because tags are not projected. Card counters remain removed. Selection resets on project
  and workspace changes. Requests are throttled during dragging; the last
  completed snapshot remains visible with a loading status until the selected
  read completes. Status and retry use a fixed-height footer caption, blank
  when idle, keeping the board still; there is
  no top history banner. Stale responses are ignored; failed reads show retry.
  The snapshot-only playground has no historical controls.
- **Picking a project in the sidebar scopes the view you're in**, it
  does not jump to the list: plan → `planProjectId`, dashboard →
  `dashboardProjectId`, list → `listFilter.project_id`, calendar →
  `soloProjectFilter` (its scoping gesture is its own visibility
  filter, since it's a time surface across every project). The nav
  order is Calendar · List · Plan · Dashboard — a widening sequence
  over the same tasks, with the roll-up last. The project highlight
  follows whichever cursor the current view uses; on the calendar it
  appears only when exactly one project is visible, which is the only
  time a single-project highlight is true.
- **Gated out of production builds** (`import.meta.env.DEV` on the
  sidebar entry) until the UX is confirmed. The reason is the op log:
  `processed_ops` is never pruned, so an op shape that reaches a real
  user is permanent. While the door is dev-only, every shape stays
  revisable at the cost of one `TRUNCATE processed_ops` and a reseed.

### 7.5 Playground mode

"Try as Maya in your browser" on the login screen drops the user into
a fully populated workspace with no account, no backend, no network.
Same store, same components, same persist layer — a single
`playgroundMode: boolean` field gates every network-touching action
(`syncOutbox`, `pollChanges`, all REST helpers, the WS handlers).
Snapshot persists to `localStorage` via `zustand/middleware/persist`
so reload re-enters playground from cache.

The playground seed lives in
[web/src/playground/bootstrap.json](../web/src/playground/bootstrap.json),
dumped from the canonical Rust seed by
`cargo run --bin dump-bootstrap` so it stays in sync without
hand-porting.

### 7.6 Mobile specifics

- **Viewport**: `width=device-width, initial-scale=1, viewport-fit=cover`.
- **Dynamic viewport units** (`100dvh`) so list / calendar / modal
  don't hide under iOS Safari toolbars.
- **3-day calendar centered on today** with single-day prev/next
  stepping on phones; 7-day grid stays on desktop.
- **Slide-over sidebar** behind a hamburger in the topbar; the icon
  rail is hidden on phones.
- **List row decluttered** to grip · check · title. Subtasks blend
  into the parent row.
- **Touch drag** end-to-end: list task + subtask reorder (long-press
  220 ms or grip), time block move/resize, rail-task → calendar
  scheduling on tablets, calendar block tap-to-reveal-then-tap-to-open.
  Shared [`useLongPress`](../web/src/useLongPress.ts) hook.
- **PWA install**: squared favicon, 32 / 180 / 192 / 512 PNGs,
  `manifest.webmanifest`, `apple-mobile-web-app-*` meta,
  `env(safe-area-inset-*)` padding so iOS standalone clears the notch.
- **`useIsMobile()`** hook for component-level branching.

### 7.7 Not yet

- Drag-to-create on calendar grid (free-draw a block on empty space)
- Inline editing of title / estimate in the list row (modal works)
- Filter chips (track / sprint / status) on the list toolbar
- Compare mode (two people side-by-side)
- Date scope on list (today / this week / a date)
- Recurring template / instance model (the section bucket exists; per-cycle instance auto-spawn does not)
- Real Jira / Notion / GCal sync — `external_id` + `external_url` are
  manual; no automation, no calendar ingest, no GCal rendering
- Email invites for non-Fira accounts (linking and workspace adds
  both require the partner to have signed in first)
- Multiple accepted links per user (hard-cap'd to one)
- Drop-on-Unassigned-bucket
- Per-task click-action on linked / personal overlays

## 8. Build / dev

See [README.md](../README.md). Quickstart inside the devcontainer:

```bash
docker compose up -d postgres   # first time
cd api && cargo run --bin seed  # one-time seed
cd api && cargo run             # api on :3000
cd web && pnpm dev --host       # web on :5173 → /api/* proxied to :3000
# open http://localhost:5173
```

Postgres on `:5432`. Set `DEV_AUTH=1` to enable `/api/auth/dev-login`
and the dev affordances on the login screen. Multi-instance WS
testing (sprint 10): see README's "Multi-instance WS test rig"
section.

Production: single Fly.io app at <https://usefira.app>, same-origin
SPA + API. Prod binary built with `--no-default-features` so the
`dev_auth`-gated handlers literally don't exist in the binary.

## 9. Out of scope for this iteration

Stated up front so future me doesn't speculate:

- Sync to Jira / Notion / GCal (write-back, status pull, calendar
  ingest). Manual `external_id` / `external_url` links exist;
  automated sync doesn't.
- Recurring task templates + per-cycle instances.
- Conflict-divergence UI. Today is last-write-wins on intent ops.
- Op-log compaction / archival of `processed_ops`. Migration 0010
  intentionally lets log rows linger past their entities; a periodic
  GC is the obvious follow-up.
- Per-user rate limit on `/api/ops`.
- Standalone test suite (smoke verified manually).
- Email invites / pre-create-by-email — workspace owners and link
  initiators both have to point at an existing Fira account.
- Multi-region Postgres.
- Production observability beyond `flyctl logs` (Sentry, structured
  log shipping).
