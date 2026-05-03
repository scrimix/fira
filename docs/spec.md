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
happens in a sectioned document (Now / Later / Done), not a board.
Prioritization is manual ordering. The product is two screens — Inbox
and Calendar — over a single shared task model, scoped by **workspace**
(the company-level tenant) and project.

The user we optimize for is a senior IC split across 3–5 projects, who
needs to see their *own* week colored by project. Standup-friendly
behavior comes free from the same data: scrub the inbox by date, see
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

Authoritative SQL: [api/migrations/](../api/migrations/) (0001–0013,
applied in order on boot via `sqlx::migrate!`).

| table              | purpose                                            |
|--------------------|----------------------------------------------------|
| `users`            | identity. `google_sub` is the unique lookup key; seeded fixtures use `dev-{slug}`. |
| `sessions`         | opaque 32-byte tokens, 30-day TTL, server-stored. The `sid` cookie names a row. |
| `workspaces`       | id, title, `is_personal`, `created_by`. Every user has one personal workspace, auto-created on Google OAuth callback and in the seeder. |
| `workspace_members`| M:N user↔workspace, `role text check (role in ('owner','member'))`, `removed_at` for soft-delete. |
| `projects`         | id, title, icon, color, source (`local`/`jira`/`notion`), `owner_id`, `external_url_template`, `workspace_id NOT NULL`. |
| `project_members`  | M:N user↔project, `workspace_id` mirrored from parent project by trigger, `role text check (role in ('owner','lead','member','inactive'))`, `removed_at` for soft-delete. Composite FK `(workspace_id, user_id) → workspace_members(workspace_id, user_id)` makes it structurally impossible to add a user to a project who isn't in the workspace. |
| `epics`            | unit of work bigger than a task, smaller than a project. |
| `sprints`          | time-boxed; `active` flag drives the inbox's sprint filter. |
| `tasks`            | section (`now`/`later`/`done`), status, estimate, assignee, sort_key, optional `external_id`, optional per-task `external_url`. |
| `subtasks`         | flat under a task. The "checkbox tree in a description" doesn't exist yet — subtasks are first-class rows. |
| `time_blocks`      | start_at, end_at, state (`planned`/`completed`/`skipped`), `user_id` (whose calendar the block lives on, independent of `task.assignee_id`). |
| `processed_ops`    | accepted-op log: `op_id` PK (idempotency) + `seq BIGSERIAL` (the global change-feed cursor) + `payload JSONB` (verbatim wire op) + `project_id` (nullable, for project-scope filtering) + `workspace_id` (nullable, for workspace-scope filtering). FKs to projects/workspaces were dropped in migration 0010 so log rows survive entity deletion. |
| `user_links`       | account-pair table; `(user_a, user_b)` canonicalized so `a < b`, `requested_by` distinguishes initiator, `status in ('pending','accepted')`. Two partial unique indexes (one per side, scoped to `status='accepted'`) cap each user to one accepted link. |
| `gcal_events`      | placeholder table — no GCal sync yet, no UI rendering. |

**Two role axes** (sprints 08, 12, 15) gate authorization:

- **Workspace role** (`workspace_members.role`): `owner` | `member`.
  Workspace owners manage the workspace title, members, and roles, and
  can create / edit / delete any project in the workspace. Members
  see only projects they're explicitly added to.
- **Project role** (`project_members.role`):
  `owner` | `lead` | `member` | `inactive`. Workspace owners get
  `owner` on every project (auto-backfilled by migration 0012). `owner`
  and `inactive` are *passive* — hidden from inbox assignee groups
  unless they have a Now task assigned to them. `lead` can edit the
  project but not delete it; only the workspace owner can promote to
  `lead` or change project roles. `member` is the default.

**Personal workspace invariant.** Every user has exactly one workspace
where `is_personal = true` and they are the sole owner. Created on
signup and on the dev fixture. Cannot be deleted, cannot have other
members added.

**Things in the design doc that are NOT in the schema yet:**
- `recurring` section + `task_type` (`regular`/`recurring`/`instance`)
  + `recurring_parent_id` — no fixture uses them.
- `sync_state`, `source_updated_at`, `last_synced_at`, `raw_payload`,
  `external_workspace`, `section_history` — no Jira/Notion write-back
  yet. Manual issue links exist via `task.external_id` +
  `project.external_url_template`, but not automated sync.
- `integration_tokens` for Jira/Notion API access — none.
- `snapshots` — no replay UI.

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
| `/api/workspaces/:id/members`          | PUT    | replace member set + roles (owner only)               |
| `/api/workspaces/:id/members/:user_id` | PATCH  | change a single member's role (owner only)            |
| `/api/workspaces/:id/users`            | GET    | directory listing scoped to one workspace             |
| `/api/workspaces/:id/all-users`        | GET    | every user in the system (owner only) — for adding a Google user not yet in any workspace |
| `/api/projects`                        | POST   | create a project (workspace owner only)               |
| `/api/projects/:id`                    | PATCH  | update title / icon / color / `external_url_template` (workspace owner OR project lead) |
| `/api/projects/:id`                    | DELETE | delete (workspace owner only)                         |
| `/api/projects/:id/members`            | PUT    | replace project member set + per-row role             |
| `/api/links`                           | GET    | list every link involving me                          |
| `/api/links`                           | POST   | `{ email }` → create pending link                     |
| `/api/links/:id`                       | DELETE | cancel sent / decline received / unlink               |
| `/api/links/:id/accept`                | POST   | accept (only the non-requester)                       |
| `/api/linked/calendar`                 | GET    | partner's blocks + `LinkedTask` projection (read-only overlay) |
| `/api/personal/calendar`               | GET    | personal-workspace blocks + `LinkedTask` projection — empty when active workspace is already personal |
| `/api/ops`                             | POST   | push outbox ops, idempotent per `op_id`, per-op tx    |
| `/api/changes?since=N`                 | GET    | pull change feed, scope-filtered, ≤ 500 rows          |
| `/api/ws?workspace_id=…`               | WS     | nudge socket for the workspace's change feed; 30 s server ping |
| `/api/ws/user`                         | WS     | per-user channel for membership / role / workspace events |

**What `/api/bootstrap` returns** (for the active workspace; arrays
non-null):

```ts
{
  me, users, projects, epics, sprints, tasks, blocks,
  workspace, links, cursor
}
```

`cursor` is the current `MAX(seq)` from `processed_ops`. Fresh clients
start polling `/api/changes` from there, not from 0. The shape
otherwise mirrors `web/src/types.ts`; no pagination, no filtering —
the dataset is small enough to send in one shot.

**Op kinds accepted by `/api/ops`** (~21):
`task.create`, `task.tick`, `task.set_section`, `task.set_title`,
`task.set_description`, `task.set_estimate`, `task.set_assignee`,
`task.set_status`, `task.set_external_id`, `task.set_external_url`,
`task.reorder`, `task.delete`, `subtask.create`, `subtask.tick`,
`subtask.set_title`, `subtask.delete`, `subtask.reorder`,
`block.create`, `block.update`, `block.delete`.

Workspace, project, and link mutations write synthesized
`workspace.create` / `workspace.update` / `workspace.set_members` /
`workspace.set_member_role` / `workspace.delete` / `project.create` /
`project.update` / `project.set_members` / `project.delete` rows onto
the same log so peer clients converge through one apply path. Account
linking events ride the per-user channel only — there is no
workspace-scoped `link.*` op (the partners might not share a
workspace).

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
desktop. Order: brand → Calendar / Inbox toggle → project icons →
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
  matches the inbox (Now first, then sort_key).
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

**Inbox view** ([web/src/components/InboxView.tsx](../web/src/components/InboxView.tsx)):
- Per-project document. Project switcher in left sidebar.
- Now / Later / Done sections (Recurring not yet). Now is grouped by
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
  Tags, `external_id`, "Xh over" hidden at phone widths. Subtasks
  blend into the parent row for tap/long-press purposes; subtask
  edits move to the modal.

**Task modal** ([web/src/components/TaskModal.tsx](../web/src/components/TaskModal.tsx)):
- Title, description, subtask checkboxes (with grip drag on desktop,
  long-press on touch), time-block history with the block-owner
  avatar (`data-me` highlights yours).
- Right side: project, assignee, status, estimate, time-left, tags,
  source, section, **Issue link** (renders `[external_id]` as a link
  when the project has an `external_url_template`, muted text
  otherwise; pencil icon arms the editor).
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
- **Dynamic viewport units** (`100dvh`) so inbox / calendar / modal
  don't hide under iOS Safari toolbars.
- **3-day calendar centered on today** with single-day prev/next
  stepping on phones; 7-day grid stays on desktop.
- **Slide-over sidebar** behind a hamburger in the topbar; the icon
  rail is hidden on phones.
- **Inbox row decluttered** to grip · check · title. Subtasks blend
  into the parent row.
- **Touch drag** end-to-end: inbox task + subtask reorder (long-press
  220 ms or grip), time block move/resize, rail-task → calendar
  scheduling on tablets, calendar block tap-to-reveal-then-tap-to-open.
  Shared [`useLongPress`](../web/src/useLongPress.ts) hook.
- **PWA install**: squared favicon, 32 / 180 / 192 / 512 PNGs,
  `manifest.webmanifest`, `apple-mobile-web-app-*` meta,
  `env(safe-area-inset-*)` padding so iOS standalone clears the notch.
- **`useIsMobile()`** hook for component-level branching.

### 7.7 Not yet

- Drag-to-create on calendar grid (free-draw a block on empty space)
- Inline editing of title / estimate in the inbox row (modal works)
- Filter chips (epic / sprint / status) on the inbox toolbar
- Compare mode (two people side-by-side)
- Date scope on inbox (today / this week / a date)
- Recurring section + template / instance model
- Snapshots / replay
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
- Snapshots / replay UI.
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
