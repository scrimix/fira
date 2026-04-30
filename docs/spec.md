# Fira — working spec

> Authoritative spec for what's actually being built. The original
> [brief_description.md](brief_description.md) and [fira_design_doc.md](fira_design_doc.md)
> are the *long-form vision*; this document is the *current contract* between
> what the code does and what it's supposed to do. When the two diverge, this
> file wins — update it as decisions change.

---

## 1. The product, in one paragraph

Fira is a task tool where the unit of planning is the **time block** —
a discrete scheduled work session attached to a real task on a real day. The
plan is the set of blocks on the calendar; reality is the set of blocks
marked complete. Capture happens in a sectioned document (Now / Later /
Done), not a board. Prioritization is manual ordering. The product is two
screens — Inbox and Calendar — over a single shared task model.

The user we optimize for is a senior IC split across 3–5 projects, who needs
to see their *own* week colored by project. Standup-friendly behavior comes
free from the same data: scrub the inbox by date, see who finished what.

## 2. Architecture

```
┌──────────────┐  GET /bootstrap (initial hydrate)  ┌──────────────┐    sqlx    ┌──────────┐
│  web (Vite)  │ ─────────────────────────────────▶ │  api (Axum)  │ ─────────▶ │ postgres │
│  React + TS  │  POST /ops      (push outbox)      │  Rust 1.x    │            │   16     │
│  Zustand     │  GET  /changes  (pull change feed) │              │            │          │
└──────────────┘ ◀───────────────────────────────── └──────────────┘            └──────────┘
```

**Local-first, closed round-trip.** The web app hydrates once from
`/bootstrap` (which also returns the current change-log cursor), then
every mutation updates the in-memory store synchronously *and* appends
an intent-shaped op to an outbox. A 2 s tick (plus opportunistic ticks
on `focus` and `online`) drives `syncOutbox().then(pollChanges)`:

- **Push**: `POST /ops` sends queued ops in batches of up to 50. The
  server applies each in its own transaction, idempotent on `op_id` via
  the `processed_ops` PK; cross-tenant writes are rejected per-op via
  `project_scope`.
- **Pull**: `GET /changes?since=cursor` returns ops authored elsewhere
  (other tabs, teammates) filtered to the caller's project scope, up
  to 500 rows. `applyRemoteOp` dispatches them through the same
  reducer-shaped handlers as local mutations. Echoes of the client's
  own writes are suppressed via an `appliedOpIds` set with a 5-minute
  TTL.

The TopBar pill (`Synced` / `N pending` / `Syncing…` / `Offline` /
`Error · N`) makes the sync state visible. Click to force a tick.

**Why not TanStack Query**: this isn't CRUD with occasional optimistic
updates — every drag, tick, retype is a mutation. A request-per-keystroke
model is the wrong shape. The Linear/Replicache pattern of "local store as
source of truth, outbox as audit log, op log as change feed" composes;
per-mutation `useMutation` hooks don't.

## 3. Data model — current

Authoritative SQL: [api/migrations/0001_init.sql](../api/migrations/0001_init.sql).

Trimmed deliberately from the design doc. Add columns when a feature needs
them, not in anticipation.

| table             | purpose                                            |
|-------------------|----------------------------------------------------|
| `users`           | identity. `google_sub` is the unique lookup key; seeded fixtures use `dev-{slug}`. |
| `sessions`        | opaque 32-byte tokens, 30-day TTL, server-stored. The `sid` cookie names a row. |
| `projects`        | id, title, icon, color, source (`local`/`jira`/`notion`), `owner_id`, `external_url_template`. |
| `project_members` | M:N user↔project, with `removed_at` for soft-delete. |
| `epics`           | unit of work bigger than a task, smaller than a project. |
| `sprints`         | time-boxed; `active` flag drives the inbox's sprint filter. |
| `tasks`           | section (`now`/`later`/`done`), status, estimate, assignee, sort_key, optional `external_id`. |
| `subtasks`        | flat under a task. The "checkbox tree in a description" doesn't exist yet — subtasks are first-class rows. |
| `time_blocks`     | start_at, end_at, state (`planned`/`completed`/`skipped`), `user_id` (whose calendar the block lives on, independent of `task.assignee_id`). |
| `gcal_events`     | dashed/muted background events, no task linkage.   |
| `processed_ops`   | accepted-op log: `op_id` PK (idempotency) + `seq BIGSERIAL` (the global change-feed cursor) + `payload JSONB` (verbatim wire op) + `project_id` (for scope filtering on read). |

**Things in the design doc that are NOT in the schema yet:**
- `recurring` section + `task_type` (`regular`/`recurring`/`instance`) +
  `recurring_parent_id` — no fixture uses them.
- `sync_state`, `source_updated_at`, `last_synced_at`, `raw_payload`,
  `external_workspace`, `section_history` — no Jira/Notion write-back
  yet. Manual issue links exist via `task.external_id` +
  `project.external_url_template`, but not automated sync.
- `integration_tokens` for Jira/Notion API access — none.
- `snapshots` — no replay UI.

## 4. API — current

All routes except `/health`, `/auth/*`, and `/auth/config` require a
session cookie (`sid`). Reads are scoped to the caller's project
membership; writes go through `/ops` with per-op `project_scope`
authorization.

| route                              | method | what                                                  |
|------------------------------------|--------|-------------------------------------------------------|
| `/health`                          | GET    | liveness                                              |
| `/auth/config`                     | GET    | `{ dev_auth }` — gates the dev-seed button on the SPA |
| `/auth/google/login`               | GET    | start Google OAuth (state cookie + consent redirect)  |
| `/auth/google/callback`            | GET    | OAuth callback, upserts user, sets `sid`              |
| `/auth/logout`                     | POST   | drop session row + cookie                             |
| `/auth/dev-login?email=…`          | GET    | dev bypass when `DEV_AUTH=1`                          |
| `/auth/dev-seed`                   | POST   | wipe + reseed fixture, sign in as Maya (`DEV_AUTH=1`) |
| `/me`                              | GET    | the authenticated user (or 401)                       |
| `/bootstrap`                       | GET    | one-shot hydrate, scoped, plus the change-log cursor  |
| `/users`                           | GET    | directory listing for the project members picker      |
| `/projects`                        | POST   | create a project (caller becomes owner + member)      |
| `/projects/:id`                    | PATCH  | update title / icon / color / `external_url_template` (three-state nullable) |
| `/projects/:id/members`            | PUT    | replace the member set; owner force-added; soft-deletes others |
| `/ops`                             | POST   | push outbox ops, idempotent per `op_id`, per-op tx    |
| `/changes?since=N`                 | GET    | pull change feed, scope-filtered, ≤ 500 rows          |

**What `/bootstrap` returns** (all keys non-null arrays except `cursor`):
```ts
{ users, projects, epics, sprints, tasks, blocks, gcal, cursor }
```

`cursor` is the current `MAX(seq)` from `processed_ops`. Fresh clients
start polling `/changes` from there, not from 0. The shape otherwise
mirrors `web/src/types.ts`; no pagination, no filtering — the dataset
is small enough to send in one shot.

**Op kinds accepted by `/ops`** (16):
`task.create`, `task.tick`, `task.set_section`, `task.set_title`,
`task.set_description`, `task.set_estimate`, `task.set_assignee`,
`task.set_status`, `task.set_priority`, `task.set_external_id`,
`task.reorder`, `subtask.create`, `subtask.tick`, `block.create`,
`block.update`, `block.delete`. Project mutations (`POST /projects`,
`PATCH /projects/:id`, `PUT /projects/:id/members`) write synthesized
`project.create` / `project.update` / `project.set_members` rows onto
the same log so peer clients converge through one apply path.

Real-time push (SSE / websocket) is still deferred — propagation
latency is the 2 s poll cadence today.

## 5. Time anchoring

The fixture is reproducible, not live. **Mon Apr 27 2026 00:00 PT** is
hardcoded as the visible week's start; **Wed Apr 29 2026** is "today". The
seeder writes timestamps in UTC (PDT = UTC-7) and the web client converts
back via [web/src/time.ts](../web/src/time.ts).

When real users land, this anchoring goes away — the calendar will compute
the visible week from `Date.now()` in the user's TZ.

## 6. Outbox / sync seam

Every store mutation in [web/src/store/index.ts](../web/src/store/index.ts)
appends an `Op` to `state.outbox`. Op shape is **intent**, not diff:
`{ kind: 'task.tick', task_id, done: true }` rather than
`subtasks[2].done = true`. This matches Linear/Replicache and survives
concurrent edits better than diff replay.

The full op-kind list is in §4. Both push and pull use the same shapes;
`applyRemoteOp` runs ops returned by `/changes` through the same handlers
as local mutations.

**Push.** `syncOutbox()` runs every 2 s (and on `focus`/`online`):

- Bails if a sync is in flight (re-entrant safe).
- Picks up to 50 queued ops, marks them `syncing`, POSTs to `/ops`.
- On per-op `ok`: drops the op from the outbox; the op's `op_id` was
  already added to `appliedOpIds` at enqueue time so the echo via
  `/changes` is suppressed.
- On per-op `error`: flips the op to `error` (kept for visibility),
  records the first error message in `syncStatus`.
- On network failure: reverts the batch to `queued`, flips
  `syncStatus` to `offline`, retries on the next tick.

**Pull.** `pollChanges()` runs after every push:

- Hits `/changes?since=cursor`.
- For each returned op: skip if `op_id ∈ appliedOpIds` (it's our own
  echo); otherwise dispatch through `applyRemoteOp`.
- Advances `cursor` to the response's high-water mark.
- GCs `appliedOpIds` entries older than 5 min.

**Server invariants.** `processed_ops` is the single source of truth
for both idempotency (PK on `op_id`) and the change feed (monotonic
`seq BIGSERIAL`). Per-op transactions: a stale `task_id` in op #3
doesn't poison ops #1, #2, #4. The wire payload is stored verbatim
as `JSONB` so peer clients replay it through the same handlers
without a re-encode.

**Conflict policy today is last-write-wins on intent.** With set-shaped
ops (`set_title`, `set_section`) that's almost always right — the user
who typed later expressed the more recent intent. Divergence display
for genuinely concurrent typing is future work.

## 7. UI — what's implemented

**Login** ([web/src/components/Login.tsx](../web/src/components/Login.tsx)):
- Rendered when `/me` returns 401. Editorial layout: stacked
  time-block mark + Instrument Serif "Fira" wordmark + tagline +
  "Continue with Google" button.
- When `/auth/config` reports `dev_auth: true`, a dashed-bordered
  "Seed dev data & sign in" button renders below — wipes the DB,
  reseeds the fixture, drops a Maya session cookie, hard-reloads.

**Sidebar + TopBar.** Project switcher with a `+` button to open
`ProjectModal`. TopBar shows the user avatar, a `Log out` button, and
the sync pill (Lucide icon-toned: `Synced` / `N pending` / `Syncing…` /
`Offline` / `Error · N`). Click the pill to force a tick.

**Calendar view** ([web/src/components/CalendarView.tsx](../web/src/components/CalendarView.tsx)):
- Weekly Mon–Sun grid, 24h scroll, hour height = 56px.
- Blocks render with project color, completed = solid + strikethrough.
- Overlap layout: blocks split width into lanes per-day.
- GCal events render as dashed muted rectangles behind blocks.
- "Now line" on today (Wed).
- Person switcher in the head — pin/unpin teammates, toggle which person's
  week is rendered. `block.user_id` is whose calendar the block lives on,
  independent of `task.assignee_id`.
- Right rail: schedulable tasks for the active project filter, with
  silent-blocker dot, **Mine/All toggle** (All shows every project task,
  non-yours dimmed and prefixed with `↗`), **title filter** (matches
  title or `external_id`).
- **Drag from rail onto a day column** to create a block (`block.create`).
- **Drag-to-move blocks** across days/times (`block.update`).
- **Drag-resize from the top or bottom edge** of a block (`block.update`).
- Double-click a block → toggle complete. Single click → opens task modal.

**Inbox view** ([web/src/components/InboxView.tsx](../web/src/components/InboxView.tsx)):
- Per-project document. Project switcher in left sidebar.
- Now / Later / Done sections (Recurring not yet). Now is grouped by
  assignee when the project has >1 member; the caller's group floats to
  the top. "(you)" is keyed off `meId`, no longer hardcoded to Maya.
- Drag a task between sections (`task.set_section`); drag onto an
  assignee subsection in Now also reassigns (`task.set_assignee`).
- Tick task or subtask to toggle done; `Archive done` button bulk-moves
  ticked Now tasks into Done.
- Click row → task modal. New-task button opens `TaskModalDraft`.

**Task modal** ([web/src/components/TaskModal.tsx](../web/src/components/TaskModal.tsx)):
- Title, description, subtask checkboxes, time-block history with the
  block-owner avatar (`data-me` highlights yours).
- Right side: project, assignee, status, priority, estimate, time-left,
  tags, source, section, **Issue link** (renders `[external_id]` as a
  link when the project has an `external_url_template`, muted text
  otherwise; pencil icon arms the editor).
- Estimate bar showing spent / planned / left.

**Project modal** ([web/src/components/ProjectModal.tsx](../web/src/components/ProjectModal.tsx)):
- Create or edit: title, Lucide icon picker, color swatches, issue
  URL template (`{key}` placeholder, validated as `http(s)://…` ≤ 512 chars).
- Members section: search popover to add (one click, auto-closes);
  two-step remove (× chip → red Remove button) since losing access is
  heavier than gaining it. Owner is force-added server-side.

**Not yet:**
- Drag-to-create on calendar grid (free-draw a block on empty space)
- Inline editing of title / estimate in the inbox row (modal works)
- Filter chips (epic / sprint / status) on the inbox toolbar
- Compare mode (two people side-by-side)
- Date scope on inbox (today / this week / a date)
- Recurring section + template / instance model
- Snapshots / replay
- Real Jira / Notion / GCal write-back (only manual issue links exist)
- SSE / websocket push (today is a 2 s poll)

## 8. Build / dev

See [README.md](../README.md). Quickstart:

```bash
docker compose up -d postgres
docker compose up --build api web
docker compose exec api cargo run --bin seed
# open http://localhost:5173
```

Postgres on `:5432`, API on `:3000`, web on `:5173`. The web dev server
proxies `/api/*` to the api service via `VITE_API_PROXY_TARGET` (set to
`http://api:3000` in compose).

## 9. Out of scope for this iteration

Stated up front so future me doesn't speculate:
- Sync to Jira / Notion / GCal (write-back, status pull, calendar
  ingest). Manual `external_id` links exist; automated sync doesn't.
- Snapshots / replay UI.
- Recurring task templates + per-cycle instances.
- Mobile / responsive.
- Real-time push (SSE / websocket). Today's collaboration runs on a
  2 s `/changes` poll — fine for a handful of users, will need
  upgrading once the user count justifies it.
- Conflict-divergence UI. Today is last-write-wins on intent ops.
- Op-log compaction / archival of `processed_ops`.
- Per-user rate limit on `/ops`.
- Standalone test suite (smoke verified manually).
- Production-ready deploys (Docker compose targets dev, not prod).
  Fly.io is the planned target.
