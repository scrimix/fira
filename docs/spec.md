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
┌──────────────┐    GET /bootstrap     ┌──────────────┐    sqlx    ┌──────────┐
│  web (Vite)  │ ────────────────────▶ │  api (Axum)  │ ─────────▶ │ postgres │
│  React + TS  │                       │  Rust 1.x    │            │   16     │
│  Zustand     │                       │              │            │          │
└──────────────┘                       └──────────────┘            └──────────┘
       │
       │  mutations are local-only (for now)
       ▼
   in-memory store + outbox queue (sync worker is a stub)
```

**Local-first**: the web app hydrates once from `/bootstrap`, then every
mutation updates the in-memory store synchronously *and* appends an op to an
outbox. A sync worker (not yet wired) drains the outbox to the server when
write endpoints exist. The TopBar shows `outbox: N` while ops are queued so
the seam is visible.

**Why not TanStack Query**: this isn't CRUD with occasional optimistic
updates — every drag, tick, retype is a mutation. A request-per-keystroke
model is the wrong shape. The Linear/Replicache pattern of "local store as
source of truth, outbox as audit log" composes; per-mutation `useMutation`
hooks don't.

## 3. Data model — current

Authoritative SQL: [api/migrations/0001_init.sql](../api/migrations/0001_init.sql).

Trimmed deliberately from the design doc. Add columns when a feature needs
them, not in anticipation.

| table             | purpose                                            |
|-------------------|----------------------------------------------------|
| `users`           | identity. No auth yet — Maya Chen is the seeded "me". |
| `projects`        | id, title, color, source (`local`/`jira`/`notion`). |
| `project_members` | M:N user↔project.                                  |
| `epics`           | unit of work bigger than a task, smaller than a project. |
| `sprints`         | time-boxed; `active` flag drives the inbox's sprint filter. |
| `tasks`           | section (`now`/`later`/`done`), status, estimate, assignee, sort_key. |
| `subtasks`        | flat under a task. The "checkbox tree in a description" doesn't exist yet — subtasks are first-class rows. |
| `time_blocks`     | start_at, end_at, state (`planned`/`completed`/`skipped`). |
| `gcal_events`     | dashed/muted background events, no task linkage.   |

**Things in the design doc that are NOT in the schema yet:**
- `recurring` section + `task_type` (`regular`/`recurring`/`instance`) +
  `recurring_parent_id` — no fixture uses them.
- `sync_state`, `source_updated_at`, `last_synced_at`, `raw_payload`,
  `external_workspace`, `external_url`, `section_history` — no write-back.
- `integration_tokens`, OAuth — no auth/sync.
- `snapshots` — no replay UI.

## 4. API — current

All read-only. Writes happen on the client, queued in the outbox.

| route             | what                                                  |
|-------------------|-------------------------------------------------------|
| `GET /health`     | liveness                                              |
| `GET /bootstrap`  | one-shot hydration: users, projects, epics, sprints, tasks (with subtasks), blocks, gcal |
| `GET /users`      | list                                                  |
| `GET /projects`   | list (with members[])                                 |
| `GET /epics`      | list                                                  |
| `GET /sprints`    | list                                                  |
| `GET /tasks`      | list (with subtasks[])                                |
| `GET /blocks`     | list                                                  |
| `GET /gcal`       | list                                                  |

**What `/bootstrap` returns** (all keys non-null arrays):
```ts
{ users, projects, epics, sprints, tasks, blocks, gcal }
```

The shape mirrors `web/src/types.ts` exactly. No pagination, no filtering;
the dataset is small enough to send in one shot. Multi-user world will
require user-scoped filters and real-time push (SSE/websocket); deferred.

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

Op kinds defined today:
- `task.tick`, `task.set_section`, `task.set_title`, `task.set_description`
- `subtask.tick`
- `block.create`, `block.update`, `block.delete`

When write endpoints land, a worker (Web Worker or simple `setInterval`)
drains queued ops in order, marks them `syncing` → `synced` → discard.
Server uses `op_id` for idempotency.

## 7. UI — what's implemented

**Calendar view** ([web/src/components/CalendarView.tsx](../web/src/components/CalendarView.tsx)):
- Weekly Mon–Sun grid, 24h scroll, hour height = 56px.
- Blocks render with project color, completed = solid + strikethrough.
- Overlap layout: blocks split width into lanes per-day.
- GCal events render as dashed muted rectangles behind blocks.
- "Now line" on today (Wed).
- Left rail: project filter with toggle, week totals (done / planned / total).
- Right rail: schedulable tasks grouped by project, with silent-blocker dot.
- Click block → opens task modal. Double-click → toggle complete (queues op).

**Inbox view** ([web/src/components/InboxView.tsx](../web/src/components/InboxView.tsx)):
- Per-project document. Project switcher in left sidebar.
- Now / Later / Done sections. Now is grouped by assignee when project has >1 member.
- Drag a task between sections (queues `task.set_section` op).
- Tick task or subtask to toggle done (queues op).
- Click row → task modal.

**Task modal** ([web/src/components/TaskModal.tsx](../web/src/components/TaskModal.tsx)):
- Title, description, subtask checkboxes, time-block history.
- Right side: project, assignee, status, priority, estimate, time-left, tags, source, section.
- Estimate bar showing spent / planned / left.

**Not yet:**
- Drag-to-create blocks on calendar grid
- Resize blocks
- Drag from rail onto grid
- Inline-editing of titles in inbox (modal works, inline doesn't)
- Filter chips (project/epic/sprint/status) on inbox toolbar
- Compare mode (two people side-by-side)
- Person switcher in calendar (always shows "me")
- Date scope on inbox (today / this week / a date)
- Snapshots / replay
- Recurring tasks
- Auth

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
- Real auth (Google sign-in or otherwise)
- Sync to Jira / Notion / GCal
- Snapshots / replay UI
- Recurring task templates
- Mobile / responsive
- Real-time collaboration
- Standalone test suite (smoke verified manually)
- Production-ready deploys (Docker compose targets dev, not prod)
