# Fira

Task management app — calendar-first, time-block as the unit of plan.

This repo is the v1 scaffold: Postgres + Rust API + React/TS web app.

## Architecture

```
┌──────────────┐  GET /bootstrap (initial hydrate)  ┌──────────────┐    sqlx    ┌──────────┐
│  web (Vite)  │ ─────────────────────────────────▶ │  api (Axum)  │ ─────────▶ │ postgres │
│  React + TS  │  POST /ops      (push outbox)      │  Rust 1.x    │            │   16     │
│  Zustand     │  GET  /changes  (pull change feed) │              │            │          │
└──────────────┘ ◀───────────────────────────────── └──────────────┘            └──────────┘
```

The web app is **local-first** with a closed round-trip:

- **Hydrate** once from `/bootstrap` (scoped to the signed-in user's
  projects), which also returns the current change-log cursor.
- **Mutate** locally — every drag, tick, retype updates the in-memory
  store synchronously and appends an intent-shaped op to the outbox.
- **Push** every 2 s (and on `focus`/`online`): a sync worker batches
  queued ops to `POST /ops`. The server applies each in its own
  transaction, idempotent on `op_id` via the `processed_ops` table.
- **Pull** every 2 s: `GET /changes?since=cursor` returns ops from
  other tabs / teammates, filtered to the caller's project scope.
  Echoes of the client's own writes are suppressed via an
  `appliedOpIds` set with a 5-minute TTL.

The TopBar pill (`Synced` / `N pending` / `Syncing…` / `Offline` /
`Error · N`) makes the sync state visible. Click it to force a tick.

Project create / edit / membership changes also run through the log
(synthesized `project.create`, `project.update`, `project.set_members`
ops) so peers converge through the same path as task ops.

## Layout

```
fira/
├── docker-compose.yml      # postgres + api + web
├── api/                    # Rust + Axum + sqlx
│   ├── migrations/         # SQL migrations (sqlx::migrate!)
│   └── src/
│       ├── main.rs         # API server + route table
│       ├── auth.rs         # Google OAuth, sessions, dev-login, dev-seed
│       ├── ops.rs          # POST /ops + GET /changes (push + pull)
│       ├── seed.rs         # fixture data (shared by bin + dev-seed)
│       ├── bin/seed.rs     # CLI seeder wrapper
│       ├── db.rs           # query layer (scoped by project membership)
│       ├── models.rs       # serde + sqlx structs
│       └── error.rs
├── web/                    # React + Vite + TS
│   └── src/
│       ├── App.tsx
│       ├── api.ts          # fetch wrappers
│       ├── store/          # Zustand store + outbox + applyRemoteOp
│       ├── time.ts         # grid <-> timestamp helpers
│       ├── components/
│       └── styles/
└── docs/                   # design docs + sprint logs
```

## Quick start — VS Code devcontainer

Open the repo in VS Code and "Reopen in Container" — `.devcontainer/`
provisions a Rust + Node + psql shell that shares the docker network with
the api/web/postgres services, so `psql -h postgres`, `curl http://api:3000`
all work from inside the shell. The post-start hook seeds the DB on first
boot.

## Quick start — plain compose

Requires Docker (with the compose plugin).

```bash
# 1. Start Postgres + API + web (first run pulls images, ~2 min)
docker compose up -d postgres
docker compose up --build api web

# 2. In another terminal, seed the database (once)
docker compose exec api cargo run --bin seed
```

Then open <http://localhost:5173>.

The web app proxies `/api/*` to the Rust API at `:3000`. Postgres listens on
`:5432` (user/pass/db all `fira`).

## Local dev (no docker)

If you'd rather run the toolchains on the host:

```bash
# postgres still in docker for convenience
docker compose up -d postgres

# api
cd api
cargo run --bin seed       # one-time
cargo watch -x run         # dev loop

# web (separate terminal)
cd web
pnpm install
pnpm dev
```

## API

All routes except `/health`, `/auth/*`, and `/auth/config` require a
session cookie (`sid`). Writes are scoped by project membership — a user
can never mutate or read a project they aren't a member or owner of.

| route                              | method | what                                                  |
|------------------------------------|--------|-------------------------------------------------------|
| `/health`                          | GET    | liveness                                              |
| `/auth/config`                     | GET    | `{ dev_auth }` so the SPA can render the dev button   |
| `/auth/google/login`               | GET    | start Google OAuth (state cookie + consent redirect)  |
| `/auth/google/callback`            | GET    | OAuth callback, upserts user, sets `sid`              |
| `/auth/logout`                     | POST   | drop session row + cookie                             |
| `/auth/dev-login?email=…`          | GET    | bypass auth in dev (`DEV_AUTH=1`)                     |
| `/auth/dev-seed`                   | POST   | wipe + reseed fixture, sign in as Maya (`DEV_AUTH=1`) |
| `/me`                              | GET    | the authenticated user (or 401)                       |
| `/bootstrap`                       | GET    | one-shot hydrate: users, projects, epics, sprints, tasks (+subtasks), blocks, gcal, **plus the change-log cursor** |
| `/users`                           | GET    | directory listing for the project members picker      |
| `/projects`                        | POST   | create a project (caller becomes owner + member)      |
| `/projects/:id`                    | PATCH  | update title / icon / color / external URL template   |
| `/projects/:id/members`            | PUT    | replace the project's member set (soft-deletes others) |
| `/ops`                             | POST   | push a batch of outbox ops, idempotent on `op_id`     |
| `/changes?since=N`                 | GET    | pull the change feed (up to 500 ops, scope-filtered)  |

The 16 op kinds accepted by `/ops` are: `task.create`, `task.tick`,
`task.set_section`, `task.set_title`, `task.set_description`,
`task.set_estimate`, `task.set_assignee`, `task.set_status`,
`task.set_priority`, `task.set_external_id`, `task.reorder`,
`subtask.create`, `subtask.tick`, `block.create`, `block.update`,
`block.delete`. Project mutations log synthesized `project.create`,
`project.update`, `project.set_members` ops onto the same feed so peer
clients converge through one apply path.

## Spec & sprint logs

- [docs/spec.md](docs/spec.md) — current contract for what's actually built
- [docs/sprints/](docs/sprints/) — what each sprint shipped, with decisions

## Data model

See [api/migrations/0001_init.sql](api/migrations/0001_init.sql).

The seeder ([api/src/bin/seed.rs](api/src/bin/seed.rs)) reproduces the
fixture from the original prototype: 4 users, 3 projects, 22 tasks, 22
time blocks, a few GCal events. IDs are deterministic UUID-v5 derived
from slugs so re-seeding is stable.

The fixture week is anchored to **Mon Apr 27 2026 00:00 PT**; "today" in
the UI is **Wed Apr 29**. This is hardcoded so the seed is reproducible
regardless of wall-clock time.

## What's here

- Google OAuth + opaque server-stored sessions, with a `DEV_AUTH=1`
  bypass and a one-click "Seed dev data & sign in" button on the login
  screen.
- Per-user data scoping: bootstrap, `/changes`, and every write op are
  filtered by the caller's project membership.
- Project create + edit (title / icon / color / issue-URL template) +
  membership editor with soft-delete and a force-add of the owner.
- Closed local-first round-trip: outbox push (`POST /ops`, idempotent
  per op) and change-log pull (`GET /changes?since=N`, log row per
  accepted op via `processed_ops.seq`). Two tabs / two teammates
  converge within ~2 s without a refresh.
- Calendar with rail Mine/All toggle + title filter, teammate blocks
  visible when a teammate is the active person, drag-from-rail to
  schedule, drag-to-move blocks across days/times, drag-resize from
  top or bottom edge, click-to-toggle-complete.
- Inbox with Now / Later / Done sections, drag between sections,
  per-assignee subsections in shared projects, modal edit on click.
- Per-task issue links: free-form `external_id` rendered as a clickable
  link when the project has an `external_url_template` (with `{key}`
  placeholder), muted text otherwise.

## What's not here yet

- **Sub-second propagation.** Pull is a 2 s `setInterval`; SSE / long-poll
  is deferred until the user count justifies it.
- **Real Jira / Notion / GCal sync.** Issue *links* exist (manual
  `external_id` + project URL template), but no write-back, no status
  pull, no calendar ingest. Only the schema columns are present.
- **Snapshots / replay UI.** Daily snapshots of `{plan, estimates,
  status}` for scrubbing back through any past day — described in the
  design doc, not yet captured.
- **Recurring tasks** (template + per-cycle instance), per the design doc.
- **Drag-to-create on the grid** (free-draw a new block on empty
  space). Move + resize already work; create-from-empty doesn't yet.
- **Inline editing** of task title / estimate in the inbox row (the
  modal works, the row doesn't).
- **Compare mode** (two people side-by-side on the calendar).
- **Conflict surfacing.** Today's behavior is last-write-wins on intent
  ops, which is the right call almost always; divergence display is
  future work.
- **Op-log compaction.** Every accepted op stays forever — fine at
  current rates, will need archival eventually.

Pieces of the deferred items are described in
[docs/fira_design_doc.md](docs/fira_design_doc.md); the per-sprint
decisions live in [docs/sprints/](docs/sprints/).
