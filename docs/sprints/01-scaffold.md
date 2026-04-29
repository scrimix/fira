# Sprint 01 — Scaffold

**Status:** done
**Date:** 2026-04-29

## Goal

Translate the prototype (single-file React + inline mock data) into a real
project: containerized stack, Rust API, Postgres schema with migrations and
a seeder, React/TS frontend that reads live data from the API. Mutations
stay in-memory client-side — no write endpoints yet.

## What shipped

### Infrastructure
- [docker-compose.yml](../../docker-compose.yml) with three services: `postgres`
  (with healthcheck), `api` (cargo-watch), `web` (Vite dev server).
- [api/Dockerfile](../../api/Dockerfile) — Rust 1.x slim-bookworm + cargo-watch.
- [web/Dockerfile](../../web/Dockerfile) — Node 22 + pnpm 9 via corepack.
- `.env.example`, `.gitignore`.

### Postgres schema ([api/migrations/0001_init.sql](../../api/migrations/0001_init.sql))
Trimmed deliberately from the design doc. Tables:
- `users`, `projects`, `project_members`
- `epics`, `sprints`
- `tasks`, `subtasks`
- `time_blocks` (with `start_at`/`end_at` as `timestamptz`)
- `gcal_events`

Dropped vs. design doc §4: `integration_tokens`, `snapshots`,
`sync_state`/`raw_payload`/`source_updated_at` machinery,
`recurring_parent_id`, `task_type`, `parent_task_id`. None of these are used
by the current UI; cheaper to add back when a feature requires them than to
maintain dead columns.

### Rust API ([api/src/](../../api/src/))
Axum 0.7 + sqlx 0.8 + tokio. Auto-runs `sqlx::migrate!` on startup. Read-only
endpoints:
- `GET /health`
- `GET /bootstrap` — single hydration payload (all collections in one shot)
- `GET /users`, `/projects`, `/epics`, `/sprints`, `/tasks`, `/blocks`, `/gcal`

The `Project.members` and `Task.subtasks` fields use `#[sqlx(skip)]` and are
populated in two passes (main row, then a separate query joined in Rust)
rather than via SQL JOINs returning JSON aggregates. Simpler and the data
volume is small.

### Seeder ([api/src/bin/seed.rs](../../api/src/bin/seed.rs))
Separate `cargo run --bin seed` binary. Reproduces the prototype fixture:
4 users, 3 projects (Atlas/Relay/Helix), 7 epics, 5 sprints, 21 tasks, 13
subtasks, 22 time blocks, 6 GCal events. IDs are deterministic UUID-v5
derived from slugs ("u_maya", "t_atlas_oauth") so reseeding is stable.

Time-block timestamps are anchored to **Mon Apr 27 2026 00:00 PT**
(= 2026-04-27T07:00:00Z). The frontend uses the same anchor when rendering
the grid.

### Web app ([web/](../../web/))

Stack:
- **Vite 5** + **React 18** + **TypeScript**
- **Zustand 5** for the local store
- **pnpm** as package manager
- No data-fetching library — `fetch` directly, called from store actions

Files:
- [web/src/types.ts](../../web/src/types.ts) — TS shapes mirroring the API
- [web/src/api.ts](../../web/src/api.ts) — fetch wrapper (always `/api/...`, proxied)
- [web/src/store/index.ts](../../web/src/store/index.ts) — Zustand store with hydrate + mutation actions
- [web/src/store/outbox.ts](../../web/src/store/outbox.ts) — Op shape + factory
- [web/src/time.ts](../../web/src/time.ts) — timestamp ↔ grid coords + estimate math
- [web/src/components/](../../web/src/components/) — Sidebar, TopBar, CalendarView, InboxView, TaskModal

Vite dev server proxies `/api/*` to the api service. Browser always sees
same-origin URLs. The proxy target is `VITE_API_PROXY_TARGET=http://api:3000`
in compose, falling back to `http://localhost:3000` for host-only dev.

### Local-first store + outbox

Every store mutation:
1. Updates local state synchronously (UI is instant).
2. Appends an `Op` to `state.outbox`. Op kind is intent (`task.tick`), not
   diff (`subtasks[2].done = true`).

Op kinds defined: `task.tick`, `task.set_section`, `task.set_title`,
`task.set_description`, `subtask.tick`, `block.create`, `block.update`,
`block.delete`.

The sync worker that drains the outbox is **not yet implemented**. Ops
accumulate; the TopBar shows `outbox: N` while there are queued ops so the
seam is visible during demos.

## Decisions worth keeping

- **Store-as-truth, outbox-as-log** is the right shape, not TanStack Query.
  Documented this in [docs/spec.md §2](../spec.md#2-architecture).
- **Trim the schema first**. Dropping `integration_tokens`, `snapshots`,
  `recurring_parent_id` etc. saved meaningful boilerplate in models, db
  layer, seeder, and TS types. Adding columns later is cheap.
- **Fixture week is hardcoded**. The whole stack treats Apr 27 2026 as the
  visible week and Wed Apr 29 as "today". Easier to demo, easier to test;
  delete this anchor when real users sign in.
- **Two passes for nested data, not JSON aggregates**. Keeps queries
  readable; small dataset means N+1 doesn't matter at this stage.

## Things that bit us

- Pinned Rust 1.83 was too old — modern crates require 1.85+. Switched to
  `rust:1-slim-bookworm`.
- `Uuid::new_v5` is gated behind the `v5` feature flag; default crate
  install only enables `v4`.
- `#[sqlx(default)]` doesn't suppress the `PgHasArrayType` requirement when
  the field type is a Vec of a custom struct. Use `#[sqlx(skip)]` instead.
- Two binaries in one Cargo crate need `default-run` set, otherwise
  `cargo run` fails ambiguously.
- Vite dev proxy target must be the docker service name (`http://api:3000`),
  not `localhost` — `localhost` inside the web container is the web
  container itself.

## What's deferred

Listed in [docs/spec.md §7 / §9](../spec.md#7-ui--whats-implemented):
- Drag-to-create / resize blocks on calendar
- Drag from rail onto grid
- Inline title editing in inbox
- Filter chips on inbox toolbar
- Compare mode (two-person calendar)
- Person switcher
- Date scope on inbox
- Recurring tasks
- Snapshots / replay
- Real auth + sync (Jira / Notion / GCal)
- Write endpoints + sync worker

## Verification

End-to-end smoke from this sprint:

```
$ docker compose up -d postgres
$ docker compose up --build api web
$ docker compose exec api cargo run --bin seed
seed: done

$ curl -s http://localhost:3000/bootstrap | jq '.tasks | length'
21
$ curl -s http://localhost:5173/api/health
ok
$ docker compose run --rm web pnpm typecheck
[no errors]
```

## Next sprint candidates

In rough order of value:

1. **Write endpoints + sync worker** — wire the outbox to the server so
   mutations persist. Smallest scope: PATCH `/tasks/:id`, PATCH `/blocks/:id`,
   POST `/blocks`, DELETE `/blocks/:id`. Worker drains FIFO, retries on
   failure, surfaces conflicts.
2. **Drag-to-create blocks on calendar grid** — the highest-leverage missing
   interaction. Needs the new POST `/blocks` endpoint from #1.
3. **Inline editing in inbox** — title and subtask edits inline. Already
   have `task.set_title` / `subtask.tick` ops.
4. **Inbox filter chips** — project/epic/sprint/status. Pure UI; the data
   is already there.
5. **Person switcher on calendar** — required before multi-user means
   anything; needs auth first to be more than cosmetic.
