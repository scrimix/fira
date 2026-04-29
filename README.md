# Fira

Task management app — calendar-first, time-block as the unit of plan.

This repo is the v1 scaffold: Postgres + Rust API + React/TS web app.

## Architecture

```
┌──────────────┐    GET /bootstrap    ┌──────────────┐    sqlx    ┌──────────┐
│  web (Vite)  │ ───────────────────▶ │  api (Axum)  │ ─────────▶ │ postgres │
│  React + TS  │                      │  Rust 1.83   │            │   16     │
│  Zustand     │                      │              │            │          │
└──────────────┘                      └──────────────┘            └──────────┘
       │
       │  mutations are local-only for now
       ▼
   in-memory store + outbox queue (sync worker is a stub)
```

The web app is **local-first**: hydrate once from `/bootstrap`, then every
mutation updates the in-memory store synchronously and appends an op to an
outbox. A sync worker drains the outbox to the server. The worker isn't
wired up in v1 — ops accumulate locally — but the seam is in place so
adding write endpoints later is a one-place change.

## Layout

```
fira/
├── docker-compose.yml      # postgres + api + web
├── api/                    # Rust + Axum + sqlx
│   ├── migrations/         # SQL migrations (sqlx::migrate!)
│   └── src/
│       ├── main.rs         # API server
│       ├── bin/seed.rs     # seeder binary
│       ├── db.rs           # query layer
│       ├── models.rs       # serde + sqlx structs
│       └── error.rs
├── web/                    # React + Vite + TS
│   └── src/
│       ├── App.tsx
│       ├── api.ts          # fetch wrappers
│       ├── store/          # Zustand store + outbox
│       ├── time.ts         # grid <-> timestamp helpers
│       ├── components/
│       └── styles/
└── docs/                   # design docs
```

## Quick start

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

| route          | what                               |
|----------------|------------------------------------|
| `GET /health`  | liveness                           |
| `GET /bootstrap` | one-shot hydration: everything the UI needs |
| `GET /users`   | list                               |
| `GET /projects` | list (with members)               |
| `GET /epics`   | list                               |
| `GET /sprints` | list                               |
| `GET /tasks`   | list (with subtasks)               |
| `GET /blocks`  | list                               |
| `GET /gcal`    | list                               |

All read-only. Writes go through the in-memory store on the client.

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

## What's not here yet

- Write endpoints (POST/PATCH). Outbox ops accumulate; a worker will
  drain them once endpoints exist.
- Sync to Jira / Notion / GCal — only the columns are present.
- Auth — there's no login; the seeded "Maya Chen" is treated as the
  current user.
- Snapshot capture and replay.
- Recurring tasks, drag-resize on calendar blocks, real estimate UI on
  the inbox row, compare mode. Pieces of these exist in
  [docs/fira_design_doc.md](docs/fira_design_doc.md) and aren't blocked
  by the data layer.
