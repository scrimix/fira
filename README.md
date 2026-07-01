# Fira

Task management app — calendar-first, time-block as the unit of plan.
Live at <https://usefira.app>.

A **time block** is a discrete scheduled work session attached to a
real task on a real day. Most tasks don't finish in one block, so a
task is a thing that *accrues* blocks across the week. The plan is the
set of blocks on the calendar; reality is the set marked complete.
That's the architectural feature current task tools don't have.

The product is two screens over a single shared task model:

- **Inbox** — a sectioned document (Now / Later / Done), per project.
  Capture, prioritize by manual ordering, group by assignee for shared
  projects. Not a board.
- **Calendar** — your week colored by project. Drag a task from the
  rail onto a day to create a block, drag to move/resize, tick button
  on each block to mark it complete. Teammates' blocks visible when
  you switch to their tab.

The user we optimize for is a senior IC split across 3–5 projects, who
needs to see their *own* week colored by project. Standup behavior
comes free from the same data: scrub the inbox by date, see who
finished what.

This repo is Postgres + Rust API + React/TS web app.

## Architecture

```
┌──────────────┐  GET /api/bootstrap (initial hydrate)  ┌──────────────┐    sqlx    ┌──────────┐
│  web (Vite)  │ ─────────────────────────────────────▶ │  api (Axum)  │ ─────────▶ │ postgres │
│  React + TS  │  POST /api/ops      (push outbox)      │  Rust 1.x    │            │   16     │
│  Zustand     │  GET  /api/changes  (pull change feed) │              │            │          │
│              │  WS   /api/ws       (real-time nudges) │              │            │          │
└──────────────┘ ◀───────────────────────────────────── └──────────────┘            └──────────┘
```

The web app is **local-first** with a closed round-trip:

- **Hydrate** once from `/api/bootstrap` (scoped to the active
  workspace), which also returns the current change-log cursor.
- **Mutate** locally — every drag, tick, retype updates the in-memory
  store synchronously and appends an intent-shaped op to the outbox.
- **Push** every 2 s (and on `focus`/`online`): a sync worker batches
  queued ops to `POST /api/ops`. The server applies each in its own
  transaction, idempotent on `op_id` via the `processed_ops` table.
- **Pull on nudge**: when a write commits, the server
  issues `pg_notify('ops_changes', '<workspace>:<seq>')` from inside
  the same transaction. A per-process `PgListener` fans out to local
  WS clients via an in-process `Hub`. The client's `/api/ws` socket
  triggers the existing `syncOutbox().then(pollChanges)` path on every
  nudge. A 60 s `/api/changes` poll is the missed-nudge fallback.
  Echoes of the client's own writes are suppressed via an
  `appliedOpIds` set with a 5-minute TTL.
- **Attachments**: with introduction of attachments, the architecture changed
  a bit because files are no longer simple text edit for the data
  and the operations happen more like traditional request / response.

### VS Code devcontainer

Open the repo in VS Code and "Reopen in Container". `.devcontainer/`
provisions a shell that shares the compose network with postgres, so
`psql -h postgres` works from inside. The post-start hook waits for
postgres and runs migrations on first boot.

Inside the devcontainer shell:

```bash
# api (terminal 1) — listens on :3000
cd api
cargo run --bin seed       # one-time, populates fixture data
cargo run                  # dev loop

# web (terminal 2) — listens on :5173, proxies /api/* to :3000
cd web
pnpm install               # one-time
pnpm dev --host
```

Then open <http://localhost:5173>

To wipe and reseed the database: `cargo run --bin seed -- --drop`.

### Using local RustFS S3 storage

Open the console using `http://localhost:9001` and create a bucket called fira, using credentials from `docker-compose.dev.yml`.
Change the `STORAGE_BACKEND` in `docker-compose.dev.yml` file to `s3` and Rebuild Container.

### Multi-instance WS test rig (sprint 10)

To verify cross-machine WS nudges over `pg_notify`:

```bash
# api 1 (terminal 1)
cd api && cargo run

# api 2 (terminal 2) — same Postgres, port :3001
./scripts/dev-second-api.sh

# web 1 (terminal 3) — Vite :5173 → API :3000
cd web && pnpm dev

# web 2 (terminal 4) — Vite :5174 → API :3001
cd web && pnpm dev:second
```

Open one tab per Vite. Edit in tab 1 → tab 2's WS receives the nudge
via Postgres NOTIFY crossing the instance boundary.

## Contact

- **Bugs and feature requests** — open a [GitHub issue](../../issues).
- **Security vulnerabilities** — see [SECURITY.md](SECURITY.md); please
  don't file them as public issues.
- **Everything else** (questions, hosting your own copy, saying hi) —
  email <scrimix@gmail.com>.

## License

[MIT](LICENSE) © Rihard Grickus — fork it, host it, modify it for your
team's needs. If you build something on top of Fira, a "Based on Fira"
link in your footer or about page would be appreciated, but it's a
thank-you, not a requirement.
