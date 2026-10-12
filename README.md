# Fira

Time, task, project, and team management — built around the work you
actually do, with Calendar and List at its core.
Live at <https://usefira.app>.

Fira brings the whole working day together: capture what comes up, break
down the work, decide what matters, distribute it across a team, schedule
time blocks, and track what gets done. Its foundation is a rich task
list connected directly to a calendar across projects and work/life
accounts. Project timelines, sprint planning, revisions, and monthly
review build on that everyday workflow.

## Calendar and List: where the work happens

**List** holds the substance of the work. Each project is a sectioned
document: Now, Later, Recurring, Someday, and Done. Capture tasks quickly,
edit them in place, order priorities, and move work between sections as
commitments change. Subtasks, tags, estimates, and assignees make the work
actionable. Filter tags together or independently to focus on the relevant
work. In shared projects, Now groups
tasks by assignee; moving a task into someone's group also assigns it.
Completion and archiving keep the active list useful while preserving
finished work.

**Task descriptions capture the information behind the work.** Keep the
brief, requirements, research, decisions, and working notes with the task,
and expand them as you learn. Markdown syntax gives that information
structure: headings, lists, links, tables, and code blocks make detailed
notes readable. Attach screenshots, documents, and other supporting files
so the context stays with the work. Descriptions and attachments help turn
a captured idea into something you or a teammate can understand and act on.

**Calendar** turns those tasks into an executable day and week. Pull work
from a searchable task rail, schedule **time blocks**, and drag or resize them
as meetings land and tasks grow. Project colors make the split between
commitments visible; overlapping blocks share the day's space. Switch
between teammates' weeks, and overlay personal time, a linked account's
schedule, and Google Calendar events to plan around the rest of life.
Moving and resizing blocks also work on touch screens. Mark time blocks
complete as you go: the same calendar holds both the intended work and
the record of time spent.

These views share the same tasks. A task's details bring together its
description, subtasks, estimate, assignee, tags, and time-block history, with
spent, planned, and remaining time visible together. The list gives a
time block its purpose; the calendar gives the task a place in real life.
Shared workspaces and projects let a team organize responsibilities and
coordinate schedules through that same workflow.

## Time management grounded in real work

A **time block** is a scheduled work session attached to a task on a real
day. Most tasks need several work sessions, each represented by a time
block; completed blocks record time spent,
and the task's estimate gives that time context. The calendar connects
intent with execution without requiring a separate time log.

Scheduling several time blocks for one task, adjusting them as work unfolds,
and seeing what remains are the core of Fira's time management. That works
across projects and work/life accounts: the commitments share your time,
even when they belong to different contexts.

## Planning and review built on that foundation

**Plan** adds a longer horizon to the tasks you already manage. Organize
workstreams into tracks, place groups of tasks in sprints across weeks
and months, and move or resize those spans as the project changes. Its
revision timeline lets you revisit earlier project structures, sprint
dates, and task membership. History is read-only and currently omits task
estimates and time blocks.

**Dashboard** adds reflection: review your monthly planned and completed
time by project and tag, and follow daily or weekly time goals.

The original ambition — capture, understand, prioritize, plan, distribute,
and review real work — now extends into project timelines and revisions.
Fira has grown into a broadly complete time and task management tool,
with its Calendar and List remaining the engine of everyday work.

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
