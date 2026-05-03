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

This repo is Postgres + Rust API + React/TS web app, scoped by
**workspace** (tenant) and project.

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
- **Pull on nudge** (sprint 10): when a write commits, the server
  issues `pg_notify('ops_changes', '<workspace>:<seq>')` from inside
  the same transaction. A per-process `PgListener` fans out to local
  WS clients via an in-process `Hub`. The client's `/api/ws` socket
  triggers the existing `syncOutbox().then(pollChanges)` path on every
  nudge. A 60 s `/api/changes` poll is the missed-nudge fallback.
  Echoes of the client's own writes are suppressed via an
  `appliedOpIds` set with a 5-minute TTL.

The TopBar pill (`Synced` / `N pending` / `Syncing…` / `Offline · N` /
`Error · N`) makes the sync state visible. Click the pill to force a
tick or open the failed-ops popover (per-op Retry / Discard, plus
header Retry all / Discard all).

Workspace, project, link, and membership mutations all run through the
same op log (synthesized `workspace.*`, `project.*` ops) so peers
converge through one apply path. Membership / role / workspace events
that *decide* who can subscribe to the workspace feed ride a separate
per-user channel (`/api/ws/user` + `pg_notify('user_changes')`) — see
sprint 13 for the chicken-and-egg this resolves.

## What's here

The foundational surface — the product as it stood by sprint 07:

- **Time blocks as first-class.** Each task accrues N blocks across
  the week. `time_blocks.user_id` is whose calendar the block lives
  on, independent of `task.assignee_id`, so a teammate scheduling on
  your behalf is a real thing.
- **Calendar view** — weekly Mon–Sun grid, blocks colored by project
  (completed = solid + strikethrough), "now line" on today, person
  switcher to view a teammate's week. Drag from the right rail to
  create, drag to move across days/times, drag-resize from the top or
  bottom edge, tick button on each block to mark it complete. Right
  rail has a Mine/All toggle and title filter so the rail stays usable
  in busy projects.
- **Inbox view** — Now / Later / Done per project, drag between
  sections, per-assignee subsections in shared projects, modal edit on
  click, bulk Archive Done.
- **Local-first round-trip.** Hydrate once from `/api/bootstrap`,
  mutate locally, push outbox to `/api/ops`, pull change feed from
  `/api/changes` — see [Architecture](#architecture). The TopBar sync
  pill makes the state visible.
- **Google OAuth + opaque server-stored sessions**, with a
  `dev_auth`-feature bypass for local dev.
- **Per-task issue links.** Free-form `external_id` rendered as a
  clickable link when the project has an `external_url_template`.

## Recent changes

The post-sprint-08 work that reshapes the surface significantly:

### Workspaces (sprint 08)

`workspaces` + `workspace_members` are the company-level tenant
boundary. Every signed-in user automatically gets one **personal
workspace** (created in the Google OAuth callback) where they're the
sole owner; they can additionally be a member of any number of
non-personal workspaces. The active workspace travels on every scoped
request as the `X-Workspace-Id` header. The TopBar breadcrumb
(`Fira / <Workspace> ⌄ / <Project> / <Title>`) opens a switcher
popover with `+ New workspace`.

**Two role axes** gate authorization:

- **Workspace**: `owner` | `member`. Workspace owners manage the
  workspace title, members, and roles, and can create/edit/delete any
  project in the workspace.
- **Project** (sprint 15): `owner` | `lead` | `member` | `inactive`.
  `owner` and `inactive` are passive — hidden from inbox assignee
  groups unless a Now task is assigned to them. Workspace owners
  auto-get `owner` on every project; only the workspace owner can
  promote to `lead`. Project leads can edit the project but not delete
  it; only workspace owners can delete projects.

A composite FK `(workspace_id, user_id) → workspace_members` on
`project_members` makes it structurally impossible to add a project
member who isn't already in the workspace.

### Account linking + personal overlay (sprint 14)

A person owns one timeline. Two opt-in, read-only overlays expose
calendar items the user owns but that aren't in the active workspace:

- **Account linking** (`user_links` table). Type a partner's email,
  they accept once, and a paired identity chip appears in the topbar
  (your initials → `Link` icon → their initials). Their blocks render
  on your calendar with a dashed border at 0.55 opacity. Cross-account
  by design — linking is consent between two account owners, no shared
  workspace required. A partial unique index enforces "one accepted
  link per user" in the database. Pending requests pop a sticky modal
  driven from the persisted row, so it survives refresh / new tabs and
  only clears when the receiver accepts or declines.
- **Personal-workspace overlay**. Inside a single account: when you're
  in a team workspace, toggle "Show personal" to project your personal
  workspace's blocks onto the team calendar. Same `LinkedTask`
  projection as account linking, but with a left project-color stripe
  at 0.7 opacity so the two overlays don't mush together visually.

Both overlays are read-only — no drag, no write-back, no ID-collision
risk against the live `tasks` array. Cross-workspace nudges ride the
per-user channel (`Hub::notify_user`) so the partner refreshes even
when looking at a different workspace.

### Mobile + PWA (sprints 15–18)

Fira runs on a phone. The desktop surface is untouched; phone-width
overrides reshape the same component tree:

- **3-day calendar** centered on today, with single-day prev/next
  stepping and an independent `dayOffset` cursor so the desktop and
  mobile time cursors don't fight.
- **Slide-over sidebar** behind a hamburger in the topbar; the 56 px
  nav rail is hidden on phones.
- **Inbox row decluttered to grip · check · title** — tags,
  `external_id`, "Xh over" all hidden at phone widths.
- **Touch drag end-to-end** via the hybrid pattern (pointer events for
  state, document-level non-passive `touchmove` for `preventDefault`-
  suppressed scroll): inbox task + subtask reorder via the `::` grip
  or 220 ms long-press, time block move/resize, rail-task → calendar
  scheduling on tablets, calendar block tap-to-reveal-then-tap-to-open.
  The shared [`useLongPress`](web/src/useLongPress.ts) hook
  (`holdMs` / `cancelPx` / vibrate-on-lock) wraps the pattern.
- **Dynamic viewport** (`100dvh`) so inbox / calendar / modal don't
  hide under iOS Safari toolbars.
- **PWA install** — squared favicon, 32 / 180 / 192 / 512 PNGs, a
  `manifest.webmanifest`, `apple-mobile-web-app-*` meta, and
  `env(safe-area-inset-*)` padding so iOS standalone clears the
  notch.
- **`useIsMobile()`** hook for component-level branching.

### WebSocket push (sprint 10)

`pg_notify` is the cross-machine bus, a per-process `PgListener` is
the local entry point, and an in-process `Hub`
(`Mutex<HashMap<workspace_id, broadcast::Sender<seq>>>`) is the
fan-out to WS clients. Wire payload is `{"new_cursor": N}` and
nothing else — clients react by calling the existing `/api/changes`
endpoint, so the existing scope filtering, idempotency dedup, and
batching stay the single source of truth. The 2 s `/api/changes` poll
dropped to a 60 s missed-nudge fallback; `syncOutbox` stayed on 2 s
so writes still flush quickly. A 30 s server-side ping keeps Fly's
edge from idling the connection out at ~60 s.

### Playground mode (sprint 11)

"Try as Maya in your browser" on the login screen drops the user into
a fully populated workspace with no account, no backend, no network.
Same store, same components, same persist layer — just with a JS-baked
seed fed in at startup and a `playgroundMode: boolean` field gating
every network-touching action. Snapshot persists to localStorage; the
playground seed (12) is built from a frozen `bootstrap.json` dumped by
a Rust `dump-bootstrap` bin so it stays in sync with `seed.rs` without
hand-porting.

### Production deploy (sprint 09)

Single Fly.io app at <https://usefira.app> serving SPA + JSON API
same-origin under `/api/*`. Dev-only endpoints stripped via the
`dev_auth` cargo feature — they don't exist in the prod binary.

### Deletions, toasts, and sync hygiene (sprint 13)

- **Tasks / projects / workspaces** all delete through a shared
  [`ConfirmDelete`](web/src/components/ConfirmDelete.tsx). Tasks get a
  plain confirm; projects and workspaces use type-to-confirm (the user
  has to type the entity name) since the blast radius is wider.
  Personal workspaces can never be deleted.
- **`processed_ops` durability** (migration 0010): the FK cascade from
  `processed_ops` to `projects`/`workspaces` was wiping the very op
  row that announced the deletion. The migration drops both FKs;
  `workspace_id` and `project_id` are now historical pointers that may
  reference vanished entities. `/api/changes` already tolerates
  missing parents.
- **Failed-ops popover.** Server-rejected ops used to silently
  auto-retry forever. Now a single rejected op blocks the queue
  (preserves intent ordering), a toast surfaces the server's actual
  error message, and the SyncPill popover offers per-op Retry /
  Discard plus Retry all / Discard all. `hydrate()` auto-runs after
  the queue drains so discarding a failed op can't leave phantoms.
- **Reload-while-offline.** The store persists to `localStorage` via
  `zustand/middleware/persist`. `hydrate()` distinguishes 401 (clear
  cache → login), network/5xx with cached `meId` (boot from cache,
  flip to `Offline`), and network failure with no cache (error page).

## Layout

```
fira/
├── Dockerfile              # production image (web build → api build → runtime)
├── docker-compose.yml      # postgres only (api + web run from the dev shell)
├── fly.toml                # Fly.io app config
├── api/                    # Rust + Axum + sqlx
│   ├── migrations/         # 0001…0013, sqlx::migrate!
│   └── src/
│       ├── main.rs         # API server + route table (everything under /api)
│       ├── auth.rs         # Google OAuth, sessions, dev-login (dev_auth feature)
│       ├── workspaces.rs   # workspaces CRUD + role mutations + user-channel nudges
│       ├── links.rs        # user_links + linked/personal calendar overlays
│       ├── ops.rs          # POST /ops + GET /changes (push + pull)
│       ├── ws.rs           # WS handlers — workspace ops channel + per-user channel
│       ├── pubsub.rs       # Hub + PgListener for pg_notify fan-out
│       ├── seed.rs         # fixture data (shared by bin + dev-seed)
│       ├── bin/seed.rs     # CLI seeder (--drop wipes + reseeds)
│       ├── bin/dump_bootstrap.rs  # writes web/src/playground/bootstrap.json
│       ├── db.rs           # query layer (scoped by workspace + project membership)
│       ├── models.rs       # serde + sqlx structs
│       └── error.rs
├── web/                    # React + Vite + TS
│   ├── public/             # favicon, PWA icons (32/180/192/512), manifest.webmanifest
│   └── src/
│       ├── App.tsx
│       ├── api.ts          # fetch wrappers (BASE = '/api')
│       ├── ws.ts           # openNudgeSocket + openUserSocket
│       ├── store/          # Zustand store + outbox + applyRemoteOp + persist
│       ├── playground/     # JS seed + bootstrap.json (offline-only "Try as Maya")
│       ├── time.ts         # grid <-> timestamp helpers (frozen-now aware)
│       ├── useLongPress.ts # shared touch long-press hook
│       ├── components/
│       └── styles/
├── scripts/
│   └── dev-second-api.sh   # second API on :3001 for multi-instance WS testing
└── docs/                   # design docs + sprint logs
```

## Running locally

The dev workflow is: **devcontainer** (Rust + Node + psql shell) on top of
**docker compose postgres** (the only service in `docker-compose.yml`).
The api and web are run by hand inside the devcontainer — no `api` or
`web` service in compose.

### VS Code devcontainer (recommended)

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

Then open <http://localhost:5173>. Set `DEV_AUTH=1` before `cargo run`
to enable `/api/auth/dev-login` and the "Sign in as Maya" button on
the login screen. The "Try as Maya in your browser" button works
without a backend at all (playground mode).

To wipe and reseed the database (after a migration): `cargo run --bin
seed -- --drop`.

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

### Plain host (no devcontainer)

Postgres still runs in compose; the toolchains run on the host:

```bash
docker compose up -d postgres

# api (terminal 1)
cd api
cargo run --bin seed
cargo run

# web (terminal 2)
cd web
pnpm install
pnpm dev --host
```

Postgres listens on `:5432` (user/pass/db all `fira`).

## Production build (Fly.io, live at usefira.app)

The repo-root [Dockerfile](Dockerfile) is a three-stage build (web →
api → debian-slim runtime) that produces one image serving the SPA and
the JSON API on the same origin. `/api/*` routes go to the api,
`/health` is at the root for Fly's healthcheck, and everything else
falls through to `dist/index.html` so React Router handles client-side
routes. CORS is dropped — same-origin in both dev (Vite proxy) and
prod.

The prod binary is built with `--no-default-features`, which strips
the `dev_auth` cargo feature — `/api/auth/dev-login` and
`/api/auth/dev-seed` don't exist in the prod binary.

Required env / secrets on the Fly app:

| name                    | what                                                  |
|-------------------------|-------------------------------------------------------|
| `DATABASE_URL`          | written by `flyctl postgres attach` automatically     |
| `GOOGLE_CLIENT_ID`      | Google OAuth client id                                |
| `GOOGLE_CLIENT_SECRET`  | Google OAuth client secret                            |
| `OAUTH_REDIRECT_URL`    | `https://usefira.app/api/auth/google/callback`        |
| `APP_BASE_URL`          | `https://usefira.app`                                 |
| `COOKIE_SECURE`         | `1`                                                   |

The image bakes `STATIC_ROOT=/app/dist` and `API_BIND_ADDR=0.0.0.0:8080`.
**Do not** set `DEV_AUTH` — it has no effect on a prod binary.

To preview the prod image locally:

```bash
docker build -t fira .
docker run --rm -p 8080:8080 \
  -e DATABASE_URL=postgres://fira:fira@host.docker.internal:5432/fira \
  -e GOOGLE_CLIENT_ID=... -e GOOGLE_CLIENT_SECRET=... \
  -e OAUTH_REDIRECT_URL=http://localhost:8080/api/auth/google/callback \
  -e APP_BASE_URL=http://localhost:8080 \
  fira
```

## API

All routes live under `/api` except `/health`. Most require a session
cookie (`sid`); scoped routes additionally require an `X-Workspace-Id`
header pointing at a workspace the caller is a member of (validated
per request). Reads and writes are scoped by workspace membership and,
where applicable, project membership.

| route                                  | method | what                                                  |
|----------------------------------------|--------|-------------------------------------------------------|
| `/health`                              | GET    | liveness                                              |
| `/api/auth/config`                     | GET    | `{ dev_auth }` so the SPA can render the dev button   |
| `/api/auth/google/login`               | GET    | start Google OAuth                                    |
| `/api/auth/google/callback`            | GET    | OAuth callback; upserts user, creates personal workspace, sets `sid` |
| `/api/auth/logout`                     | POST   | drop session row + cookie                             |
| `/api/auth/dev-login?email=…`          | GET    | bypass auth in dev (`dev_auth` feature)               |
| `/api/me`                              | GET    | the authenticated user (or 401)                       |
| `/api/bootstrap`                       | GET    | one-shot hydrate for the active workspace: users, projects, epics, sprints, tasks (+subtasks), blocks, links, plus the change-log cursor |
| `/api/workspaces`                      | GET    | the caller's workspaces (incl. personal)              |
| `/api/workspaces`                      | POST   | create a non-personal workspace; caller becomes owner |
| `/api/workspaces/:id`                  | PATCH  | rename (workspace owner only)                         |
| `/api/workspaces/:id`                  | DELETE | delete (owner only; personal workspaces rejected)     |
| `/api/workspaces/:id/members`          | PUT    | replace member set + roles (owner only)               |
| `/api/workspaces/:id/members/:user_id` | PATCH  | change a single member's role (owner only)            |
| `/api/workspaces/:id/users`            | GET    | directory listing scoped to one workspace             |
| `/api/workspaces/:id/all-users`        | GET    | every user in the system (owner only) — for adding users not yet in any workspace |
| `/api/projects`                        | POST   | create a project (workspace owner only)               |
| `/api/projects/:id`                    | PATCH  | update title / icon / color / external URL template (owner or lead) |
| `/api/projects/:id`                    | DELETE | delete (workspace owner only)                         |
| `/api/projects/:id/members`            | PUT    | replace project member set + per-row role             |
| `/api/links`                           | GET    | list every link involving me                          |
| `/api/links`                           | POST   | `{ email }` → create pending link                     |
| `/api/links/:id`                       | DELETE | cancel sent / decline received / unlink               |
| `/api/links/:id/accept`                | POST   | accept (only the non-requester)                       |
| `/api/linked/calendar`                 | GET    | partner's blocks + `LinkedTask` projection            |
| `/api/personal/calendar`               | GET    | personal workspace blocks + `LinkedTask` projection (empty when active workspace already is personal) |
| `/api/ops`                             | POST   | push a batch of outbox ops, idempotent on `op_id`     |
| `/api/changes?since=N`                 | GET    | pull the change feed (≤ 500 ops, scope-filtered)      |
| `/api/ws?workspace_id=…`               | WS     | nudge socket for the workspace's change feed          |
| `/api/ws/user`                         | WS     | per-user channel for membership / role / workspace events |

The op kinds accepted by `/api/ops` (~21 today): `task.create`,
`task.tick`, `task.set_section`, `task.set_title`,
`task.set_description`, `task.set_estimate`, `task.set_assignee`,
`task.set_status`, `task.set_external_id`, `task.set_external_url`,
`task.reorder`, `task.delete`, `subtask.create`, `subtask.tick`,
`subtask.set_title`, `subtask.delete`, `subtask.reorder`,
`block.create`, `block.update`, `block.delete`. Workspace and project
mutations log synthesized `workspace.create` / `workspace.update` /
`workspace.set_members` / `workspace.set_member_role` /
`workspace.delete` / `project.create` / `project.update` /
`project.set_members` / `project.delete` ops onto the same feed so
peer clients converge through one apply path.

## Spec & sprint logs

- [docs/spec.md](docs/spec.md) — current contract for what's actually built
- [docs/sprints/](docs/sprints/) — what each sprint shipped, with decisions
- [docs/fira_design_doc.md](docs/fira_design_doc.md) — long-form vision (parts now superseded — see sprint 08 on workspaces)

## Data model

Authoritative SQL: [api/migrations/](api/migrations/). Migrations
0001–0013, applied in order on boot via `sqlx::migrate!`.

Core tables: `users`, `sessions`, `workspaces`, `workspace_members`,
`projects`, `project_members`, `epics`, `sprints`, `tasks`,
`subtasks`, `time_blocks`, `processed_ops`, `user_links`
(`gcal_events` exists in the schema as a placeholder for future
GCal sync — not yet wired up). See sprint 08 for the workspace + composite-FK shape,
sprint 11 for `user_links`, and sprint 13 for the `processed_ops`
durability change (migration 0010 dropped the FK cascades so audit
log rows survive entity deletion).

The seeder ([api/src/bin/seed.rs](api/src/bin/seed.rs)) reproduces a
canonical fixture: 4 users, one shared `Default` workspace plus a
personal workspace per user, 3 projects (Atlas / Relay / Helix), 22
tasks, 22 time blocks. IDs are deterministic
UUID-v5 derived from slugs so re-seeding is stable. The fixture week
is anchored to **Mon Apr 27 2026 00:00 PT**; "today" in the UI is
**Wed Apr 29**, hardcoded so the seed is reproducible regardless of
wall-clock time.

The same fixture is dumped to
[web/src/playground/bootstrap.json](web/src/playground/bootstrap.json)
by `cargo run --bin dump-bootstrap`, which is what the in-browser
playground feeds into the store.

## What's not here yet

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
  current rates, will need archival eventually. Migration 0010
  intentionally lets log rows linger past their entities; a periodic
  GC is the obvious follow-up.
- **Email invites** for non-Fira accounts. Linking and workspace adds
  both require the partner to have signed in first.
- **Multiple accepted links per user.** Hard-cap'd to one via partial
  unique indexes; "one person, two accounts, one timeline" is the
  product premise.

Pieces of the deferred items are described in
[docs/fira_design_doc.md](docs/fira_design_doc.md); the per-sprint
decisions live in [docs/sprints/](docs/sprints/).
