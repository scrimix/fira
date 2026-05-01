# Sprints

Each file in this directory is a sprint log: what was scoped, what was
actually built, what was deferred, and the decisions worth remembering.

Format: `NN-short-title.md`. One sprint per file. Don't rewrite history when
priorities change — open a new sprint.

## Index

- [01-scaffold.md](01-scaffold.md) — initial scaffold: docker-compose, Postgres schema, Rust API, Vite/React web app reading from `/bootstrap`.
- [02-interactions.md](02-interactions.md) — interactions: drag-to-schedule, draft modal, switchable user tabs, week navigation, editable estimates / status / subtasks, done-task visuals.
- [03-auth-and-projects.md](03-auth-and-projects.md) — Google OAuth, sessions, per-user data scoping, login screen, project create.
- [04-polish.md](04-polish.md) — Lucide icons, palette, project edit, calendar layout reshape (kill left rail, project filter into right rail), inline subtask edit, alignment fixes.
- [05-sync.md](05-sync.md) — push (`POST /ops` + outbox worker + status pill) and pull (`processed_ops` as change log + `GET /changes?since=N` + cursor + applyRemoteOp) — local-first round-trip closed.
- [06-bootstrap-fix-and-dev-seeder.md](06-bootstrap-fix-and-dev-seeder.md) — fix `/bootstrap` 500 on empty `processed_ops` (`MAX(seq)` NULL decode), share seeder logic between CLI bin and a new `POST /auth/dev-seed` endpoint, add "Seed dev data & sign in" button to the login screen behind `DEV_AUTH=1`.
- [07-collab-and-issue-links.md](07-collab-and-issue-links.md) — editable project membership (split into `project.update` + `project.set_members` ops with soft-delete on `project_members`), bootstrap blocks-in-scope so teammates' calendars render, rail Mine/All toggle + title filter so `time_blocks.user_id` becomes a usable column, manual issue links via `external_url_template` + `task.set_external_id`, inbox `(you)` no longer hardcoded to Maya, `fmtMin` sign fix.
- [08-workspaces.md](08-workspaces.md) — `workspaces` + `workspace_members` as the company-level tenant boundary; personal workspace auto-created per user (Google OAuth + seeder); `X-Workspace-Id` header on all scoped routes; **two role axes** — workspace `owner`/`member` and project `lead`/`member` — gating workspace and project mutations; topbar workspace switcher; owner-only settings modal in the sidebar; custom `<Select>` replaces every native dropdown so popovers stay inside the editorial palette and escape `overflow: auto` containers; sync pill now combines `Offline · N pending`, surfaces a failed-ops popover with retry/discard, and suppresses fast-tick flicker; `zustand/middleware/persist` snapshot lets the app boot offline from cache when `/me` can't reach the server.
- [09-deploy.md](09-deploy.md) — production-shape changes for the first Fly.io deploy at `usefira.app`: api serves the SPA same-origin via `ServeDir` (CORS dropped), dev-mode endpoints behind a `dev_auth` cargo feature, `API_BIND_ADDR=0.0.0.0:8080`, multi-stage Dockerfile, `fly.toml` skeleton.
