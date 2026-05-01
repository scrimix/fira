# Sprint 09 — Production deploy on Fly.io (usefira.app)

**Status:** shipped
**Date:** 2026-05-01

## Goal

Get the app onto the public internet at `usefira.app` so a small set of
real users can try it. The server-side code was "dev-mode correct"
everywhere a production setting differs (CORS wide open, dev auth
endpoints live, cookies non-secure, OAuth redirect hard-coded to
localhost). This sprint made the existing binary safe to ship and
worked through the deployment surprises.

## Topology

**Single Fly app, single origin.** The api binary serves both the JSON
routes under `/api/*` and the SPA's `dist/` static files from `/`. No
CORS, no two-cookie-domain dance, one TLS cert, one deploy step. Vite's
`/api` proxy is dev-only and goes away in prod (api on `:8080` serves
both).

## What landed

### 1. API serves the SPA, with `/api` prefix

[`main.rs`](../../api/src/main.rs) puts every JSON / auth route under a
`/api` nest, keeps `/health` at the root for Fly's healthcheck, and
mounts `ServeDir` as the fallback so anything else gets `dist/index.html`
(React Router handles client-side paths):

```rust
let api = Router::new()
    .route("/me", get(auth::me))
    .route("/auth/google/callback", get(auth::google_callback))
    // … all the other routes …
    .route("/changes", get(ops::get_changes));

#[cfg(feature = "dev_auth")]
let api = api
    .route("/auth/dev-login", get(auth::dev_login))
    .route("/auth/dev-seed", post(auth::dev_seed));

let app = Router::new()
    .route("/health", get(health))
    .nest("/api", api)
    .with_state(state)
    .layer(TraceLayer::new_for_http())
    .fallback_service(static_svc);
```

Routes moving under `/api` was an in-flight discovery — the SPA's
[`api.ts`](../../web/src/api.ts) hard-codes `BASE = '/api'`, and the
Vite dev proxy was stripping that prefix before forwarding to the api
on `:3000`. Same-origin in prod means no proxy and no strip, so the api
has to handle `/api/*` natively. The Vite proxy now forwards
unchanged so dev and prod hit the same URL shape.

`tower-http` gained the `fs` feature in [`Cargo.toml`](../../api/Cargo.toml).
Dev is unaffected: `STATIC_ROOT` defaults to `dist/`, which doesn't exist
locally, so the fallback returns 404 and the developer hits Vite on
`:5173`. In the prod image `STATIC_ROOT=/app/dist`.

### 2. CORS dropped

`CorsLayer` is gone — same-origin in both dev (Vite proxy) and prod
(api serves the SPA). Re-add scoped to `https://usefira.app` if a
non-browser caller ever appears.

### 3. `dev_auth` cargo feature

Added `[features] default = ["dev_auth"]` to
[`Cargo.toml`](../../api/Cargo.toml). The feature gates:

- `auth::dev_login` and `auth::dev_seed` handlers
- The `/api/auth/dev-login` + `/api/auth/dev-seed` route registrations
- The `mod seed;` declaration (only `dev_seed` references it)
- The `DEV_AUTH` env-var read in `AuthConfig::from_env` (so the env var
  can't accidentally re-enable the endpoints in a prod binary)

Prod builds with `--no-default-features` and the dev-only handlers
literally do not exist in the binary. `/api/auth/config` still returns
`{ dev_auth: bool }` so the SPA's "Seed dev data" affordance hides
itself in prod.

### 4. Production Dockerfile (repo root)

[`Dockerfile`](../../Dockerfile) at the repo root — Fly's web UI
auto-detects it, no `fly.toml` needed for first deploy. Three stages:

1. **web** (`node:20-alpine`) — `pnpm install --frozen-lockfile`, `pnpm build` → `/web/dist`
2. **api** (`rust:1.88-slim`) — dummy-main cache layer, then real build with `--no-default-features --bin fira-api`
3. **runtime** (`debian:bookworm-slim`) — `ca-certificates`, copies binary + migrations + dist, sets `STATIC_ROOT=/app/dist` and `API_BIND_ADDR=0.0.0.0:8080`, `EXPOSE 8080`

Caveats picked up the hard way:

- The Rust toolchain version matters: `rust:1.83-slim` couldn't build
  `time-core 0.1.8` (transitive via `sqlx`) because that crate requires
  edition 2024, stabilized in 1.85. Pinned to `1.88-slim`.
- `migrations/` ships in the image because `sqlx::migrate!` is a
  compile-time macro that bakes the SQL into the binary; the COPY is
  belt-and-braces.

### 5. Required env / secrets

`AuthConfig::from_env` reads everything; values change for prod. Set
as Fly secrets:

| name                    | value                                                  |
|-------------------------|--------------------------------------------------------|
| `DATABASE_URL`          | written automatically by `flyctl postgres attach`      |
| `GOOGLE_CLIENT_ID`      | Google OAuth client id                                 |
| `GOOGLE_CLIENT_SECRET`  | Google OAuth client secret                             |
| `OAUTH_REDIRECT_URL`    | `https://usefira.app/api/auth/google/callback`         |
| `APP_BASE_URL`          | `https://usefira.app`                                  |
| `COOKIE_SECURE`         | `1`                                                    |

`STATIC_ROOT` and `API_BIND_ADDR` are baked into the image. **Do not**
set `DEV_AUTH` — it has no effect on a prod binary anyway.

### 6. Startup logging hardened

[`main.rs`](../../api/src/main.rs) prints an `eprintln!("fira-api:
starting")` breadcrumb before tracing init (so `docker logs` is never
empty even if init explodes), uses `fira_api=trace,info` as the default
filter (every app log line at trace, library noise at info — override
via `RUST_LOG`), and emits a structured `resolved config` line on
startup with the bind address, static root, and *redacted* DB host. The
single most useful line for "did my env var actually land or did I get
the localhost default."

### 7. Login screen brand mark

The login card was still rendering the old three-stacked-bar inline
mark while the rest of the app had moved to
[`BrandMark`](../../web/src/components/BrandMark.tsx) (the gradient "F"
glyph that matches the favicon). [`Login.tsx`](../../web/src/components/Login.tsx)
now uses `BrandMark`; the inline `<Mark>` is gone.

### 8. Empty-workspace UX

A first-time user with no projects landed on calendar with a "+ New
task" button that couldn't do anything. [Store hydrate / switchWorkspace](../../web/src/store/index.ts)
now picks `view: 'inbox'` when the bootstrap returns zero projects;
calendar stays the landing for any non-empty workspace. The inbox's
empty state already has the owner-aware CTA — owners get a "Create
your first project" button, plain members see "ask a workspace admin"
— so this reuses existing UI rather than duplicating a CTA in the
calendar rail.

## Operational steps for first deploy (no code work)

1. **Fly app.** `flyctl launch` (or web UI) — point at the repo root,
   no `fly.toml` needed; Fly detects the `Dockerfile`.
   `internal_port = 8080`, healthcheck on `/health`. Bump
   `grace_period` to 60 s to ride out cold-start migrations.
2. **Postgres.** `flyctl postgres create --name fira-tasks-db --region <same>` →
   `flyctl postgres attach fira-tasks-db -a <app>` (writes
   `DATABASE_URL` as a secret automatically).
3. **Secrets.** `flyctl secrets set` for the rest of §5.
4. **DNS.** `usefira.app` → the Fly app's anycast IPs.
5. **Google OAuth client.** Authorized redirect URI =
   `https://usefira.app/api/auth/google/callback`.

### Verification after first deploy

1. `flyctl logs` — `fira-api: starting` line, then `resolved config`
   with the right `db_host`, then `fira-api listening on 0.0.0.0:8080`.
2. `curl https://usefira.app/health` returns `ok`.
3. `https://usefira.app` shows the login screen with the new
   gradient-F mark and **no** "Seed dev data" button (dev_auth feature
   compiled out).
4. `curl -i https://usefira.app/api/auth/dev-login?email=foo` returns
   404 — the route doesn't exist in the prod binary, not just gated.
5. Google sign-in → bootstrap. A first-time user with no projects lands
   on the inbox with the "Create your first project" CTA.
6. After creating a project: drag block, refresh — state persists, sync
   pill reads Synced.

## Near-future, post-deploy

- **Bind listener before the DB pool is ready.** The current cold-start
  flow refuses TCP connections for ~30 s while `wait_for_pool` retries.
  Once `DATABASE_URL` is wired up correctly the wait is sub-second, but
  if Postgres is ever down at startup Fly's healthcheck refuses
  connections instead of getting a 503. Bind first, serve a 503
  "starting" router until the pool is up, then swap.
- **`fly.toml` checked in.** First deploy is via the web UI; once the
  config stabilizes, commit a trimmed `fly.toml` so deploys are
  reproducible from CLI / CI.
- **Sessions table GC.** Trivial cron to delete
  `WHERE expires_at < now() - interval '7 days'`.
- **`pg_dump` → object storage backup.** Fly volume snapshots happen,
  but logical backup (point-in-time, off-Fly) is the next thing once
  real users land. One-line cron on a tiny machine.
- **Rate limit on `/api/ops`.** Spec already notes this is deferred.
- **Deploy-from-CI** (GitHub Actions → Fly). Manual `flyctl deploy` is
  fine for the first cut.
- **Prod observability** (Sentry / structured log shipping). For now
  `flyctl logs` is the runway.
- **Multi-region postgres.** Single-node fine for testing.

## After this sprint

- Per-task done-archive pagination (the "thousands of done tasks"
  question we punted on).
- Scoped `/api/bootstrap` + lazy-load per project (the scaling cliff
  also discussed mid-session).
- Email invites — workspace owners pre-create users by email instead
  of requiring them to sign in once first.
- Real spec.md update covering workspaces (carried from sprint 08).
