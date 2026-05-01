# Sprint 09 — Production deploy on Fly.io (usefira.app)

**Status:** code landed; first deploy pending Fly account + DNS
**Date:** 2026-05-01

## Goal

Get the app onto the public internet at `usefira.app` so a small set of
real users can try it. The server-side code was "dev-mode correct"
everywhere a production setting differs (CORS wide open, dev auth
endpoints live, cookies non-secure, OAuth redirect hard-coded to
localhost). This sprint makes the existing binary safe to ship; the
**operational checklist** (Fly account, DNS, Google OAuth client) lives
in the README, not here.

## Topology

**Single Fly app, single origin.** The api binary serves both the JSON
routes under `/api/*` and the SPA's `dist/` static files from `/`. No
CORS, no two-cookie-domain dance, one TLS cert, one deploy step. Vite's
`/api` proxy is dev-only and goes away in prod (`api on :8080` serves
both).

## What landed

### 1. API serves the SPA

[`main.rs`](../../api/src/main.rs) mounts a `ServeDir` fallback after the
route table:

```rust
let static_root = std::env::var("STATIC_ROOT").unwrap_or_else(|_| "dist".into());
let serve_index = ServeFile::new(format!("{static_root}/index.html"));
let static_svc = ServeDir::new(&static_root).not_found_service(serve_index);

let app = app
    .with_state(state)
    .layer(TraceLayer::new_for_http())
    .fallback_service(static_svc);
```

`tower-http` gained the `fs` feature in [`Cargo.toml`](../../api/Cargo.toml).
Dev is unaffected: `STATIC_ROOT` defaults to `dist/`, which doesn't
exist locally, so the fallback returns 404 and the developer hits Vite
on `:5173`. In the prod image `STATIC_ROOT=/app/dist`.

### 2. CORS dropped

`CorsLayer` is gone — same-origin in both dev (Vite proxy) and prod (api
serves the SPA). Re-add scoped to `https://usefira.app` if a non-browser
caller ever appears.

### 3. `dev_auth` cargo feature

Added `[features] default = ["dev_auth"]` to
[`Cargo.toml`](../../api/Cargo.toml). The `dev_auth` feature gates:

- `auth::dev_login` and `auth::dev_seed` handlers
- The `/auth/dev-login` + `/auth/dev-seed` route registrations
- The `mod seed;` declaration (only `dev_seed` references it)
- The `DEV_AUTH` env-var read in `AuthConfig::from_env` (so the env var
  can't accidentally re-enable the endpoints in a prod binary)

Prod builds with `--no-default-features` and the dev-only handlers
literally do not exist in the binary. `/auth/config` still returns
`{ dev_auth: bool }` so the SPA's "Seed dev data" affordance hides
itself in prod.

### 4. Production Dockerfile (repo root)

[`Dockerfile`](../../Dockerfile) at the repo root — Fly's web UI
auto-detects it, no `fly.toml` needed for first deploy. Three stages:

1. **web** (`node:20-alpine`) — `pnpm install --frozen-lockfile`, `pnpm build` → `/web/dist`
2. **api** (`rust:1.83-slim`) — dummy-main cache layer, then real build with `--no-default-features --bin fira-api`
3. **runtime** (`debian:bookworm-slim`) — `ca-certificates`, copies binary + migrations + dist, sets `STATIC_ROOT=/app/dist` and `API_BIND_ADDR=0.0.0.0:8080`, `EXPOSE 8080`

The dummy-main trick gives the dep cache its own layer so source-only
edits redeploy in seconds. `migrations/` ships in the image because
`sqlx::migrate!` is a compile-time macro that bakes the SQL into the
binary; the COPY is belt-and-braces.

### 5. Required env / secrets

`AuthConfig::from_env` already reads everything; what changes for prod
is the *values*. Set as Fly secrets:

| name                    | value                                                 |
|-------------------------|-------------------------------------------------------|
| `DATABASE_URL`          | postgres connection string (Fly Postgres or external) |
| `GOOGLE_CLIENT_ID`      | Google OAuth client id                                |
| `GOOGLE_CLIENT_SECRET`  | Google OAuth client secret                            |
| `OAUTH_REDIRECT_URL`    | `https://usefira.app/auth/google/callback`            |
| `APP_BASE_URL`          | `https://usefira.app`                                 |
| `COOKIE_SECURE`         | `1`                                                   |

`STATIC_ROOT` and `API_BIND_ADDR` are baked into the image. `RUST_LOG`
defaults to `info` in code; override with a Fly env var if needed
(`info,sqlx=warn,tower_http=info` is the recommended starting point).
**Do not** set `DEV_AUTH` — it has no effect on a prod binary anyway,
but don't set it.

### 6. Web build — env hygiene

[`web/src/api.ts`](../../web/src/api.ts) hard-codes `BASE = '/api'`,
correct for both dev (Vite proxy) and same-origin prod. No change.

## What's left for first deploy

**No code work**, only operational steps:

1. **Fly account + app.** `flyctl launch` (or web UI) — point it at the
   repo root, no `fly.toml` needed; Fly detects the `Dockerfile`. Set
   `internal_port = 8080` and add a healthcheck on `/health`.
2. **Postgres.** `flyctl postgres create` and attach to the app, or
   point `DATABASE_URL` at an external instance.
3. **Secrets.** `flyctl secrets set` for the six entries in §5.
4. **DNS.** `usefira.app` → Fly app's anycast IPs.
5. **Google OAuth client.** Authorized redirect URI =
   `https://usefira.app/auth/google/callback`.

### Verification checklist after first deploy

1. `flyctl logs` — migrations run clean, no panic, listening on `:8080`.
2. `curl https://usefira.app/health` returns `ok`.
3. `https://usefira.app` shows the login screen with **no** "Seed dev
   data" button (dev_auth feature compiled out).
4. `curl https://usefira.app/auth/dev-login?email=foo@bar` returns 404
   (route doesn't exist, not just gated).
5. Google sign-in → bootstrap → `/me` returns the new user's personal
   workspace.
6. Create project, drag block, refresh — state persists, sync pill
   reads Synced.
7. `flyctl postgres connect` → `\dt` shows the expected schema.

## Near-future, post-deploy

Once one stable deploy is up and a couple of friends are poking at it:

- **`fly.toml` checked in.** First deploy is via the web UI; once the
  config stabilizes, commit a trimmed `fly.toml` so deploys are
  reproducible from CLI / CI.
- **Sessions table GC.** Trivial cron to delete
  `WHERE expires_at < now() - interval '7 days'`.
- **`pg_dump` → object storage backup.** Fly volume snapshots happen,
  but logical backup (point-in-time, off-Fly) is the next thing once
  real users land. One-line cron on a tiny machine.
- **Rate limit on `/ops`.** Spec already notes this is deferred.
- **Deploy-from-CI** (GitHub Actions → Fly). Manual `flyctl deploy` is
  fine for the first cut.
- **Prod observability** (Sentry / structured log shipping). For now
  `flyctl logs` is the runway.
- **Multi-region postgres.** Single-node fine for testing.

## After this sprint

- Per-task done-archive pagination (the "thousands of done tasks"
  question we punted on).
- Scoped `/bootstrap` + lazy-load per project (the scaling cliff also
  discussed mid-session).
- Email invites — workspace owners pre-create users by email instead
  of requiring them to sign in once first.
- Real spec.md update covering workspaces (carried from sprint 08).
