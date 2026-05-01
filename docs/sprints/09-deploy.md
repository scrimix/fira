# Sprint 09 — Production deploy on Fly.io (usefira.app)

**Status:** planned
**Date:** 2026-05-01

## Goal

Get the app onto the public internet at `usefira.app` so a small set of
real users can try it. The server-side codebase has been "dev mode
correct" everywhere a production setting differs (CORS wide open, dev
auth endpoints live, cookies non-secure, OAuth redirect hard-coded to
localhost, etc.). This sprint is the **code changes** that make the
existing binary safe to ship; the **operational checklist** (Fly
account, DNS, Google OAuth client) lives in the README/wiki, not here.

## Topology decision

**Single Fly app, single origin.** The api binary serves both the JSON
routes under `/api/*` and the SPA's static `dist/` from `/`. No CORS,
no two-cookie-domain dance, one TLS cert, one deploy step. The
dev-mode setup (`web` on `:5173` proxying `/api/*` to `:3000`) becomes
prod-mode "api on `:8080` serves both" — Vite's proxy is a dev-only
detail that goes away.

## Code changes (this sprint)

### 1. API serves the SPA

- `tower-http`'s `ServeDir` already in `Cargo.toml` (it's pulled in
  for `cors`/`trace`); add the `fs` feature.
- In [`main.rs`](../../api/src/main.rs), after the existing routes:

  ```rust
  use tower_http::services::{ServeDir, ServeFile};

  let static_root = std::env::var("STATIC_ROOT").unwrap_or_else(|_| "dist".into());
  let serve_index = ServeFile::new(format!("{static_root}/index.html"));
  let static_svc = ServeDir::new(&static_root)
      .not_found_service(serve_index);   // SPA fallback for client-side routing

  let app = Router::new()
      .route("/health", get(health))
      // ... existing /auth, /bootstrap, /projects, /workspaces, /ops, /changes ...
      .with_state(state)
      .layer(cors)
      .layer(TraceLayer::new_for_http())
      .fallback_service(static_svc);     // last-resort handler for any non-/api path
  ```

- The dev flow keeps working unchanged: `STATIC_ROOT` defaults to `dist`,
  which doesn't exist in dev so the fallback simply returns 404 — Vite
  on `:5173` is what the developer hits. In prod, `dist/` is copied
  into the image and `STATIC_ROOT=/app/dist`.

### 2. Tighten CORS

- Today: [`main.rs`](../../api/src/main.rs) sets `allow_origin(Any)`.
  Once the api serves the SPA same-origin, **CORS layer is no longer
  needed for browser traffic** — drop it entirely, or restrict to
  `https://usefira.app` if we want to keep the door cracked open for
  a hypothetical future api-only mobile client. Recommend dropping;
  re-add when there's a non-browser caller.

### 3. Strip dev-mode endpoints in prod builds

The `dev-seed`, `dev-login`, and the "Sign in as Maya" affordance in
[`Login.tsx`](../../web/src/components/Login.tsx) all already gate on
`DEV_AUTH=1`. Two options:

- **Keep + gate** (current) — the routes exist in the binary but
  return 404 when `DEV_AUTH` is unset. Cheapest.
- **`#[cfg(feature = "dev_auth")]` them out of the prod build** —
  defence in depth; one less attack surface to think about.

Recommend feature flag. Add `[features] dev_auth = []` to
`api/Cargo.toml`, gate the four handlers + the route registrations,
and the prod Dockerfile builds with `--no-default-features`. The dev
container keeps building with `--features dev_auth` (or default).

### 4. Auth/cookie environment

- `AuthConfig::from_env()` already reads `COOKIE_SECURE`, `DEV_AUTH`,
  `APP_BASE_URL`, `OAUTH_REDIRECT_URL`, `GOOGLE_CLIENT_ID`,
  `GOOGLE_CLIENT_SECRET`. No code change — just secrets to set on
  Fly. Document the full list in `README.md` (env-var section).
- One quiet correctness item: `compute_initials` falls back to the
  email's first char when name parsing fails. Real Google profiles
  always have a name, but worth keeping the fallback.

### 5. Bind address + port

- Fly expects the app to listen on whatever `internal_port` says in
  `fly.toml` (default 8080). Today the api defaults to
  `0.0.0.0:3000`. Either:
  - Set `API_BIND_ADDR=0.0.0.0:8080` as a Fly secret.
  - Or change the default in [`main.rs`](../../api/src/main.rs#L269)
    to `:8080`.

  Prefer the env-var route — keeps the dev binary on `:3000` so the
  Vite proxy and the existing developer-shell muscle memory work.

### 6. Production Dockerfile

Replace the dev `api/Dockerfile`. Multi-stage:

```dockerfile
# --- web build ---
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build       # writes /web/dist

# --- api build ---
FROM rust:1.83-slim AS api
WORKDIR /api
COPY api/Cargo.toml api/Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src
COPY api/ ./
RUN cargo build --release --bin fira-api --no-default-features

# --- runtime ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=api /api/target/release/fira-api /app/fira-api
COPY --from=api /api/migrations /app/migrations
COPY --from=web /web/dist /app/dist
ENV STATIC_ROOT=/app/dist API_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
CMD ["/app/fira-api"]
```

Notes:
- `--no-default-features` keeps `dev_auth` out of the prod binary.
- The dummy-main trick gives the cargo dep cache a separate layer
  from the source — re-deploys without dep changes are seconds, not
  minutes.
- `migrations/` ships in the image because `sqlx::migrate!` is a
  compile-time macro that bakes the SQL into the binary. The COPY is
  belt-and-braces so a `--features remote-migrations` mode could
  read from disk later if needed.

### 7. `fly.toml` skeleton

Generated by `flyctl launch`, then trimmed:

```toml
app = "fira"
primary_region = "fra"  # whichever Fly region is closest

[build]
  dockerfile = "api/Dockerfile"

[env]
  RUST_LOG = "info,sqlx=warn,tower_http=info"
  STATIC_ROOT = "/app/dist"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "suspend"
  auto_start_machines = true
  min_machines_running = 1

[[http_service.checks]]
  grace_period = "10s"
  interval = "30s"
  method = "GET"
  path = "/health"
  protocol = "http"
```

`auto_stop` + `min_machines_running = 1` keeps cost low; raise the
floor when traffic justifies it.

### 8. Web build — env hygiene

[`web/src/api.ts`](../../web/src/api.ts) hard-codes `BASE = '/api'`,
which is correct for both dev (Vite proxy) and same-origin prod. No
change needed. If the topology ever splits to two apps, this is the
one line that becomes a `VITE_API_BASE_URL` env var.

## Out of scope (deferred)

- **`pg_dump` → object storage backup**. Fly volume snapshots happen,
  but a logical backup story (point-in-time, off-Fly) is the next
  thing once real users land. One-line cron on a tiny machine.
- **Rate limit on `/ops`**. Spec already notes deferred.
- **Sessions table GC**. Old rows accumulate; trivial cron to delete
  `WHERE expires_at < now() - interval '7 days'`.
- **Multi-region postgres**. Single-node fine for testing.
- **Prod observability** (Sentry / structured log shipping). For now
  `flyctl logs` is the runway.
- **Deploy-from-CI** (GitHub Actions → Fly). Manual `flyctl deploy`
  is fine for the first cut.

## Verification

After first deploy:

1. `flyctl logs` — confirm migrations ran clean, no panic, listening
   on `:8080`.
2. `curl https://usefira.app/health` returns `ok`.
3. `https://usefira.app` shows the login screen (no "Sign in as
   Maya" button — `DEV_AUTH` unset).
4. Google sign-in → bootstraps → `/me` returns the new user's
   personal workspace.
5. Create project, drag block, refresh — state persists, sync pill
   reads Synced.
6. `flyctl postgres connect` → `\dt` shows the expected schema.

## After this sprint

Once we have one stable production deploy and a couple of friends
poking at it, the next sprint candidates are:

- Per-task done-archive pagination (the "thousands of done tasks"
  question we punted on).
- Scoped `/bootstrap` + lazy-load per project (the scaling cliff
  also discussed mid-session).
- Email invites — workspace owners pre-create users by email instead
  of requiring them to sign in once first.
- Real spec.md update covering workspaces (carried from sprint 08).
