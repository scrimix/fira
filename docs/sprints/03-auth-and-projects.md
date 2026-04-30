# Sprint 03 — Auth & projects

**Status:** done
**Date:** 2026-04-30

## Goal

Sprints 01–02 built a single-tenant prototype with no login: the seed
fixture's "Maya" was hardcoded as the current user, and every browser tab
saw the same shared dataset. To make this app actually deployable for
personal use (and seed the road to company use), we need real identity,
per-user data scoping, and the ability to create/edit projects from the UI.
This sprint stands up the auth fence and the first write endpoints.

## What shipped

### Google OAuth (server-side code flow)

- `GET /auth/google/login` — redirects the browser to Google's consent URL
  with a random `state` token stored in a 5-minute HttpOnly cookie for CSRF.
- `GET /auth/google/callback` — verifies state, exchanges the code at
  `https://oauth2.googleapis.com/token`, fetches the userinfo, upserts
  the user (matching by `google_sub`, not email), creates a session row,
  sets the `sid` cookie, redirects to `APP_BASE_URL`.
- `POST /auth/logout` — deletes the session row, clears the cookie.
- `GET /me` — returns the authenticated user (or 401).
- `GET /auth/dev-login?email=…` — bypass for dev. Only mounted when
  `DEV_AUTH=1`. Routes a known seeded user into a real session without
  needing a Google credential.

Same Google OAuth client serves dev (`http://localhost:5173/...`) and prod
(`https://usefira.app/...`) — both URLs registered as authorized redirects
in the GCP console; the `OAUTH_REDIRECT_URL` env var picks which one we
send to Google at runtime.

### Sessions

Opaque random 32-byte tokens (URL-safe base64), 30-day TTL, stored in the
new `sessions` table with `(id, user_id, expires_at, user_agent)`. Lookup
is one indexed PK fetch per authenticated request — fine at our scale and
gives us instant revocation on logout (vs. waiting for a JWT to expire).

The `AuthUser` extractor wraps this: any handler that takes `AuthUser` is
protected. Missing or invalid `sid` → 401, expired session → row is
deleted in passing → 401.

### Per-user data scoping

- New columns: `users.google_sub` (unique partial index), `users.avatar_url`,
  `projects.owner_id`.
- `project_scope(user_id)` returns the set of projects the user owns OR is
  an explicit member of via `project_members`. We kept the membership
  table even in personal mode (auto-inserting the owner as a member) so
  switching to "shared" later is a no-op.
- `/bootstrap` now filters everything through this scope: only the
  caller's owned/member projects, only their own time blocks and gcal
  events. The `users[]` returned is the caller plus any co-members of
  their projects — no leaking unrelated org users.
- Seed fixture updated: every fixture project gets `owner_id = u_maya`,
  every fixture user gets `google_sub = "dev-{slug}"` so a real Google
  login can never collide with seeded identities.

### Login screen

New `Login.tsx` component, rendered when `/me` returns 401. Editorial
layout: `[Mark] Fira` on one row in **Instrument Serif** (40 px display
face), tagline below, full-width "Continue with Google" button below
that. The mark is a stack of three time-block bars in a square, the
middle one in cyan accent — visualizes the unit-of-plan and ties to the
product. Soft radial-gradient background plus a small drop-shadow on the
card so it doesn't read flat.

### Logout

Plain mono-text button in the top bar (`Log out`). On click: POST
`/auth/logout` (best-effort), then `window.location.assign('/')` so all
in-memory state — outbox, modals, drag state — is dropped before the
next `/me` check.

### Project create

- `POST /projects` (auth required) — accepts `{title, icon, color}`,
  validates (title 1–80 chars, hex color regex, icon ≤ 32 chars),
  inserts in a transaction with `source = 'local'` and `owner_id =
  caller`, also inserts the caller into `project_members`.
- `NewProjectModal` (later renamed `ProjectModal` in sprint 04) — title
  input + 4×3 Lucide icon picker + 2×4 colored swatches. Live preview
  in the modal head with the chosen icon in the chosen color. Submit
  is a synchronous round-trip (not outbox-routed): create is rare and
  deliberate, so a "appears then disappears on error" optimistic insert
  would be jankier than a brief loading state.
- Sidebar gets a `+` button at the end of the project list opening the
  modal.

### Store

New state:
- `authChecked: boolean` — tri-state with `meId` so the app shell renders
  `loading → Login → app` without an "anonymous as me" intermediate.
- `creatingProject: boolean` (later collapsed into `projectModal` in
  sprint 04).

New actions:
- `logout()` — calls `api.logout`, hard-reloads.
- `addProject(input)` — POSTs and appends the new project to local state,
  switches the inbox view to it.

The hardcoded `users.find(u => u.email === 'maya@fira.dev')` lookup is
gone — `meId` comes from `/me`, period.

## Decisions worth keeping

- **Server-stored opaque sessions, not JWT.** One DB hit per request is
  fine at < 100 users and gives us instant revocation. JWT's "stateless
  scaling" benefit is irrelevant before the database is the bottleneck,
  and the cost of a leaked-token-can't-be-revoked window isn't worth it.
- **Single Google OAuth client for dev + prod.** Both redirect URIs
  registered in the same client; the `OAUTH_REDIRECT_URL` env var picks
  which one to send. Two separate clients would mean two separate
  consent screens, two sets of test users, and "wait, is this dev or
  prod?" confusion.
- **Keep `project_members` even in personal mode.** Cheap row, makes the
  membership query in `list_users_in_scope` honest, and means the
  promotion to "shared project" is purely a permissions UI change.
- **Identity scopes only, defer Calendar/Gmail.** Adding Calendar later
  is one OAuth re-consent, not a code overhaul. Until we're ingesting
  actual events, the wider scope just enlarges the consent screen.
- **`google_sub` is the lookup key, not email.** Google emails can change;
  `sub` cannot. Storing both is fine (we want the email for the UI), but
  matching on `sub` is the only way to keep an account stable across an
  email change.
- **Project create is a live round-trip; everything else still goes
  through the outbox.** Frequency of action drives this — you create a
  project once a quarter, you tick a task fifty times an hour. The two
  shouldn't share UX.

## Things that bit us

- `axum-extra` 0.9 is the version paired with axum 0.7; cargo's "available:
  0.12" hint is the wrong major version.
- `FromRequestParts` in axum 0.7 still uses `#[async_trait]` even though
  Rust supports `async fn in trait` natively now. Implementing the
  extractor without the macro fails with a lifetime mismatch.
- `redirect_uri_mismatch` from Google bites three times before you
  internalize the rule: the URI in **Authorized redirect URIs** must
  match byte-for-byte (full path included), and the **Authorized
  JavaScript origins** field is a separate list — populating only the
  origins doesn't satisfy the redirect check.
- `.app` TLDs are HSTS-preloaded → `usefira.app` is implicitly
  HTTPS-only. We don't have to think about cookie `Secure: true`
  surprises in prod.

## Things that surprised in a good way

- The seeded "users" can ride the same login flow as real Google users
  with zero overlap, because the partial unique index on `google_sub`
  treats `NULL` as distinct and our seeded `dev-*` placeholders never
  collide with Google's numeric `sub`s.

## What's deferred

- Outbox sync worker (still — but the seam is now load-bearing because
  the API is per-user-scoped).
- Real-time updates between tabs.
- Project share / invite a member.
- Account settings page.
- Calendar / Gmail OAuth scopes.

## Verification

```
$ DEV_AUTH=1 cargo run                        # api on :3000
$ curl -i /api/me                              → 401
$ curl /api/auth/dev-login?email=maya@fira.dev → 303 + sid cookie
$ curl -b sid /api/me                          → { "id": "...", ... }
$ curl -b sid /api/bootstrap                   → maya's scope only
$ curl -X POST -b sid /api/auth/logout         → 204, sid cleared
$ curl -b sid /api/me                          → 401
```

Real Google flow: open `/`, click "Continue with Google", consent, land
back on `/`, app loads. `POST /projects` creates a Lucide-iconned project,
sidebar updates, refresh-safe.

## Next sprint candidates

1. The UX is rough in places (login flat, project icons missing
   everywhere, calendar feels cramped). One polish pass.
2. Wire the outbox to `/ops`. Now that the API can authenticate writes
   per user, the next missing piece is letting the client deliver them.
3. Live updates across tabs / devices.
