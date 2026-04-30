# Sprint 06 — Bootstrap fix + dev seeder button

**Status:** done
**Date:** 2026-04-30

## Goal

Two follow-ups from the sync sprint left cracks in the dev experience.
First, signing in via Google immediately tripped a `/bootstrap` 500 on
fresh databases — `current_cursor` was decoding `MAX(seq)` as `i64` and
choking on the empty-table NULL. Second, sprint 03 introduced per-user
data scoping, which silently invalidated the seeded fixtures: the seed
binary still owned everything as Maya, but a Google-signed-in dev was a
different user with an empty scope and saw nothing. We needed a way to
flip back to the demo dataset in one click without leaving the login
screen.

## What shipped

### Bug: `/bootstrap` 500 on first login

- **`SELECT MAX(seq) FROM processed_ops`** returns one row whose value
  is NULL when the table is empty. `current_cursor` was decoding that
  as `(i64,)`, which fails with `unexpected null; try decoding as an
  Option`. Switched the row type to `(Option<i64>,)` and `unwrap_or(0)`.
- The path runs as part of the `tokio::try_join!` in `bootstrap()`, so
  the error surfaced as a top-level handler failure with no obvious
  trigger. A fresh `processed_ops` is the common case for any new
  database — every dev hit it.

### Dev seeder, accessible from the login screen

Refactor: the seeder used to live entirely inside `bin/seed.rs`. To
share it with an HTTP endpoint without standing up a `[lib]` target,
moved everything to `src/seed.rs` and pulled it into the bin via
`#[path = "../seed.rs"] mod seed;`. One source of truth, two callers.

- **`src/seed.rs`.** Public `wipe`, `seed_all`, `primary_user_id`. The
  fixture data (4 users, 3 projects, epics, sprints, tasks, time
  blocks, gcal events) is unchanged from sprint 01's binary; the only
  behavioral change is in `wipe`:
  - **Scopes user deletion to fixture rows** — `DELETE FROM users
    WHERE google_sub LIKE 'dev-%'`. Real Google-authenticated users
    survive a reseed, as do their sessions.
  - **Truncates `processed_ops`.** Replaying a logged op against a
    just-wiped database would either fail (referenced row gone) or
    resurrect stale state on peer clients. Better to start the
    change log fresh.
- **`bin/seed.rs`** is now a 30-line wrapper: open the pool, run
  migrations, `wipe` + `seed_all` in one transaction. Same CLI
  contract as before (`cargo run --bin seed`).
- **`GET /auth/config`.** Public, unauthenticated. Returns
  `{ dev_auth: bool }` so the SPA can decide whether to render the
  dev affordance — production builds (which don't set `DEV_AUTH=1`)
  see `false` and the button vanishes.
- **`POST /auth/dev-seed`.** Refuses to run unless `DEV_AUTH=1` (404
  in production). Wipes + reseeds inside a single transaction, then
  drops a session cookie for the primary fixture user (Maya). Returns
  `204 No Content`; the client follows up with a hard reload so
  `/me` + `/bootstrap` re-run against the fresh state.
- **Login UI.** `Login.tsx` calls `/auth/config` on mount. When
  `dev_auth` is true, a "Seed dev data & sign in" button renders
  below the Google button, dashed-border styling so it visually
  reads as "developer escape hatch, not a real auth method." Hint
  line: "Dev mode · wipes the database and signs you in as Maya."
  Errors render in red below.

## Decisions worth keeping

- **`#[path = "../seed.rs"]` over standing up a `[lib]` target.** The
  seeder is one of two binaries; a library target would mean
  rewiring `main.rs`, every `mod` declaration, and re-deciding what's
  `pub`. The `#[path]` attribute is the smaller change and reads
  exactly as "these two binaries share this file."
- **Seed-and-login is one button, not two.** A previous draft had the
  button only run the seeder, leaving the user to then click "Continue
  with Google". That re-introduces the original problem (Google login
  produces a different user_id from `u_maya`, scope is empty). Folding
  the session cookie into the same endpoint is what makes the demo
  dataset show up immediately.
- **Wipe scoped to `google_sub LIKE 'dev-%'`.** The original CLI
  seeder did `DELETE FROM users` unconditionally. Now the dev-seed
  endpoint can run on a database that already contains real Google
  users without nuking them. Same behavior in the CLI bin, which is
  almost certainly what the original wanted too.
- **Wipe `processed_ops` on reseed.** The change log can't outlive
  the rows it references — peer tabs polling `/changes` would either
  see ops that fail to apply (unknown task_id) or, worse, recreate
  stale state. Truncate is the correct invariant: after a reseed,
  the world starts at `cursor=0`.
- **404, not 403, when `DEV_AUTH=0`.** Prod-mode users shouldn't even
  learn the endpoint exists. Same pattern as `/auth/dev-login`.
- **Public `/auth/config`.** The login screen has to read it before
  any session exists, so it can't require auth. Returning a single
  boolean keeps the surface area minimal.
- **POST + 204 + manual reload, not GET + Redirect.** `dev-seed` is a
  destructive operation (wipes the DB); GETs shouldn't have side
  effects. The client does the reload after a successful POST so the
  store re-hydrates from scratch.

## Things that bit us

- The original `wipe` truncated `users` last and didn't think about
  sessions. A naive "drop all users" approach would have cascaded
  through every session. Scoping the delete to fixture users
  side-stepped both the CASCADE blast radius and the Google-user
  preservation question in one move.
- `MAX(seq)` returning a NULL row instead of zero rows is one of those
  SQL semantics that's obvious in retrospect — `SELECT MAX(...) FROM
  empty_table` is "one row, NULL value", not "zero rows". The sqlx
  error message (`try decoding as an Option`) actually told us the
  fix verbatim.

## Verification

```
$ cd api && cargo build --bins      # clean
$ cd web && pnpm exec tsc --noEmit  # clean
```

Manual:

| scenario                                                    | result |
|-------------------------------------------------------------|--------|
| Fresh DB, sign in via Google                                | `/bootstrap` returns 200 with empty scope |
| Login screen with `DEV_AUTH=1`                              | "Seed dev data & sign in" button renders |
| Login screen with `DEV_AUTH=0`                              | button hidden; `POST /auth/dev-seed` → 404 |
| Click "Seed dev data & sign in"                             | wipes DB, reseeds, lands on `/` signed in as Maya, full demo data visible |
| Real Google user exists, then click seeder                  | fixture rows replaced, real user + their session preserved |
| Re-click seeder while data is loaded                        | wipes, reseeds, reloads — no orphan rows, no stale change log |

## What's deferred

- **Picking which fixture user to log in as.** Right now it's always
  Maya. A small dropdown or query param could let a dev land as Anna,
  Bob, or Jin to test multi-user scope behavior without juggling
  cookies. Easy to add when needed.
- **Seed for the *currently signed-in* Google user.** The original
  request hinted at this, but folding the demo data into a real
  user's account muddles the "fixtures vs. real" line and would
  require either renaming Maya's rows or duplicating them. Punted —
  the dev-seed flow as built is enough for hand testing.
- **Per-table reseed.** The current button is all-or-nothing. A
  future "add a sample task to my project" affordance might want
  finer-grained inserts, but that's not a real need yet.

## Next sprint candidates

1. **Deployment** — still the next big rock from sprint 05.
2. **Real-time push (SSE)** — drop the 2s poll once the company-mode
   rollout feels the latency.
3. **Inline editing of task title + estimate in the inbox row** —
   carry-over from sprint 04 / 05.
