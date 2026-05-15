# Sprint 27 — Stress testing: load harness, scaling cliffs, fixes

**Status:** complete
**Date:** 2026-05-15

## Goal

Find out where the app falls over. Build a repeatable load harness, seed
a database far larger than anything the dev fixture exercises, drive it
with hundreds-to-thousands of concurrent users, and measure. Fix the
acute bugs the load surfaces. The *architectural* scaling fix (don't ship
the whole workspace at once) is explicitly out of scope here — this
sprint is about measuring it and clearing the bugs in the way.

Everything runs against a **separate `fira_stress` database** and a
**dedicated API instance on `:3100`**, so the dev fixture DB and the
`:3000` API are never touched.

## 1. The harness

Three new pieces, all under `api/src/bin/` + `scripts/`:

- **`stress_seed`** — bulk seeder. Generates the synthetic dataset and
  streams it in via Postgres `COPY` (text format, flushed in 50k-row
  chunks). A full seed is ~40s. `--maya` is an idempotent fast path that
  (re)creates just the Maya dev user without a reseed.
- **`stress_load`** — load client (`tokio` + `reqwest`). Spawns N virtual
  users; each bootstraps once, then loops a weighted pick over ~21 sample
  operations with 150–900ms think-time, until a deadline. ~70% reads
  (`/bootstrap`, `/changes`, `/projects`, `/me`) / ~30% writes (the full
  `/ops` surface). Records per-operation latency histograms
  (p50/p90/p95/p99/max), throughput, and error class.
- **`scripts/dev-stress-api.sh`** — launches the standard `fira-api`
  binary against `fira_stress` on `:3100`, release build, with a wider
  DB pool. `web/` gets a matching `pnpm dev:stress` (Vite on `:5175`
  proxying to `:3100`).

Auth for the load client: the seeder mints one session per user tagged
`user_agent='loadtest'`. The client discovers them by querying the DB
directly — see §6.

The **Maya dev user** (`maya@fira.dev`, fixed ids) is seeded into
`fira_stress` so the login page's "Sign in as Maya" button works against
the stress env; she owns her personal workspace plus the first two
shared workspaces.

`api/src/main.rs` gained a `DB_MAX_CONNECTIONS` env knob (default 5, the
prod posture). Load tests run at 100 — a 5-deep pool just measures pool
queueing, not the app.

## 2. The dataset, and why it was resized

First cut: **20 workspaces × 5 projects × 10k tasks = 1,000,000 tasks**,
10k users. This was too big on *every* axis (see §3–§4) and not a
realistic per-workspace shape. Final profile:

| | value |
|---|---|
| workspaces | 50 |
| projects | 3 / workspace = 150 |
| users | 40 / workspace = 2,000 |
| project members | 10–15 / project (round-robin so every user lands in one) |
| tasks | 2,000 / project = **300,000**, ~70% in `done` |
| tags | realistic vocabulary (`UI`, `CORE`, `BUG`, `API`, `perf`, …), 75% of tasks linked |

A workspace is now ~6k tasks instead of 50k — deliberately under the
client-side ceiling found in §4.

## 3. Finding 1 — bootstrap connection fan-out (server)

The headline bug. At 1,000 concurrent users on the 1M-task dataset:
**throughput 327 req/s, `bootstrap` p50 ~25s, 46% of bootstraps failing**
(client-side 30s timeout). Even `/me` — one indexed session lookup — sat
at p50 686ms. The whole process was starved.

Cause: `load_bootstrap` ([lib.rs](../../api/src/lib.rs)) issued its 12
hydrate queries via `tokio::try_join!`, **each on `&PgPool`** — so a
single bootstrap acquired up to **12 pool connections at once**.
`list_tasks_in_scope` fanned out 2 more internally. With a 100-connection
pool, only ~8 concurrent bootstraps exhausted it; every other query —
in bootstrap *and* every other endpoint — then blocked on
`acquire_timeout` and failed. The fan-out made one isolated bootstrap
slightly faster and made the system fall over ~12× sooner under load.

Fix: run the hydrate queries **sequentially** — one pooled connection per
bootstrap at a time, not twelve. The latency cost is negligible: the
`tasks` query (50k rows, ~2s) dominates; the other eleven are
sub-millisecond. `list_tasks_in_scope`'s inner `try_join!` was
sequentialised for the same reason.

This is a general lesson: `try_join!` over `&PgPool` is a connection
*multiplier*. Parallel-looks-faster, but under concurrency it's a
pool-exhaustion amplifier.

## 4. Finding 2 — the `localStorage` quota wall (client)

The Zustand store persists the whole workspace to `localStorage` via the
`persist` middleware. A 50k-task workspace bootstrap is ~31MB of JSON;
`localStorage`'s quota is ~5MB per origin. Browsing such a workspace
throws `QuotaExceededError` inside `applyBootstrap` — the offline cache,
the entire point of the local-first store, silently dies above roughly
**~8k tasks per workspace** (≈ 5MB ÷ ~600 bytes/task).

It's a *hard* wall — untickeable. This is the client-side mirror of §3:
the 50k-task workspace is too big for the DB query, the wire, *and* the
browser cache.

Not fixed this sprint — addressed by **right-sizing**: medium workspaces
are 6k tasks, under the ceiling, so Maya can browse them. The real fix
(IndexedDB-backed persistence, or `partialize` the big arrays out, or the
bounded-payload work in §8) is deferred.

## 5. Finding 3 — WS-nudge fan-out (client)

A workspace under sustained write load degraded *every* connected
browser. The server emits one WS nudge per committed op; `App.tsx` wired
each nudge straight to `syncOutbox()` + `pollChanges()`, with **no
debounce and no in-flight guard** on the pull. A burst of N nudges fired
N concurrent `GET /changes` — and since `pollChanges` only advances the
cursor on completion, the overlapping requests all re-pulled and
re-applied the *same* rows on a stale cursor. Self-amplifying: the tab
janks, falls behind, the next batch is bigger.

Fix:
- `App.tsx` — the nudge handler now **debounces** (200ms) and
  **coalesces**: an in-flight guard + `pending` flag means a burst of any
  size collapses to one sync plus at most one catch-up pass. `/changes`
  already returns up to 500 ops, so one pull drains the backlog.
- `store/index.ts` — `pollChanges` got a module-level in-flight guard, so
  the 60s-interval and focus/online callers can't race it either.

## 6. Finding 4 — `applyRemoteOp` trusts partial op payloads (client)

`<InboxView>` crashed: `Cannot read properties of undefined (reading
'localeCompare')` — the `byKey` sort comparator hit a task with no
`sort_key`.

Cause: `applyRemoteOp` pushed `task.create` / `subtask.create` op
payloads into the store **raw**. The server's `TaskInput` /
`SubtaskInput` mark `sort_key` (and most fields) `#[serde(default)]` — a
create op is wire-legal *without* them, and the server fills defaults.
But the change feed re-broadcasts the original, partial payload, so a
client applying it stored a task with `sort_key: undefined`, which throws
in every section sort. The store had no invariant that its tasks were
well-formed.

Fix: `normalizeTask` / `normalizeSubtask` helpers fill every optional
field with the same default the server uses (`sort_key → 'M'`,
`spent_min → 0`, …). `applyRemoteOp` runs create payloads through them;
`onRehydrateStorage` runs persisted tasks through them too, so
`localStorage` contaminated before the fix self-heals on reload.

The load client's synthetic `task.create` omitted `sort_key`, which is
what triggered it — but the gap is real: the wire format permits partial
create payloads and the frontend has to apply the same defaults the
backend does.

## 7. Harness bugs found along the way

Stress tooling has its own bugs; worth recording so they aren't
re-discovered:

- **Session map drift.** The seeder first wrote a `loadtest-map.json`
  (token → user → workspace) for the client. Session tokens came from a
  *seeded* RNG (deterministic) but all UUIDs from `Uuid::new_v4()`
  (random) — so after a reseed the tokens still matched while every
  workspace id had changed. The stale map half-matched: `/me` passed,
  every `AuthCtx` endpoint 403'd. Fixed properly by deleting the map
  file: the load client now queries `sessions WHERE
  user_agent='loadtest'` straight from the DB. One source of truth, can't
  drift.
- **Load-script artifacts, not app bugs.** `task.set_tags` initially
  showed 97% errors — the script paired a random task with workspace-wide
  random tags, and the server *correctly* rejects cross-project tag sets.
  `tag.create` collided on titles across reruns. Both fixed in the load
  client; flagged here so the numbers aren't misread as server faults.

## 8. Results

Final run — medium dataset, 1,000 concurrent users, 60s + 20s ramp,
`DB_MAX_CONNECTIONS=100`:

| | value |
|---|---|
| requests | 109,230 |
| throughput | **1,336 req/s** |
| transport failures / 503s | **0 / 0** |
| per-op errors | 4 (0.004% — `task.set_tags` on tasks deleted mid-flight; a correct rejection) |
| `bootstrap` | p50 57ms · p95 3.6s · max 4.1s |
| `changes` | p50 5ms · p99 640ms |
| writes (`task.*`, `block.*`, …) | p50 ~20ms · p99 ~1.0s |

For contrast, the **before** picture — 1M-task dataset, pre-§3-fix,
1,000 users: 327 req/s, `bootstrap` p50 ~25s, 46% bootstrap errors.

The medium profile holds up cleanly under 1,000 concurrent users. The
connection fan-out fix is what removed the failures; the dataset resize
is what kept `bootstrap` fast and inside the `localStorage` ceiling.

## 9. Deferred

- **Bounded bootstrap — the real scaling fix.** `/bootstrap` ships the
  entire workspace. It's the cliff on three axes at once (DB query, 31MB
  wire payload, `localStorage`). The cure is to *not* send 50k tasks:
  lazy-load per project, paginate, or exclude archival `done` tasks, and
  lean on the existing `/changes` + cursor machinery so a full bootstrap
  becomes a once-per-device event. Architectural; its own sprint.
- **Op-apply backpressure.** Under thousands of ops/sec into one
  workspace the UI thrashes — one re-render per op. The fix is not "drop
  changes" but *defer* them: batch the apply (one render per animation
  frame), and above a rate threshold trip to a deferred *"N changes —
  click to refresh"* banner. Note the scenario is largely synthetic — a
  real workspace sees ops per *minute*, not per millisecond.
- **Client persistence** — IndexedDB storage (much larger quota) or
  `partialize` the task arrays out of `localStorage` entirely.
- **Response compression** (`tower-http` `CompressionLayer`) — ~8–10× on
  the bootstrap payload for free on real (non-loopback) networks.
- **Rate limiting on `/ops`** — there is none; a load test is also a
  self-DoS surface.

## Files

- `api/src/bin/stress_seed.rs`, `api/src/bin/stress_load.rs` — new.
- `scripts/dev-stress-api.sh`, `web` `pnpm dev:stress` — new.
- `api/src/main.rs` — `DB_MAX_CONNECTIONS` env knob.
- `api/src/lib.rs`, `api/src/db.rs` — sequential hydrate queries (§3).
- `web/src/App.tsx`, `web/src/store/index.ts` — nudge coalescing (§5),
  task normalization (§6).
