# Sprint 05 — Sync (push + pull)

**Status:** done
**Date:** 2026-04-30

## Goal

Sprints 01–04 left the outbox accumulating and reads frozen-at-mount.
This sprint makes the local-first round-trip real: a sync worker drains
the outbox to the server, and a change feed pushes other clients' edits
back so two tabs (or two devices, or two teammates) converge without a
manual refresh. Architectural choice up front: log-based pull over a
shared cursor, modeled on Linear/Replicache. The same `processed_ops`
table that gives us idempotency on the way in gets a `seq BIGSERIAL`
and becomes the change log on the way out.

## What shipped

### Push: `POST /ops` + outbox sync worker

- **Server.** New `ops.rs` module, serde-tagged `Op` enum mirroring the
  client's `OpKind` union (16 variants: `task.create`, `task.tick`,
  `task.set_*`, `task.reorder`, `subtask.*`, `block.*`).
  - `POST /ops` accepts `{ ops: [{ op_id, payload }, ...] }`, applies
    each in its own transaction (one bad op never blocks the rest of
    the batch), returns `{ results: [{ op_id, status, error? }] }`.
  - **Idempotency** via `processed_ops`: each op tries to claim its
    `op_id` via `INSERT ... ON CONFLICT DO NOTHING RETURNING seq`. PK
    conflict means a concurrent retry already won; we roll back the
    whole transaction so the mutation can never be double-applied.
  - **Authorization** via `project_scope`: every op resolves the affected
    project_id (task → project, subtask → task → project, block → task →
    project) and rejects with `task not in scope` (etc.) if the caller
    isn't an owner or member. Cross-tenant writes can't sneak through.

- **Client.** `syncOutbox()` action in the store:
  - Bails if a sync is in flight (re-entrant safe).
  - Picks up to 50 queued ops, marks them `syncing`, POSTs.
  - On `ok` from the server, drops the op from the outbox.
  - On `error`, flips the op to `error` status (kept for visibility +
    retry), records the first error message in `syncStatus`.
  - On network failure, reverts the batch to `queued` and flips
    `syncStatus` to `offline` so the next tick retries.
  - Driven by a 2s `setInterval` plus opportunistic ticks on `focus` and
    `online` events.

- **Sync status pill in the topbar.** Lucide `Check / Loader2 / Alert
  Triangle / CloudOff` icons, color-toned by state:
  - `Synced` (default ink-3 muted).
  - `N pending` (cyan accent + accent-soft background) while ops queue.
  - `Syncing…` (spinning loader, accent border).
  - `Offline` (warn amber background) when the request fails outright.
  - `Error · N` (danger red background) when the server rejected ops.
  Click the pill to force an immediate sync.

### Pull: `GET /changes` + change-feed cursor

- **`processed_ops` becomes the change log.** Migration `0004_op_log.sql`
  adds `seq BIGSERIAL` (the monotonic global cursor), `payload JSONB`
  (the original wire op verbatim), `project_id UUID` (for scope
  filtering on read). Index `(seq, project_id)` is the hot path.

- **Apply path rewritten.** `OpEnvelope.payload` is now `serde_json::Value`
  — we deserialize a typed `Op` from it for dispatch, but persist the
  raw JSON so peer clients can replay it through the same handlers
  they use for local mutations. `apply_payload` returns the captured
  `project_id` via an out-parameter so the log row has it for free.

- **`GET /changes?since=N`.** Filters by `seq > N AND project_id IN
  (caller's project_scope)`. Returns up to 500 rows + the new cursor.
  This is where the membership-based scoping pays off: a member of
  project A never sees ops from project B, and a new member of A
  retroactively sees its full history because the scope just grows.

- **`Bootstrap.cursor`.** The hydrate response now includes the current
  `MAX(seq)`. Fresh clients start polling from there, not from 0.

- **Project mutations also write to the log.** `POST /projects` and
  `PATCH /projects/:id` now run in a transaction that also writes a
  synthesized `project.create` / `project.update` op via
  `record_synthesized_op`. Peer clients receive the full project
  payload through the same poll path as task ops.

- **Client poll worker.** `pollChanges()` action:
  - Hits `/changes?since=cursor`.
  - For each returned op: if its `op_id` is in the local `appliedOpIds`
    set, skip (it's an echo of our own write). Otherwise, dispatch
    through `applyRemoteOp`.
  - Advances `cursor` to the response's new high-water mark.
  - GCs `appliedOpIds` entries older than 5 min — by that point any
    echo will have either arrived or been lost.

- **`applyRemoteOp` + `applyOpToState` (pure dispatch).** Handles all
  16 client op kinds plus `project.create` / `project.update`.
  Upsert-tolerant by design — applying the same op twice (echo +
  local) is a no-op, deletes against missing rows are no-ops. Adds
  the op_id to `appliedOpIds` after applying so a re-poll can't
  re-apply.

- **`pushOp` helper** in the store replaces the old `enqueue`. Every
  local mutation now records its op_id in `appliedOpIds` at the
  moment of enqueueing — push side primes the suppression set
  before the echo can arrive.

- **App tick chain.** Every 2 s: `syncOutbox().then(pollChanges)`.
  Push first so own ops hit `appliedOpIds` before the echo arrives.

### Schema

- `0003_ops.sql` — initial `processed_ops` (PK `op_id`, `user_id`,
  `kind`, `applied_at`).
- `0004_op_log.sql` — adds `seq`, `payload`, `project_id` + indexes.
  Splitting the migration in two kept the "what's the idempotency
  table" mental model intact, then evolved it into "log table".

## Decisions worth keeping

- **One row in `processed_ops` per accepted op.** Idempotency claim
  and log entry are the same row. Two failure modes collapse into
  one — if you can't write the row, the mutation rolls back.
- **Per-op transactions, not per-batch.** A stale `task_id` in op #3
  shouldn't poison ops #1, #2, #4. Per-op gives the client a clean
  per-result error to surface.
- **Wire payload stored verbatim as JSONB.** We could re-derive the
  payload from the structured `Op` and re-serialize, but the
  round-trip is fragile (extra fields silently dropped, ordering
  drift in JSON keys, future op kinds requiring a re-encode pass).
  Storing the original Value is the simplest replay path.
- **Cursor advances via `/changes` only, never via `/ops` response.**
  If client A and client B both write between A's polls, A's seqs
  could interleave with B's. Letting `/ops` advance A's cursor
  would skip B's interleaved ops. So `/ops` returns success/error
  per op; `/changes` is the only authority on cursor position.
- **`appliedOpIds` set, not "ignore ops where user_id == me".** The
  server doesn't tag log rows with the originating client; multiple
  tabs of the same user are still distinct clients that each want
  to receive each other's writes. Op_id is the right discriminator.
- **5-minute TTL on `appliedOpIds`.** The poll cadence is 2 s; an
  echo of one's own op arrives within seconds. 5 min is a comfortable
  safety margin that doesn't grow the set unboundedly.
- **Project mutations log a *Project* payload** (the full row, not
  diffed `{title?, icon?, color?}`). Peer clients run the same
  upsert codepath whether they're seeing a creation or an update —
  uniform shape, simpler client.
- **`project_scope` derived per-request.** No caching. At 40
  concurrent users with maybe 20 projects each, the union query is
  microseconds. When that stops being true we can cache, but
  premature caching of authorization checks is a recipe for
  permission leaks.
- **Push then pull in the tick.** Self-echo ordering matters: if
  pull runs first against a fresh server-side write of our own op,
  we'd apply it to local state (which already has it) before our
  push registers in `appliedOpIds`. Push first guarantees the
  suppression set is primed.

## Things that bit us

- `tokio::try_join!` over functions returning different `Result<_,
  E>` types. The fix was making `current_cursor` return
  `sqlx::Result<i64>` so it composes with the other db calls.
- Pattern matching on `Op` enum variants while *also* keeping the
  raw JSON payload to store: solved by carrying both the typed
  `Op` (for dispatch) and `serde_json::Value` (for storage)
  separately on the path, instead of trying to round-trip back to
  JSON after consuming the typed value.
- The first apply path INSERT'd into `processed_ops` *before*
  applying the mutation, then never updated the row with the
  payload + project_id (because the apply consumed the value).
  Restructured to apply first, capture project_id, then INSERT
  with full info. Tx rollback on PK conflict undoes the apply.

## Things that surprised in a good way

- The op kinds the client was already enqueueing turned out to map
  to 1-line UPDATE statements on the server side for almost
  everything. Two months of "we'll add server writes later, the
  outbox will be ready" turned into a single afternoon of straight
  copy-paste-style handlers because the op shape was right.
- Echo suppression via `appliedOpIds` Just Worked the first time —
  no double-apply, no flicker, no race. The discipline of "intent
  payloads, not diffs" carrying through both push and pull was the
  load-bearing decision.

## What's deferred

- **Long-poll or SSE for sub-second propagation.** Polling at 2 s is
  fine for now and gracefully degrades to 5-10 s if we want to
  back off. SSE would mean a `tokio::sync::broadcast` keyed on
  user_id and managing a long-lived `text/event-stream`. Worth doing
  once the company-mode rollout actually feels the latency.
- **Conflict UI.** Today, last-write-wins. With intent-shaped ops
  (set_title, set_section) that's almost always the right call —
  the user typing later got the more recent intent. Where it's
  wrong (two people typing different titles into the same task at
  once) is the conflict-detection / divergence-display problem
  alluded to by the deferred Relay sync-engine.
- **Per-user rate limit on `/ops`.** A misbehaving client could
  flood the log. Trivial to add (simple counter in Redis, or
  even an in-memory `tokio::sync::Mutex<HashMap>` keyed on
  user_id) once we're paying attention.
- **Compaction of the log.** Every op stays forever. At our op
  rate (10s per user per day) this is months before we'd notice.
  Eventually: a daily job that archives anything older than
  `MAX(cursor) - retention_window` to cold storage.
- **Bootstrap-aware cursor reset.** If a user's `project_scope`
  shrinks (kicked from a project), their cursor still points at
  `seq` values for ops they can no longer see. Today the server
  filters them out, so it's safe but not "clean". A `bootstrap`
  call resets correctly. A live "membership change" event would
  also have to bump the cursor — punted.

## Verification

```
$ DEV_AUTH=1 cargo run                      # api on :3000
$ pnpm typecheck                            # web — no errors
```

Smoke matrix (run from the server-side smoke test, all green):

| scenario                                    | result |
|---------------------------------------------|--------|
| `POST /ops` two ops                         | both `ok`, DB updated |
| Replay same op_ids                          | both `ok`, DB unchanged |
| Cross-tenant op (random task UUID)          | per-op `error: "task not in scope"` |
| `/ops` with no auth                         | `401 unauthorized` |
| `block.create` → `block.update(state=completed)` → `block.delete` | DB reflects each step, final count = 0 |
| `task.create` → `subtask.create` → `subtask.tick` | row + child + done=true |
| Bootstrap returns cursor                    | initial `MAX(seq)` |
| `/changes?since=K` after two ops at K+1, K+2 | both rows returned with full payloads |
| Maya mutates Helix-only task (Anna not a member) | Anna's `/changes` empty |
| Maya mutates the same task                  | Maya's `/changes` shows it |
| `POST /projects`                            | log row carries `project.create` payload, full project blob |

Browser UX: tab A creates a task → pill flicks `1 pending` → `Syncing…`
→ `Synced` within 2 s. Tab B (same user, same browser) catches up on
the next tick — task appears in the inbox without a refresh. Anna
(member of Atlas) sees Maya's Atlas writes propagate; Anna does not see
Maya's Helix-only writes. Refresh either tab — state is exactly what
the other tab thinks it is.

## Next sprint candidates

1. **Deployment.** Fly.io for API + web + Postgres, Cloudflare for the
   `usefira.app` domain, GitHub Actions for `flyctl deploy` on push to
   master.
2. **Real-time push (SSE).** Drop the 2s poll for live broadcasts when
   the user-count justifies it.
3. **Inline editing of task title + estimate in the inbox row** —
   carry-over from sprint 04. Now that writes flow to the DB, the
   payoff is real (vs. invisible in local-only state).
4. **Conflict surfacing for divergent intents** (rare, but the
   sync-engine's design space is now relevant).
