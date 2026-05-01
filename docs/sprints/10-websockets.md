# Sprint 10 — WebSocket nudges for the change feed

**Status:** shipped
**Date:** 2026-05-01

## Goal

Sprint 05 closed the local-first round-trip with a 2 s pull on
`GET /api/changes?since=cursor`. That cadence is fine for one tab but
visibly laggy when two people are looking at the same workspace —
"open this task and edit, watch the other tab take 0–2 s to reflect."
Worse, every tab is paying for the poll whether or not anything has
changed.

This sprint replaces the constant pull with a server push: when an op
commits, the server sends a small "new cursor available" nudge over a
WebSocket and the client triggers the existing `/changes` fetch. The
2 s timer goes away on the read side; a 60 s fallback poll covers the
case where the WS is dead. Multi-instance fan-out comes through
Postgres `LISTEN / NOTIFY` so it works once Fly scales beyond a single
machine.

## Topology

**Nudge-only protocol.** The wire payload is `{"new_cursor": N}` and
nothing else — no op data, no scoping logic. Clients react by calling
the existing `/api/changes?since=cursor` exactly as they did with the
poll. Server-side scope filtering, idempotency dedup
(`appliedOpIds`), batching — all unchanged. The WS is a *signal*, not
a delivery channel.

Why nudge over push: the `/changes` endpoint already encodes the
workspace + project + membership scope, the `seq`-based cursor is
already idempotent, and the client already debounces dup ops by
`op_id`. Pushing payloads would duplicate that surface. Pushing
nudges keeps one source of truth.

## Architecture

```
┌─────────┐    pg_notify      ┌──────────────┐
│ writer  │  ──────────────▶  │  Postgres    │
│ (any    │  (in same tx as   │  ops_changes │
│ machine)│   processed_ops   │  channel     │
└─────────┘   insert)         └──────┬───────┘
                                     │  LISTEN
                ┌────────────────────┼────────────────────┐
                ▼                    ▼                    ▼
         ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
         │ machine A    │     │ machine B    │     │ machine N    │
         │ PgListener   │     │ PgListener   │     │ PgListener   │
         │      │       │     │      │       │     │      │       │
         │      ▼       │     │      ▼       │     │      ▼       │
         │ Hub (local)  │     │ Hub (local)  │     │ Hub (local)  │
         │ broadcast    │     │ broadcast    │     │ broadcast    │
         │      │       │     │      │       │     │      │       │
         │   WS clients │     │   WS clients │     │   WS clients │
         └──────────────┘     └──────────────┘     └──────────────┘
```

- **`pg_notify` is the cross-machine bus.** Issued from the same
  transaction as the `processed_ops` insert. NOTIFY is transactional
  in Postgres: the message fires only on commit, so a rolled-back op
  never nudges anyone. Payload is `<workspace_uuid>:<seq>` — under
  the 8 KB NOTIFY limit by orders of magnitude.
- **`PgListener` per process is the local entry point.** One
  long-lived dedicated connection per API instance, started at boot,
  re-spawns on error with 5 s backoff. Receives every commit's
  notification regardless of which instance wrote it.
- **`Hub` is the in-process fan-out.** A
  `Mutex<HashMap<workspace_id, broadcast::Sender<seq>>>`. The
  listener task feeds it; WS handlers subscribe to it. Single
  responsibility, single source of within-process delivery.

The split matters: `pg_notify` is the only path that crosses
machines; `Hub` is the only path that reaches local clients. The
write path doesn't talk to `Hub` directly — that would skip the
cross-instance bus and create asymmetric behavior between
"originating machine" and "everybody else."

## What landed

### 1. Backend module split

- [`api/src/pubsub.rs`](../../api/src/pubsub.rs) — `Hub` type,
  `start_listener_task` that holds a `PgListener` and forwards every
  `ops_changes` notification into the Hub. `format_payload` /
  `parse_payload` keep the wire format in one place so the writer and
  reader can't drift.
- [`api/src/ws.rs`](../../api/src/ws.rs) — `GET /api/ws?workspace_id=…`.
  Auth via the same `sid` cookie as the REST routes (browsers can't
  set custom headers on WS, so the workspace comes via query string,
  not the `X-Workspace-Id` header). Membership check, then a single
  `tokio::select!` loop that pumps Hub → socket and runs a 30 s
  server ping so Fly's edge / intermediaries don't idle the
  connection out at ~60 s.
- [`api/src/main.rs`](../../api/src/main.rs) — `Hub` plumbed into
  `AppState`, listener task spawned in `main`, `/ws` registered under
  the same `/api` nest as the REST routes.

### 2. NOTIFY at the write boundary

[`apply_one`](../../api/src/ops.rs) inserts into `processed_ops`,
captures the returned `seq`, and issues
`SELECT pg_notify('ops_changes', '<workspace>:<seq>')` *inside the
same transaction*. Same pattern in `record_synthesized_op` (project
REST writes) and `record_workspace_op` (workspace REST writes), both
of which now `RETURNING seq` and emit the notify before the caller
commits. One source of truth: no commit happens without a notify, no
notify fires without a commit.

### 3. Frontend

- [`web/src/ws.ts`](../../web/src/ws.ts) — `openNudgeSocket(workspaceId,
  onNudge)`. Auto-reconnect with 1 → 30 s exponential backoff.
  `wss://` in prod, `ws://` in dev — derived from
  `window.location.protocol`.
- [`web/src/App.tsx`](../../web/src/App.tsx) — opens one socket per
  active workspace (close + reopen on workspace switch). Each nudge
  triggers `syncOutbox().then(pollChanges)` — same path as the timer,
  so ordering and dedup behave identically whether the trigger is a
  nudge or a fallback tick.

### 4. Cadence split (regressed-and-fixed mid-sprint)

The first cut bundled `syncOutbox` and `pollChanges` into one 60 s
timer, with the WS handling real-time on top. That was wrong: it
also slowed the *write* side, because outbox flush rides the same
ticker. Locally-queued mutations were sitting up to 60 s before
hitting the server, so the nudge log on the receiving end showed
"30 s late" — the commit itself was 30 s late, the nudge was on time.

Final shape, two timers:
- `syncOutbox` — 2 s (unchanged from sprint 05). Push side stays
  fast.
- `pollChanges` — 60 s. Pure fallback for missed nudges.
- WS nudge — runs `syncOutbox + pollChanges` on every tick (so a
  remote change still triggers an immediate local catchup of any
  pending writes).

### 5. Local multi-instance test rig

Single-machine dev was hiding the cross-instance leg. Added:

- [`scripts/dev-second-api.sh`](../../scripts/dev-second-api.sh) — runs
  a second API on `:3001` against the same Postgres.
- [`web/vite.config.ts`](../../web/vite.config.ts) — env-driven
  (`API_HOST`, `API_PORT`, `PORT`) and `ws: true` on the proxy so WS
  upgrades pass through.
- [`web/package.json`](../../web/package.json) — `pnpm dev:second`
  runs Vite on `:5174` against API `:3001`.

Workflow: `cargo run` (API 3000) + `scripts/dev-second-api.sh` (API
3001) + `pnpm dev` (web 5173 → API 3000) + `pnpm dev:second` (web
5174 → API 3001). Open one browser tab per Vite. Edit in tab 1 →
tab 2's WS receives the nudge via Postgres NOTIFY crossing the
instance boundary.

## Decisions worth remembering

- **Nudge-only protocol.** Avoids re-implementing `/changes`'s
  scoping rules over the socket and keeps the existing dedup +
  ordering logic as the single source of truth.
- **Cookie + query string for WS auth.** The browser WS API can't
  set arbitrary headers, so `X-Workspace-Id` doesn't transfer; we
  read `?workspace_id=…` instead and reuse the same membership check
  the REST `AuthCtx` extractor performs.
- **Postgres `LISTEN/NOTIFY` over Redis.** Postgres is already in
  the stack. Adding Redis just for pub/sub would mean another moving
  part to deploy, monitor, and pay for. NOTIFY is transactional with
  the op insert, which is a real correctness win — no
  "nudged-but-rolled-back" race.
- **Listener task uses a dedicated connection.**
  `PgListener::connect_with(pool)` opens its own connection rather
  than borrowing-and-returning to the pool. A LISTEN that's returned
  to the pool would either drop subscriptions or pollute random
  borrowers' state.
- **Server-side ping every 30 s.** Fly's edge and most LB / proxy
  layers idle WS connections after ~60 s of silence. Without the
  ping, a low-traffic workspace would silently drop the socket and
  rely on the client's reconnect to recover. Cheap insurance.
- **Hub is fed *only* by the listener.** Mid-sprint we tried having
  the originating machine also dispatch directly to its local Hub to
  shortcut the pg_notify round-trip. Reverted: it created two
  delivery paths with different semantics (originating machine
  instant, others via NOTIFY) and that asymmetry makes diagnostics
  harder. One path, slightly slower for the originator, much
  cleaner.

## What we noticed but didn't fix

- **Backoff is per-tab, not workspace-wide.** If a user opens five
  tabs they get five WS connections. Could share via
  `BroadcastChannel` + a leader election, but five sockets per user
  is not yet a real cost.
- **No replay on reconnect.** Reconnect just resumes from "now"; any
  ops that committed during the disconnect are picked up by the
  60 s fallback poll, with up to ~60 s of latency in the worst
  case. Fine for now; a `?since=cursor` on the WS upgrade could
  shrink that to <1 s if it ever bites.
- **Hub map grows monotonically.** One `broadcast::Sender` per
  workspace ever subscribed-to or notified-about, never reaped. At
  one entry per workspace it's nothing; at hundreds of thousands it
  would be. GC strategy: a periodic sweep that drops entries with
  `receiver_count() == 0` and no recent dispatch. Defer.
- **`PgListener` reconnect window.** If the listener connection
  drops, NOTIFY messages issued during the window between
  disconnect and re-LISTEN are lost. Acceptable: the 60 s fallback
  catches them. If we ever want true gap-free delivery, the listener
  could query `MAX(seq)` on reconnect and fan out everything new.

## Near-future

- **Sprint 09's deferred items still stand** (sessions GC, pg_dump
  backup, rate limit on `/api/ops`, deploy-from-CI, observability).
- **Replay-on-WS-open** for sub-second reconnect catchup (above).
- **`processed_ops` GC.** Eventually a row's `seq` is older than any
  client's `appliedOpIds` TTL on every device; the row is no longer
  serving anyone. Trim with a cron once we know the longest-lived
  client offline window.
