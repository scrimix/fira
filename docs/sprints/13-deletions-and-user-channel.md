# Sprint 13 — Deletions, sync hygiene, and the user channel

**Status:** shipped
**Date:** 2026-05-02

## Goal

Three threads:

1. **Destructive flows.** Tasks, projects, and workspaces all needed
   delete buttons with appropriate confirmation. Tasks already had subtask
   delete and the modal scaffolding; projects and workspaces had nothing,
   and "delete a workspace" forced us to think about how membership
   changes propagate to other clients.
2. **Sync hygiene.** Server-rejected ops were silently auto-retrying
   forever and leaving phantom local mutations. The user couldn't see
   *why* an op failed, and discarding a failed op left the local state
   inconsistent with the server.
3. **Real-time membership / role / workspace events.** Adding a member
   to a workspace didn't update anyone's UI in real time — neither the
   new member's nor the existing members'. The change-feed scoping
   gates on workspace membership, so the very op that *grants*
   membership has nowhere to be delivered. Needed a second transport.

## 1. Destructive flows

### Shared confirm dialog

A new `ConfirmDelete` component (web/src/components/ConfirmDelete.tsx)
that overlays the parent modal with a small backdrop dialog. Two modes:

- **Plain confirm** (tasks): focus on the Delete button, Esc cancels,
  Enter confirms.
- **Type-to-confirm** (projects, workspaces): the user has to type the
  entity's name into an input. Delete button stays disabled until the
  typed string matches. Same focus/keyboard handling otherwise.

Type-to-confirm is the "additional guard" for higher-blast-radius
deletions — projects wipe every task, sprint, epic, block, and
membership inside them; workspaces wipe everything in every project
plus the workspace itself.

### Task delete

Added a `task.delete` op kind end-to-end:

- `OpKind` extended in `web/src/store/outbox.ts`.
- `Op::TaskDelete { task_id: Uuid }` variant added to `api/src/ops.rs`,
  with handler that scopes by `ensure_task_in_scope` and runs a single
  `DELETE FROM tasks WHERE id = $1`. Subtasks and `time_blocks` cascade
  via existing FK constraints; we don't enumerate.
- Frontend store action mirrors the existing `deleteSubtask` shape:
  filters tasks + their blocks, clears `openTaskId` if it matched,
  pushes the op.
- `applyOpToState` case symmetrical with the action so remote echoes
  drop the same state.

UI: trash icon button in the task modal header (next to close), opens
the confirm dialog, on confirm calls `deleteTask` and closes the modal.

### Project delete

Owner-only `DELETE /projects/:id` route. Workspace owners can delete;
project leads can edit but not delete (asymmetric on purpose — an
errant lead shouldn't be able to wipe a project). Cascade handles the
entity tree.

The propagation op is a synthesized `project.delete` written through
`record_workspace_op` with `project_id = NULL` so it routes to every
workspace member through `/changes`, not just members of a project that
no longer exists. Other clients receive the op and drop the project
locally via a new `applyOpToState` case (filters tasks/blocks/epics/
sprints, fixes `inboxFilter` if it was pointed at the deleted project,
closes the project modal if it was editing it).

### Workspace delete

Owner-only `DELETE /workspaces/:id`. Personal workspaces are off-limits
(server rejects, frontend hides the button). Cascade handles the entity
tree (projects and through them everything else, plus
`workspace_members`).

There is **no workspace-scoped op** for workspace.delete — that event
is delivered exclusively through the user channel (see §3). The
deleter handles their own local state inline (filters out the
workspace, closes any open workspace modal) and calls the new
`reloadWorkspaces` action; other members receive a user-channel nudge
and reload the same way.

### Migration 0010 — durable processed_ops

`processed_ops.project_id` and `.workspace_id` had `ON DELETE CASCADE`
referencing the parent tables. That meant a project-delete cascade
wiped the very `project.delete` log row that announced it.

The migration drops both FK constraints. `workspace_id` and
`project_id` are now historical pointers that may reference deleted
rows. The `/changes` query already handles missing parents (the
EXISTS / IN checks naturally yield nothing for vanished projects); the
log row's job is to deliver the announcement once and then linger as
audit history.

## 2. Sync hygiene

### Stop auto-retrying server-rejected ops

`syncOutbox` previously re-batched any non-`syncing` op, which meant
errored ops re-entered the next 2 s tick and re-failed forever. Tightened
to:

```ts
if (outbox.some((o) => o.status === 'error')) return;
const batch = outbox.filter((o) => o.status === 'queued').slice(...);
```

So a single rejected op blocks the queue (preserves order — ops are
intent-based and depend on each other, so skipping a failed earlier op
would orphan its dependents). Network failures still re-queue and
retry — the catch block puts them back to `queued`, which the guard
allows through.

User-driven resolution stays on the existing SyncPill popover (Retry /
Discard / Retry All / Discard All).

### Toasts for actually surfacing errors

API errors used to vanish into the console. The `req()` wrapper threw
`HttpError` with just `path → status`, swallowing the
`{ "error": "..." }` body the server sent.

- `HttpError` now carries an optional body string, and `req()`
  parses the JSON envelope before throwing — so the server's actual
  message reaches the catch site.
- New `toasts` slice on the store (`Toast[]`, `showToast`,
  `dismissToast`). Errors auto-dismiss after 6 s, info after 3 s;
  click to dismiss early.
- `Toasts` component is a bottom-right stack with an explicit
  `<X size={14}>` button. The error variant uses `--danger` for the
  border + text and `color-mix(in oklab, --paper 92%, --danger)` for
  the background — soft enough not to blast, contrasty enough that
  the X stays visible.
- Wired into the project + workspace modal save / delete catches.
- `syncOutbox` also fires a toast when the per-op results come back
  with rejections — the SyncPill counter alone doesn't say *why*, and
  the actual server message ("`unknown variant 'task.create1'`,
  expected one of …") is exactly what the user needs to fix it.

### Auto-resync after the failed-ops queue drains

Discarding a failed op leaves the local optimistic mutation in place
while the server never saw it — phantoms. Reverting per op was tempting
(every op needs an inverse, snapshot the pre-state at push time, apply
on discard) but turned into a lot of code for an edge case.

Simpler model that covers the user's real flow:

- Discard / retry the failed ops as you like — the popover stays
  open, the failed-ops list stays put, you can iterate.
- The moment the outbox is fully drained (no errored, no queued, no
  syncing), call `hydrate()`. `/bootstrap` is the cheapest reset to
  ground truth and wipes any local phantoms.

Implementation is a one-line helper called from `discardOp`,
`discardAllFailed`, and the success branch of `syncOutbox` (the last
catches the case where the user retried all failed ops and the retry
just succeeded). The `syncOutbox` call is gated on the previous
`syncStatus.kind === 'error'` so a normal sync of a clean queue
doesn't trigger a needless re-bootstrap.

## 3. Real-time membership / role / workspace events

### The chicken-and-egg

The existing `/api/ws?workspace_id=` socket and `/api/changes` feed
both gate on workspace membership. That works for in-workspace data
ops — every existing member has a socket on the workspace, every
member receives the nudge. But it breaks for events that *decide*
membership:

- A newly added member has no socket on the workspace (they just got
  added) — the workspace.set_members op nudges, but they're not
  subscribed.
- A removed member's `workspace_members.removed_at` is set, so the
  /changes membership EXISTS check excludes them — they never see the
  op that kicked them out.
- A workspace.delete cascade wipes `workspace_members` entirely, so
  even existing members lose authorization to receive the op
  announcing the delete.

We considered (and prototyped, then reverted) two alternatives:

- **Soft-delete workspace_members and relax /changes for ex-members.**
  Mirrors the existing `project.set_members` pattern. Worked for the
  removed-member case but didn't help newly-added members at all (they
  have no row before the op). Also coupled membership lifecycle to op
  visibility in a way that snowballed across handlers.
- **Soft-delete workspaces and keep workspace_members alive.** Same
  issue, plus required a `deleted_at` column and filter clauses across
  every workspace-reading query.

### What we shipped: a separate user channel

A dedicated transport for events that decide workspace surface, scoped
by session instead of by membership.

**Backend** (`api/src/pubsub.rs`, `api/src/ws.rs`, `api/src/main.rs`):

- `Hub` gains a per-user `broadcast::Sender<()>` keyed by `user_id`.
- A second pg_notify channel `user_changes` carries just the `user_id`
  string. The same `PgListener` task LISTENs on both channels and
  dispatches into local hubs based on `n.channel()`.
- `Hub::notify_user(pool, user_id)` writes the pg_notify; cross-instance
  fan-out works identically to the existing ops_changes path.
- `/api/ws/user` is session-only (no workspace gate) and pumps opaque
  `{ "user_changed": true }` frames on each notification. Same heartbeat
  /reconnect shape as the ops socket.

**Workspace handlers** (`api/src/workspaces.rs`) all snapshot the affected
user set and fan out user nudges after commit:

- `create` → notify the creator (covers their other tabs / devices).
- `rename` → notify every active member (title shows in their list).
- `set_members` → notify `pre ∪ post` (added users, removed users,
  retained members all need to refetch).
- `set_member_role` → notify every active member.
- `delete` → snapshot members before the cascade, notify them after
  commit. No workspace-scoped change-feed op for this event — the user
  channel is the only delivery path.

**Frontend** (`web/src/ws.ts`, `web/src/store/index.ts`, `web/src/App.tsx`):

- `openUserSocket(onNudge)` mirrors `openNudgeSocket` but URL-only,
  no workspace_id.
- `App.tsx` opens it once per signed-in session (gated on `meId &&
  !playgroundMode`), independent of the active workspace.
- New `reloadWorkspaces` store action: refetch `listMyWorkspaces`,
  diff against current state, auto-switch to a fallback (personal
  first) if the active workspace disappeared, otherwise just replace
  the array and recompute `myWorkspaceRole` from the new active
  workspace's member list.

The dual-channel design lets each transport be simple. The ops channel
keeps its strict membership scoping; the user channel carries the
"your workspace surface changed" opaque signal and pays for it with
one extra LISTEN and one socket per user.

### Decisions worth remembering

- **A failed op is not the same as an offline op.** The 4xx-rejection
  case ("`only workspace owners can delete`") needs human input to
  unblock — auto-retry just races the user. The network/5xx case is
  transient and should retry. The two paths must look different to
  the loop.
- **An op log row should outlive its referenced entities.** Tying
  `processed_ops` cascade to `projects`/`workspaces` meant the very
  op that announced a deletion got cascade-wiped by it. Audit logs
  should be append-only and durable; FK cascade was the wrong tool
  for keeping the table clean. (Cleanup of orphaned log rows is a
  separate job.)
- **Don't try to invert every op.** Per-op inverses sound general
  (snapshot pre-state at push time, apply on discard) but you end up
  designing against the entire op surface. A `hydrate()` after the
  queue drains gets you 95% of the same outcome with one helper
  function.
- **Don't mix transports across event classes.** Membership / role
  / workspace events have a different scope rule than in-workspace
  data ops — gating on the same membership table that the events
  *modify* is the chicken-and-egg. Carving them into a dedicated
  per-user channel is much cleaner than relaxing the existing
  channel's scoping until it accommodates both.
- **Toast contrast matters.** Soft-red errors with a darker-red text
  read as a unit, but a `currentColor` X button on that background is
  visually invisible. Bumping the icon's hover background to
  `color-mix(in oklab, --danger 18%, transparent)` gave it a hit
  target the user can actually see.

## Bug fixes along the way

- **Workspace delete order-of-operations.** The store action was
  calling `switchWorkspace(fallback)` before `api.deleteWorkspace(id)`,
  which flipped the `x-workspace-id` header to the fallback. The
  server's owner check then failed `ctx.workspace_id != id` and
  rejected with 400. Fix: snapshot the fallback up front, run the
  DELETE while the header still matches the target, switch after.
- **WebSocket "closed before connection established" warnings.** React
  StrictMode mounts the WS effect twice in dev; the cleanup ran
  `socket.close()` while the WS was still in `CONNECTING`. Patched
  both `openNudgeSocket` and `openUserSocket` to defer close until
  `OPEN` (or skip it entirely if cleanup runs first — the eventual
  onopen sees the `closed` flag and closes cleanly). Functional
  behavior was already fine; just silenced the noise.
- **TaskModal subtask spacing.** The list container used `gap: 4`
  (vs the inbox's `gap: 2`) and the delete button was `22 × 22 px`
  forcing taller rows. Tightened to match.
- **TaskModal width.** Bumped from 720 → 840 px (still capped at 92vw).

## Decisions worth remembering

- **`ConfirmDelete` is one component with optional `confirmName`.**
  Resisted having two separate components for "simple delete" and
  "type-to-confirm delete" — the optional prop keeps the call sites
  symmetric and the focus management in one place. Tasks pass no
  `confirmName`; projects and workspaces pass the entity title.
- **Backend authorization for project / workspace mutations stays
  active-context.** `ctx.workspace_id != id` rejecting cross-context
  mutations is correct — the user is "in" a workspace and the API
  treats their membership in that workspace as the authorization
  scope. The frontend just needs to be careful about header
  ordering (see workspace-delete bug above). We considered relaxing
  to "owner of target" lookups but it broadens the attack surface
  for not much gain.

## What we noticed but didn't fix

- **Cleanup job for orphaned `processed_ops` rows.** Migration 0010
  intentionally lets log rows linger past their entities. Eventually
  we'll want a periodic GC to keep the table from growing forever.
  Low priority — log rows are ~200 bytes each and the change feed
  query naturally ignores stale ones.
- **Dev container Vite port.** `.devcontainer/docker-compose.dev.yml`
  has `5174:5173` instead of `5173:5173` — the host port no longer
  matches the container port 1:1. Diagnosed (was probably auto-bumped
  when 5173 was busy at compose time) but not patched in this sprint.
- **Newly-added member's *visible UI* in their existing tabs is
  refetched, but the WS connection to the new workspace's data
  channel still requires switching to it.** That's by design — the
  ops socket stays workspace-scoped — but if we ever want
  cross-workspace background activity (notifications,
  badge counts), the user channel is where to add it.
