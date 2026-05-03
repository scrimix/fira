# Sprint 19 — Email-based workspace invites + textarea-vs-input

**Status:** shipped
**Date:** 2026-05-03

## Goal

Two unrelated user-blockers in one cleanup pass:

1. **Workspace membership was a closed system.** The "add member"
   affordance was a search of the global user table — fine for a
   pre-seeded dev environment, useless for actual onboarding. To get
   a teammate into a workspace they had to already be a Fira account
   the owner could find by name. Real users hit a wall.
2. **iCloud's "Hide My Email" QuickType chip kept popping up** on the
   inbox add-task input on Safari (desktop and iOS), even after we
   layered every `autocomplete` / `autocorrect` / `name` attribute we
   could think of in sprint 17 / 18. The chip is keyed off the
   *element type*, not the attributes — `<input>` triggers it,
   `<textarea>` doesn't.

Both got resolved in this sprint, plus a chain of fallout fixes from
the new invite flow as it ran into real-world testing.

## 1. textarea instead of input

The fix that finally worked: render the inbox add-task field as a
`<textarea rows={1}>` styled to look like a single-line input. iOS /
iCloud's "Hide My Email" heuristic doesn't fire on textareas. Same
font, same caret, same submit-on-Enter; Shift+Enter inserts a
newline (rare for tasks, harmless when it happens).

CSS in [inbox.css](../../web/src/styles/inbox.css):

```css
.task-add-input {
  /* same font / border / color as before, plus: */
  resize: none;
  overflow-y: hidden;
  min-height: calc(1.45em);
  width: 100%;
  display: block;
  vertical-align: top;
}
```

This is a "what works" fix, not an elegant one. Documented so the
next person doesn't waste a day on autocomplete attributes.

## 2. Workspace invites — full feature

### Data model

New table in
[migration 0014](../../api/migrations/0014_workspace_invites.sql):

```sql
CREATE TABLE workspace_invites (
    id            uuid primary key,
    workspace_id  uuid references workspaces(id) on delete cascade,
    email         text not null,           -- canonicalized lower+trim
    role          text not null default 'member' check (role in ('member','lead')),
    status        text not null check (status in ('pending','accepted','declined','cancelled')),
    invited_by    uuid references users(id),
    created_at    timestamptz default now(),
    resolved_at   timestamptz
);
CREATE UNIQUE INDEX workspace_invites_one_pending
    ON workspace_invites (workspace_id, email) WHERE status = 'pending';
```

Email is canonicalized at write so re-sending an invite for the
same address (regardless of casing) is idempotent.

### API

New module
[`api/src/invites.rs`](../../api/src/invites.rs) with four routes
under `/api/invites`:

- `GET    /` — list the caller's pending invites (sent + received).
  Direction (`'sent' | 'received'`) is derived from the caller's
  position relative to the row.
- `POST   /` — owner-only create. Validates email format, that the
  email isn't already an active workspace member, that no pending
  invite already exists for `(workspace, email)`. Idempotent: sending
  the same invite twice returns the existing row.
- `DELETE /:id` — sender or owner cancel. Pending → cancelled.
- `POST   /:id/accept` — recipient-only (canonical-email match).
  Pending → accepted, inserts into `workspace_members` with
  `ON CONFLICT DO UPDATE SET role = EXCLUDED.role, removed_at = NULL`
  so re-inviting a previously-removed user un-soft-deletes their row.
- `POST   /:id/decline` — recipient-only. Pending → declined.

Every state change fires per-user pubsub nudges
(`Hub::notify_user`) on the user channel so the inviter and the
recipient both see the modal/list update in real time, regardless of
which workspace they currently have open. Same delivery shape as the
account-linking flow — that pattern is now load-bearing for two
features.

The accept handler additionally fans out to every existing workspace
member so their member list refreshes when a new colleague joins.

[Bootstrap](../../api/src/lib.rs) now returns
`workspace_invites: Vec<WorkspaceInvite>` (pending only) so first
paint has the right state.

### Web

- New
  [`useFira` slice](../../web/src/store/index.ts):
  `workspaceInvites`, `reloadWorkspaceInvites`,
  `inviteToWorkspace`, `cancelWorkspaceInvite`,
  `acceptWorkspaceInvite`, `declineWorkspaceInvite`. `accept`
  captures the invite's `workspace_id` *before* clearing the row,
  then `await switchWorkspace(targetId)` so the recipient lands
  inside the workspace they just joined instead of staring at their
  personal workspace.
- [`api.ts`](../../web/src/api.ts) thin wrappers for the four
  routes.
- The user-channel WS handler in
  [`App.tsx`](../../web/src/App.tsx) now also calls
  `reloadWorkspaceInvites` alongside `reloadWorkspaces` and
  `reloadLinks`.
- [`WorkspaceInviteModal`](../../web/src/components/WorkspaceInviteModal.tsx)
  is the receive-side sticky modal — same shape as
  `LinkAccountModal`'s "received pending" state (mounted whenever a
  pending received invite exists; only Accept / Decline dismisses
  it). No privacy warning — joining a workspace is a low-risk
  action.
- [`WorkspaceModal`](../../web/src/components/WorkspaceModal.tsx)
  Members section: the global user search is gone. In its place a
  `WorkspaceInviteSection`: email input + role default + "Send
  invite" button, with a "Pending invites" list under it (each row
  shows email, role, sent-relative-time, and a Cancel button).
- New global CSS in [`globals.css`](../../web/src/styles/globals.css)
  for `.np-invites`, `.np-invite-row`, `.np-invite-input`,
  `.np-invites-pending`, `.np-invite-item`, `.np-invite-cancel`.

## 3. Remove workspace member — properly

This started as a "we left it out of sprint 14, time to add" and
turned into a refactor of the whole bulk-member-set surface. The
final shape is much cleaner.

### What changed (Web)

The old design was: `WorkspaceModal` kept a local copy of the
members array, the user clicked X → Remove → local filter, the user
then clicked Save Changes which sent the entire desired-set to
`PUT /workspaces/:id/members`. The local-staged-then-bulk-save
pattern was the source of multiple bugs — stale state when a remote
invite landed, removed-and-reappeared-on-refresh because the user
forgot to hit Save, etc.

Replaced with **one mutation per click, no staged state**:

- **Add a member** → invite-by-email only (the new section above).
- **Change a role** → the per-row Select calls
  `setWorkspaceMemberRole` immediately. One PATCH per change.
- **Remove a member** → click X (arms) → click Remove → opens
  `ConfirmDelete` requiring the user's email typed exactly → on
  confirm, fires
  `removeWorkspaceMember(workspace.id, uid)` directly. New API
  route `DELETE /api/workspaces/:id/members/:user_id`.
- **Save Changes** is now title-only. Disabled when the title is
  unchanged.

The displayed member list is now derived directly from
`workspace.members` via `useMemo` — invite acceptance, role change,
and removal all flow back through the same store path with zero
special handling. The resync useEffect, the `dirtyRef`, the
`memberSetEqual` helper — all gone.

### What changed (API)

[`workspaces.rs::remove_member`](../../api/src/workspaces.rs) is the
new `DELETE` handler. Owner-only; rejects self-removal (owners
transfer first); snapshots pre-state for nudge fan-out.

[`db.rs::remove_workspace_member_tx`](../../api/src/db.rs) sets
`removed_at = now()` on the `workspace_members` row, then calls
`soft_remove_project_members_tx` to soft-delete the user from every
project_members row in this workspace's projects.

The `project_members → workspace_members` FK has
`ON DELETE CASCADE`, but `workspace_members` is *soft*-deleted, so
the cascade never fires. Without the explicit
`soft_remove_project_members_tx`, an ex-workspace-member would
still appear as a project member.

### Side effects on tasks / time blocks

User direction during testing was clear: **don't touch them**. A
removed member did do those tasks and log that time — that's true
history, not stale data. The only cleanup is membership rows; the
content stays.

### Change-feed propagation

The remove handler emits two op kinds in the same transaction:

- One `workspace.set_members` op (the post-removal workspace
  member list).
- One `project.set_members` op per affected project (with the
  post-removal project member list, fetched via the new
  `list_project_members_tx` helper).

[`applyRemoteOp`](../../web/src/store/index.ts) gained handlers for
`workspace.set_members` and `workspace.set_member_role` so the
change-feed delivery patches `s.workspaces[i].members` in place —
the user-channel `reloadWorkspaces` is still the user-facing
backstop, but the change-feed path is more deterministic and
catches both the workspace and project list updates without a
manual refresh.

### Newly-added project member: hydrate

When a workspace owner adds the just-joined user to a project, the
new member's bootstrap predates that project, so an
`apply_remote_op('project.set_members')` patch is a no-op (the
project isn't in their `s.projects` to map over). New behavior in
`applyRemoteOp`: if the op is `project.set_members`, the local user
is in the new member list, *and* the project isn't in local state,
schedule a `get().hydrate()` on the next tick. The fresh bootstrap
pulls the project + tasks + blocks.

## 4. Cascading bug fixes from real-world testing

Not all in-line — listed here so the trail is recorded:

- **`getSnapshot` infinite loop** in `WorkspaceInviteSection`. Selector
  was returning `s.workspaceInvites.filter(...)` — fresh array
  every render → `useSyncExternalStore` re-fired forever. Fixed
  by reading the full array and deriving filtered list with
  `useMemo`. Same pattern sprint 14 hit and fixed in `TopBar`.
- **`is_workspace_owner(pool, ctx.user.id, body.workspace_id)`** had
  the args swapped — function signature is `(pool, workspace_id,
  user_id)`. Owner check returned false for everyone, so every
  invite POST returned 403 Forbidden.
- **`Joined Atlas` toast was red.** `showToast`'s second arg defaults
  to `'error'`; passed `'info'` explicitly for success/decline.
- **"Already a member" check ignored soft-delete.** Re-inviting a
  removed user returned the bad-request "already a member" because
  the SQL didn't filter `removed_at IS NULL`. Fixed.
- **`accept_workspace_invite_tx` left the old row soft-deleted.** The
  `INSERT ... ON CONFLICT DO NOTHING` skipped the existing row.
  Changed to `ON CONFLICT DO UPDATE SET role = EXCLUDED.role,
  removed_at = NULL` so re-accepting un-soft-deletes properly.
- **`RETURNING DISTINCT project_id`** is invalid Postgres. Removed
  the keyword from the SQL and dedupe in Rust via a `BTreeSet`.
- **Member list didn't refresh on the inviter side after accept.** The
  user-channel `reloadWorkspaces` *was* firing but somehow not
  propagating the new member into the open modal. Added the
  change-feed `apply_remote_op` handler for `workspace.set_members`
  as a deterministic backup path. Both paths now run; whichever
  arrives first wins.
- **Member list didn't refresh on the owner side after a removal**.
  The remove handler was only emitting `workspace.set_members`,
  not the per-project `project.set_members` ops. Added those.
- **Project list didn't refresh on the new member's side after they
  were added to a project.** The hydrate-on-newly-added case
  described above.
- **Buggy resync effect re-added the removed user.** A leftover
  effect from the staged-state era was running on workspace prop
  change and reverting local edits. Removed entirely once the
  staged-state went away.
- **"Save changes" button was committing membership.** Mentioned
  above but worth pulling out: the user explicitly wanted Save
  Changes scoped to title-only. The bulk member-set call is now
  not invoked from anywhere on the web side. The
  `setWorkspaceMembers` action and the `PUT /members` endpoint
  stay in place for completeness / future bulk needs.
- **Add-member picker rendered below the modal fold.** In the
  *project* modal (not the workspace one), the picker opened
  off-screen below the member list. Fixed with
  `scrollIntoView({ block: 'end', behavior: 'instant' })` on
  the picker ref + `scroll-margin-bottom: 24px` in CSS so the
  picker doesn't slam against the actions row.

## Decisions worth remembering

- **One mutation per click beats staged + save.** The bulk
  set-members pattern looked clean but produced two classes of
  bugs: stale local state when the server side changed mid-edit,
  and silent "did nothing" when the user clicked Remove and forgot
  to Save. Per-action mutations cost an extra round trip but
  match the user's mental model and don't have those failure
  modes. The `removeWorkspaceMember` / `setWorkspaceMemberRole`
  pair replaced a single `setWorkspaceMembers` and the membership
  UX got noticeably less surprising.
- **Two paths to the same store update is fine; one path is
  fragile.** Workspace member changes propagate via *both* the
  user-channel WS nudge → `reloadWorkspaces`, and via the
  workspace-channel change feed → `applyRemoteOp`
  patch-in-place. Either one is enough; together they're robust
  against either delivery being slow or dropped. We had a real
  bug where the user-channel path silently didn't update the
  modal, and the change-feed path saved us once we added the
  handler.
- **Soft-delete cascades aren't free.** `workspace_members` is
  soft-deleted (sets `removed_at`), so the
  `project_members → workspace_members` FK with
  `ON DELETE CASCADE` doesn't fire. Whenever you soft-delete a row
  whose hard-delete would cascade, *also* soft-delete the rows
  that the FK would have caught. Quiet bug otherwise — you'll
  notice it months later when an ex-employee shows up in a
  project member list.
- **textarea suppresses iOS QuickType chips that input doesn't.**
  After every `autocomplete` / `autocorrect` / `name` value we
  could think of, the only thing that worked was changing the
  *element type*. Add to the playbook: when iOS heuristics are
  flagging a single-line text field as something it isn't,
  switching to `<textarea rows={1}>` styled like an input is the
  pragmatic escape hatch.
- **Re-inviting a removed user is a happy path, not an edge case.**
  The first cut treated it as "already a member" or "row exists".
  Real onboarding flow: invite Alice, Alice accepts, Alice gets
  removed (mistake / tested), invite Alice again. The accept SQL
  needs `ON CONFLICT DO UPDATE` not `DO NOTHING`, and the
  pre-invite check needs to look only at active membership. Both
  fall out naturally if you remember soft-delete is the model.

## What we noticed but didn't fix

- **Email delivery.** Invites are in-app modal only. If the
  recipient isn't logged in (or doesn't have the app open), they
  see the modal on next sign-in via the bootstrap-included
  pending-invites list. No SMTP / SES / whatever yet. Probably
  fine for now; a v2 nice-to-have.
- **Pre-registration invites for not-yet-signed-up emails.** They
  *technically* work — the invite row sits in pending with the
  email, and as soon as someone signs in with a matching email
  the bootstrap surfaces it. But there's no signup-time hookup
  that wires the new account to existing invites; we rely on the
  email match at bootstrap time. Hasn't been smoke-tested with a
  brand-new Google account.
- **Decline visibility on the sender side.** Once declined, the
  invite drops out of the inviter's pending list silently — no
  toast, no notification. The inviter notices the absence rather
  than the decline. Acceptable for v1; could surface as a quiet
  toast later.
- **No "leave workspace" affordance for non-owner members.** Today
  only the owner can remove a member. A member who wants to leave
  has to ask. Should add a "Leave workspace" button for self-
  removal.
- **Tag feature still parked** (deferred from the previous turn —
  conversation log has the design sketch).
