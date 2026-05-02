# Sprint 14 — Account linking and the personal-workspace overlay

**Status:** shipped
**Date:** 2026-05-02

## Goal

A person owns one timeline. The product had been fragmenting it across
two boundaries:

1. **Two accounts.** Personal Gmail and work Google sign-in are
   different Fira users with different sessions. The user wants a
   single calendar that reflects "what I'm actually busy with on
   Tuesday" without context-switching between tabs.
2. **Two workspaces inside one account.** Even within a single
   account, the calendar a user is looking at is scoped to whichever
   workspace they currently have active. If their personal workspace
   has a Tuesday morning block planned and they're in the team
   workspace, the team calendar pretends that block doesn't exist.

Both share the work-life-balance angle, and both wanted the same UX
shape: an opt-in, read-only overlay you can toggle on without leaving
the workspace you're in. The data already exists server-side; the
sprint is about consenting to share it (across accounts) and
projecting it (across workspaces).

## 1. Account linking

### Data model — migration 0011

```sql
CREATE TABLE user_links (
    id            uuid primary key default gen_random_uuid(),
    user_a_id     uuid not null references users(id) on delete cascade,
    user_b_id     uuid not null references users(id) on delete cascade,
    requested_by  uuid not null references users(id) on delete cascade,
    status        text not null check (status in ('pending', 'accepted')),
    created_at    timestamptz not null default now(),
    accepted_at   timestamptz,
    check (user_a_id < user_b_id),
    check (requested_by in (user_a_id, user_b_id)),
    unique (user_a_id, user_b_id)
);
CREATE UNIQUE INDEX user_links_one_accepted_a
    ON user_links (user_a_id) WHERE status = 'accepted';
CREATE UNIQUE INDEX user_links_one_accepted_b
    ON user_links (user_b_id) WHERE status = 'accepted';
```

Pair canonicalization (`a < b`) gives one row per unordered pair so
the unique index does what it says. `requested_by` distinguishes who
initiated. Two **partial** unique indexes (one per side, scoped to
`status = 'accepted'`) enforce the "one accepted link per user" rule
in the database — pending requests can stack up to multiple targets
but only one can ever be accepted at a time.

### HTTP surface (api/src/links.rs)

```
GET    /api/links                  list every link involving me
POST   /api/links                  { email: string }      create pending
DELETE /api/links/:id              cancel sent / decline received / unlink
POST   /api/links/:id/accept       only the non-requester can accept
GET    /api/linked/calendar        read-only overlay (blocks + tasks + gcal)
```

Authorization rules:

- **Create.** Caller types the partner's email; server lower-cases and
  trims, looks the user up, returns 400 "no Fira account found for
  that email" on miss. No workspace co-membership required — linking
  is consent between two account owners regardless of which workspaces
  they share, if any.
- **Accept.** Only the non-requester side of a pending link.
- **Cancel / unlink.** Either party (mirrors how workspace-member
  removals work — both ends can sever).

The "one link per user in any state" check fires before insert so the
UI's empty-state assumption holds even with concurrent requests.

We started with a workspace-member picker (the brief said "select
from accounts in workspace") but flipped to email-only halfway through
when it became clear the workspace dependency is incidental: the
relationship is between two account owners, and tying it to a shared
workspace makes the cross-account case worse, not better. The picker
is gone; `LinkAccountModal` now has a single email input.

### Cross-workspace nudges via the user channel

Linking is inherently cross-workspace — the two parties might only
share one workspace (the one the request was sent from), or none at
all once unlinked. Handlers fan out through `Hub::notify_user` (added
in sprint 13) on every state change so the partner refreshes even
when they're looking at a different workspace. There is no
workspace-scoped op for `link.*` — same model as `workspace.delete`.

`reloadLinks()` on the frontend is the user-channel handler: it diffs
the new list, refetches the partner overlay if the link became (or
stayed) accepted, and clears the cached overlay if it disappeared, so
a stale partner snapshot can't leak after unlink.

### LinkAccountModal — one shell, four states

```
┌─ Link account ────────────────┐
│  Pair this account with ...   │
│  [ name@example.com       ]   │
│  [ Clear ]      [ Send invite]│
└───────────────────────────────┘
```

Driven entirely by `links` state. Same priority order as the topbar
icon — received > sent > accepted > none — so the most actionable
card always renders first if multiple coexist.

- **none** → email input + Send invite.
- **sent (pending)** → "Waiting for <Name>" + Cancel request.
- **received (pending)** → "<Name> wants to link with you" + Accept /
  Decline. **Sticky:** the modal pops on first paint, on every
  refresh, and on every tab; Esc, the X, and the backdrop are all no-
  ops in this state. Only Accept or Decline can clear it, and both
  clear it because both delete the row server-side. Persistence is
  the database row, not any client state.
- **accepted** → "Linked with <Name>" + Unlink.

### TopBar — paired identity chip

When a link is accepted, the trailing slot of the topbar swaps from
the standalone `topbar-me` chip to a paired display:

```
[Log out]  [SC] <link icon> [MR]
```

Two `topbar-me`-styled black-box-with-letters chips (me + partner)
with a small lucide `Link` icon between them. Clicking the pair opens
the modal (Unlink / Close).

For the unaccepted states the link button is just a borderless lucide
`Link` icon next to Log out, color-tinted by state: muted by default,
accent for received (calls for attention), dimmed for sent (waiting).

### Bootstrap surface

`Bootstrap` gains `links: Vec<UserLink>` so the topbar icon can
render the right state on first paint without a follow-up fetch.

`list_users_in_scope` was caller + workspace members; it now also
unions in **every link partner** (sent / received / accepted)
regardless of workspace. Without this the topbar's
`users.find(partner_id)` returned `undefined` after the email-based
lookup, since the partner might not be in any workspace the caller
shares — the paired chip wouldn't render.

### Linked calendar overlay

`GET /api/linked/calendar` returns the partner's blocks + a minimal
task projection (title, status, project_color) + their gcal events.
Read-only by design — the UI never sends ops back against these IDs.
Cross-workspace because the linked partner's data lives wherever
they work.

`db::list_blocks_for_user(partner_id)` returns blocks across **every**
workspace the partner belongs to. Linking is mutual consent to share
the calendar, so the workspace scope rule that gates everything else
doesn't apply — a `db::are_linked` check before the projection is the
gate instead.

`LinkedTask` is a deliberate shadow type. It mirrors enough of `Task`
to render the block (title, status for done-state styling, project
color) but doesn't pollute the global `tasks` array — overlay items
must never be drag-and-droppable, ID-collision-prone, or written
back to.

`CalendarView` has a "Show linked" toggle next to the user picker
(visible only when there's an accepted link AND the user is on their
own calendar tab — switching to a teammate's view drops the overlay).
Linked blocks render as `.tblock-linked`: full column width, lower
z-index, opacity 0.55, dashed border. Linked gcal events get a dotted
border + 0.55 opacity so "their busy time" stays visually subordinate
to "your busy time".

## 2. Personal-workspace overlay

The same shape as account linking, but inside a single account. The
user is in a team workspace, has time blocks planned in their
personal workspace, and wants to see both at once without switching.

### HTTP surface

```
GET /api/personal/calendar    blocks + LinkedTask projection
```

Returns empty when the active workspace already *is* the personal one
(the data is already in `bootstrap.blocks/tasks`, no need to
duplicate). No gcal field — gcal events are tied to the user, not a
workspace, so they're already in `bootstrap.gcal`.

### Reuse the same projection

We chose to reuse `LinkedTask` rather than introduce a sibling type.
The fields (`id`, `title`, `status`, `project_color`) are exactly
what either overlay needs; semantically "linked" was already a hint
that the type is the read-only overlay shape, not a workspace
relationship. Adding a `PersonalTask` alias would just split the
projection across two equivalent types.

`db::list_blocks_in_workspace_for_user(workspace_id, user_id)` and
`db::list_linked_tasks_in_workspace_for_user(workspace_id, user_id)`
mirror the linked variants but scope by `(workspace, user)` instead
of "all blocks this user owns".

### Frontend — second toggle, distinct visual

`CalendarView` gets a second "Show personal" / "Hide personal" toggle
in the toolbar, visible only when the active workspace is a team
workspace AND the user is on their own tab. Personal-overlay blocks
render as `.tblock-personal`: same full-column-width, read-only
posture as `.tblock-linked`, but with a **left project-color stripe**
(`border-left: 3px solid <proj>`) instead of a dashed border, and
opacity 0.7 instead of 0.55. The two overlays don't mush together
visually if the user has both on at the same time.

`showPersonal` is persisted in the zustand snapshot like `showLinked`,
but cleared on `switchWorkspace` because the toggle's meaning is
workspace-relative — a user who flipped it on in workspace A
shouldn't have it pre-flipped in workspace B.

`loadPersonalCalendar()` runs once per workspace switch, gated on
`inTeamWorkspace`. In the personal workspace, the endpoint returns
empty and the toggle is hidden, so no unnecessary fetches.

## Bug fixes along the way

- **`useSyncExternalStore` infinite loop in TopBar.** The first
  `linkState` selector returned a fresh `{ kind: 'none' as const }`
  object literal on every call. Zustand v4 uses
  `useSyncExternalStore`, which calls the selector twice per commit
  and forces a rerender if the two results aren't `Object.is`-equal.
  Fresh object literals each call → React believes the store
  perpetually updates → "Maximum update depth exceeded" crash. Fix:
  subscribe to `links` and `users` directly (those references are
  stable across unrelated store updates) and derive `linkState`
  outside the selector. **Lesson:** selector returns must be
  reference-stable for the same input, full stop. Computed objects
  belong outside `useFira`.
- **Partner missing from `bootstrap.users`.** `list_users_in_scope`
  had only caller + workspace members; once linking dropped the
  workspace requirement, the partner could be in zero workspaces the
  caller shared, so the topbar's `users.find(partner_id)` returned
  `undefined` and the paired chip silently didn't render. Union'ed
  link partners (any status) into the user list — they were already
  needed for the modal headline ("<Name> wants to link") in all
  three pending-state directions anyway.
- **`Show linked` button white-on-cream.** The active-state CSS used
  `color: var(--accent-fg)` (white) on a barely-tinted paper
  background — illegible. Changed to the codebase's standard active-
  pill convention: `color: var(--accent)` text, `var(--accent-soft)`
  background, `var(--accent-line)` border. Same look as the user-
  picker pills.

## Decisions worth remembering

- **Two transports beats one with branching.** Account linking and
  personal-overlay both deliver "calendar items that aren't yours to
  edit". They have separate endpoints, separate state slices,
  separate render paths, and separate visual treatment. We considered
  fusing them into one `overlays` slice and deciding at render time —
  rejected because the privacy/consent posture is fundamentally
  different (cross-account requires explicit acceptance; cross-
  workspace within an account is just a projection of data the user
  already owns), and a single API would have to encode both. The
  shared `LinkedTask` type and the matching toolbar-toggle UX give
  enough symmetry; the rest stays separated.
- **Modal-open from server state, not client state.** The
  received-pending modal is sticky because the row exists, not
  because the client toggled `linkModalOpen`. App.tsx renders
  `<LinkAccountModal>` whenever `linkModalOpen || hasPendingReceived`
  — the second clause is a pure derivation from `links`. There's no
  "have I auto-opened this id yet" tracking. Refresh / new tab / Esc
  all behave the same way: while the row exists, the modal is up.
  Acting on it deletes the row and the modal naturally goes away.
  This is a much smaller mental model than "open exactly once per
  session per request id".
- **Email lookup beats workspace picker for cross-account
  linking.** The original brief said "select from accounts in
  workspace", which made sense as a discoverability mechanism, but
  the actual pairing relationship is account-to-account, not
  workspace-relative. Forcing the linkable set through a shared
  workspace makes the case the feature most wants to support
  (different orgs entirely) the hardest one. An email field is the
  smaller, more honest interface — the "is this user a Fira account"
  miss case becomes the only validation we owe the user, and the
  server already had that lookup for OAuth.
- **Restart > recompile.** When the API rejected `{ email }` with
  "missing field `target_user_id`" while the source clearly had
  `email`, the running binary was stale. The watch loop builds; the
  Docker / dev process doesn't auto-restart. Worth saying out loud:
  "rebuild the binary" and "the new code is running" are different
  facts.

## What we noticed but didn't fix

- **Email invites for non-Fira accounts.** Right now `POST /links`
  with an email that doesn't match any user returns 400. A future
  pass should send an "invitation to sign up + auto-link on first
  login" email. Out of scope here — gets us into transactional email
  infrastructure and an inbound-OAuth-claim flow. The current
  workspace-add path is the workaround: the user signs up first,
  then links.
- **Multiple accepted links per user.** Hard-cap'd to one for now
  via the partial unique indexes. The product premise is "one
  person, two accounts, one timeline", so a 1-1 link captures it.
  If we ever want a "team calendar overlay" pattern (your manager,
  your two reports), the model needs to flex to N partners and the
  overlay UI to a list — both deferred until there's a real demand.
- **Drag-to-create on the linked overlay.** The personal-workspace
  overlay shares `tblock` styling with the active calendar; a
  pointer-down on the day column starts the create-drag flow even
  when the press intersects a `.tblock-personal`. Currently the
  read-only overlay is full-column-width and z-index 1, so the
  ghost from a press-on-personal-block looks weird. Cheap fix is to
  intercept `pointerdown` on `.tblock-personal`/`.tblock-linked`
  the way the existing handler intercepts `.tblock` and `.gcal-evt`
  — left for next sprint.
- **Personal overlay's per-block click action.** Linked / personal
  blocks are read-only and currently do nothing on click. A natural
  next step is "click → switch to that workspace and open that
  task" (one-tap context switch). Defer until we have a case where
  the user actually wants to edit, not just see.
