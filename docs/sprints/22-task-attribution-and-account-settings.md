# Sprint 22 — Task attribution + account settings

**Status:** shipped
**Date:** 2026-05-05

## Goal

Two strands that landed together:

1. **Plug holes in the task record.** Tasks lose information today —
   you can land in someone else's group with no assignee and no signal
   about who put it there, and the Done section sorts by `created_at`
   which only approximates "most recently finished". Add `created_by`
   and `finished_at` so the modal can surface the creator and the
   inbox can sort Done newest-finished-first.

2. **First step on a real account-settings home.** The topbar's
   "two avatars + link button" cluster was already overloaded;
   adding a Google Calendar connection on top would have made it
   incomprehensible. Move identity-shaped affordances behind one
   avatar that opens a proper modal, and seed it with the link
   affordance, a stubbed gcal row, and a personal/work mode badge
   — a tiny first preference that lets us prove out the
   per-user-settings table end-to-end.

The two strands share a layer: both required schema changes, both
touched the bootstrap shape, and both are stepping stones to bigger
features (creator → assignment workflows; settings → gcal).

Plus a few smaller fixups along the way: a Me/All toggle on the
inbox, a redesigned Section picker in the task modal, and the
SectionEditor / StatusEditor popovers finally escaping the modal
sidebar's `overflow: auto` via a portal.

## 1. `created_by` + `finished_at`

Migration `0017_task_created_by_and_finished_at.sql` adds:

```
tasks.created_by  uuid references users(id) on delete set null
tasks.finished_at timestamptz
```

Both nullable to cover legacy rows. Backfill defaults `created_by` to
`assignee_id` (the closest proxy we have for pre-migration tasks —
most tasks are self-created); `finished_at` stays null on existing
rows and the inbox falls back to `created_at` for the Done sort.

**`created_by` is server-stamped from the actor.** The `task.create`
op handler binds `user_id` (the authenticated caller) into the INSERT
regardless of what's in the wire payload. The local store still puts
`meId` on the optimistic `Task` it constructs so the echoed op carries
the right value to peer clients without a second `/changes` round.

**`finished_at` is server-managed via the existing tick / set_status
ops.** A new SQL CASE on those updates stamps `now()` on transitions
into `'done'` and clears it on transitions out — no new op kind,
which keeps the wire surface tight. Web mirrors the same logic in
both the optimistic mutation and `applyOpToState` (echoed remote ops),
approximating with the local clock since the op envelope doesn't
carry the server's `applied_at`. Sub-second drift only matters for
the Done-section sort tiebreak.

Inbox Done sort becomes `(b.finished_at ?? b.created_at)` so legacy
rows still sort sensibly. Modal side pane gets a new "Created by"
field with avatar + name (`(you)` suffix for self, "Removed user"
fallback when the user_id is dangling).

The seed inserts `created_by = assignee` and stamps `finished_at` for
seeded done rows; `dump-bootstrap` regenerated against the new schema.

## 2. Account settings modal

Replaces the topbar cluster (`partner avatar | link button | own
avatar | Log out`) with a single own-avatar button that opens
`AccountSettingsModal`. The new modal hosts:

- **Identity card.** Avatar + name + email at the top.
- **Linked account.** State-aware sentence (none / sent / received /
  accepted) plus the same link button as before — clicking opens the
  existing `LinkAccountModal` for the actual flow. The
  received-pending sticky modal is unchanged because the link row is
  server-persisted and pops independent of this menu.
- **Google Calendar.** Stub row: disabled "Connect" button + "Coming
  soon" hint. Costs nothing today and signals where the affordance
  will live.
- **Mode badge.** Personal / work / none segmented pill, same idiom
  as the inbox `or/and` and `me/all` controls.
- **Log out.** Bottom-right.

This is the first modal that's not workspace-scoped — it's about
the account, independent of which workspace the caller is in.

## 3. Server-persisted user settings

The mode badge initially lived in localStorage — easy and obvious,
but it doesn't follow the user across devices, which is exactly what
the user is going to expect from any setting they pick. Promoted to
the database before the pattern set.

Migration `0018_user_settings.sql`:

```
user_settings(user_id PK fk users, account_badge text check ('personal' | 'work'), updated_at)
```

One row per user, missing-row = "no preferences set yet". Built as
the home for future preferences (gcal connection metadata, theme,
default-view) — adding a field is a column + a `UserSettings`
struct field + a line in the PATCH route, no new table per setting.

`Bootstrap.settings: UserSettings` ships on every `/api/bootstrap`
call so the badge is hydrated at boot, no separate request.
`PATCH /api/me/settings` accepts a partial; serde tri-state
(`Option<Option<T>>` via a `deserialize_some` helper) distinguishes
"field absent → leave alone" from "field null → clear". The web
`setAccountBadge` action does optimistic local update + PATCH, with
a revert + toast on failure. Playground mode skips the network call
since there's no backend.

## 4. Topbar badge — flush, not floating

First pass had a 4 px gap between the badge and the avatar. The
adjacent-sibling CSS rule (`.topbar-badge + .topbar-me`) didn't help
because the topbar is a flex row with `gap: 12px` — gap beats margin.

Wrapped both into a single `<div class="topbar-account">` with its
own `gap: 0`, so the parent's gap can't slot whitespace between
them. Inside the wrapper the badge drops its right border so the
two share a single 1 px seam. Saturated mode color (accent for
personal, warn-amber for work, white text on both) so it reads at
a glance.

## 5. Section picker mirrors the Status picker

`<Select<Section>>` in the task modal was a generic dropdown that
didn't match the `StatusEditor`'s colored pill — small visual
inconsistency, but the modal already feels of-a-piece on every
other field. Replaced with a `SectionEditor` that shares the
`status-trigger` / `status-popover` / `status-option` classes;
each section gets a tone reused from the status palette
(`now`→now, `later`→todo, `someday`→backlog, `done`→done).

Refactored both editors to share a generic `TonedPicker` since the
shapes were now identical save for the value type.

While we were here:

- Dropped the `✓ ` `::before` pseudo on selected options (looked
  redundant against the pill trigger that already shows the
  current value); selected option now indicated by a `paper-3`
  background fill.
- Portaled the popover to `document.body` with `position: fixed`,
  anchored under the trigger via `getBoundingClientRect`. Same
  pattern `TagEditor` uses. Without it the popover was clipped by
  `.modal-side`'s `overflow: auto` and required scrolling the
  modal sidebar to see the dropdown — same bug the tag picker
  fixed last sprint, on a different surface.
- Bumped `.status-popover` z-index from 30 to 1300 to clear the
  modal backdrop (z:50). Matches `.tag-editor-popover`.

## 6. Inbox: Me / All scope toggle

Added an `assignee_scope: 'me' | 'all'` field to `inboxFilter`
(default `'all'`, persisted via `partialize`). Rendered as a
segmented pill in the existing filter strip, identical idiom to the
`or/and` mode pill. With `'me'` selected, `projectTasks` filters to
tasks where `assignee_id === meId`, and the Now section's
`visibleMembers` collapses to just the caller's group — every other
member's tasks are filtered out anyway, so leaving their empty
headings around was just noise.

The first sketch of "highlight my assignment" was an avatar chip in
the row trail (per-row signal). Discarded — the row was already
cramped on mobile, the avatar didn't scale below 16 px legibly, and
"is this mine?" is really a list-level filter, not a per-row
attribute. The Me/All toggle subsumes both questions.

## Decisions worth remembering

- **Server stamps `created_by`, ignores client's value.** Any
  field that's "who is acting" should be derived from auth, not
  trusted from the wire. The op payload still carries it (so peer
  clients see it on the echo without a re-fetch) but the
  authoritative writer is the server.
- **`finished_at` via existing ops, not a new op kind.** A
  `task.finish` op would have to be authored by the same client
  that authors `task.tick`, which means duplicating intent for no
  gain. CASE on the existing UPDATE keeps the contract narrow.
- **Settings get their own table from the start.** Tempting to
  add `account_badge` directly to `users`. Resisted — the second
  setting we add (gcal, theme, default-view) would have forced a
  table extraction anyway, and the conventions for "merge a
  partial patch" are easier to land once and reuse.
- **`Option<Option<T>>` for PATCH semantics.** `serde` collapses
  bare `Option<String>` to "missing or null = None"; tri-state
  via `Option<Option<_>>` + `deserialize_some` lets the client
  distinguish "leave alone" from "clear". Cheap convention, will
  reuse on every settings field.
- **`<div class="topbar-account">` wrapper instead of fighting
  flex `gap`.** A single wrapper child of the flex row is the
  clean answer when two adjacent items need to read as one chip.
  Margin tricks won't beat `gap`; tweaking the parent's gap would
  affect every other pair on the row.
- **Account modal is not workspace-scoped.** Existing modals
  (project, workspace, invite) are all workspace-scoped — they
  open and close with the active workspace. The account modal
  is the first that exists "above" workspaces and stays valid
  even as the workspace switcher fires. Worth marking; it's
  going to multiply (preferences, gcal, link).
- **Bootstrap stays the one-shot hydrate.** Tempting to give
  settings their own `GET /me/settings` since they change rarely.
  Resisted — bootstrap is already the boot path's source of truth,
  adding a parallel request just to save bytes on the same
  payload would split the surface for no real win.

## What we noticed but didn't fix

- **Real Google Calendar integration.** The "Connect" button is a
  stub. Putting the affordance in the account modal is the
  scaffolding; the actual OAuth flow + ingest pipeline is a
  separate sprint.
- **Mode-aware behavior.** The badge is purely informational
  today — picking "personal" doesn't filter anything. Obvious
  follow-up: when "personal" is selected, default the inbox /
  calendar to the personal workspace; when "work", default to a
  team workspace. Held off because we don't yet have a story for
  "what counts as the right team workspace if you have several",
  and a wrong default is worse than no default.
- **More preferences.** `user_settings` only carries the badge
  today. Theme, default-view (calendar vs inbox at boot), 24h vs
  12h time, week-start-day are obvious next residents. Each
  becomes a column + a row in the Preferences section.
- **`account_badge` change feed propagation.** Today it's
  account-scoped state with a single owner (the user themselves),
  so peer clients don't need to be notified — but if a setting
  ever needs to be reflected by collaborators (e.g. "Maya is in
  do-not-disturb"), it'll need its own pubsub channel. The
  per-user channel already exists for membership/role events; it
  would slot in there.
- **Created_by display in the inbox row.** Modal shows it; the
  inbox row doesn't. Chose not to clutter the trail — the user
  who's looking at the row already filtered it down. If "find me
  tasks Bob created" becomes a real workflow, a creator filter is
  the better answer than a per-row chip.
