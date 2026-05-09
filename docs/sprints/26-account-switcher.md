# Sprint 26 — Fast account switcher (linked accounts)

**Status:** in progress
**Date:** 2026-05-09

## Goal

Skip the Google OAuth round-trip when bouncing between two accounts
the user has already signed into on this device. The "two accounts"
relationship is the existing `user_links` (sprint 14) — linking is the
user-visible group definition; the per-browser session group is the
device-binding gate that keeps the switch from being usable as
account-takeover anywhere else. Switch button lives next to the
Linked-account row in `AccountSettingsModal`. Land where the user just
was, not at their personal-workspace inbox.

## 1. Schema and the `sg` cookie

Migration `0021_session_groups.sql` adds one nullable column:

```sql
ALTER TABLE sessions ADD COLUMN session_group_id TEXT;
CREATE INDEX idx_sessions_group ON sessions(session_group_id)
    WHERE session_group_id IS NOT NULL;
```

A second cookie sits next to `sid`:

| field        | `sid`                       | `sg`                         |
|--------------|-----------------------------|------------------------------|
| Carries      | session token (credential)  | per-browser group id         |
| HttpOnly     | yes                         | yes                          |
| SameSite     | Lax                         | Lax                          |
| Secure       | env-gated                   | env-gated                    |
| Max-Age      | 30 days                     | 365 days                     |
| Cleared on   | logout / sign-out-everywhere| sign-out-everywhere only     |

`sg` is set on every login (Google OAuth, dev-login, dev-seed) by
`ensure_session_group(&jar)` — read the existing cookie if present,
mint a fresh 24-byte random otherwise. `create_session` writes that id
into `sessions.session_group_id` so every login on the same browser
joins one group.

Pre-migration sessions stay `session_group_id = NULL` and are
invisible to the picker but remain individually valid until they
expire or the user logs out. The first login after the migration
mints a fresh group and enrolls subsequent logins into it.

## 2. Logout semantics

`/auth/logout` unchanged in shape but deliberately narrow in scope:

- Deletes `sessions WHERE id = $sid`. The current session row is gone
  from the DB.
- Clears the `sid` cookie.
- **Does not** touch the `sg` cookie or any sibling sessions in the
  group. That preservation is what lets the picker still find the
  other linked account on the next visit.

Two new endpoints:

- `POST /auth/switch { user_id }` — rotate `sid` to a sibling.
- `POST /auth/sign-out-everywhere` — nuke the group + clear `sg`.

## 3. The two gates on `/auth/switch`

The switch endpoint refuses (404) unless **all three** hold:

1. **Caller is authenticated** (`AuthUser` extractor on the handler).
2. **Caller and target are linked** (`user_links.status = 'accepted'`,
   either side).
3. **Target has a live session in the same group** (`sessions.user_id =
   target AND session_group_id = caller's sg AND expires_at > now()`).

All three are enforced in **one** SQL — the link gate and the session
gate share a JOIN, so a malformed client can't beat them by sending
clever parameters.

```sql
SELECT s.id
FROM user_links ul
JOIN sessions s ON s.user_id = CASE
       WHEN ul.user_a_id = $caller THEN ul.user_b_id
       ELSE ul.user_a_id
   END
WHERE ul.status = 'accepted'
  AND (ul.user_a_id = $caller OR ul.user_b_id = $caller)
  AND s.user_id = $target
  AND s.session_group_id = $sg
  AND s.expires_at > now()
ORDER BY s.created_at DESC LIMIT 1
```

If the row exists, the handler rotates the `sid` cookie to the
returned session id. The previous `sid` row stays alive in the DB so
the user can switch back without another OAuth round-trip.

`/auth/accounts` runs the same JOIN shape but returns the partner row
(name / email / initials / avatar / account_badge). It's the picker
data source, used by `AccountSettingsModal` only.

Same-user switch is a no-op short-circuit — return 204 without
rotating. Avoids client-side branching when the user clicks themselves.

## 4. Client side

**Store actions (`web/src/store/index.ts`).** Two new actions sit next
to `logout`:

- `switchToAccount(user_id)` — calls `api.switchAccount`, clears
  `fira:store-v1` and `fira:activeWorkspace` from localStorage (the
  next user's data shouldn't briefly leak through hydrate), hard
  reloads. The per-account snapshot (§5) is namespaced and stays.
- `signOutEverywhere()` — best-effort `api.signOutEverywhere()`,
  clears localStorage, hard reload.

**Account modal (`AccountSettingsModal.tsx`).**

- Linked-account row: when `linkState.kind === 'accepted'` AND the
  partner appears in `/auth/accounts`, render an inline
  `Switch to {Personal | Work | name}` button. Label uses the
  partner's `account_badge` from `user_settings` so the vocabulary
  matches the existing personal/work badge ("Switch to Personal",
  "Switch to Work"); falls back to the partner's name otherwise.
- When the link is `accepted` but the partner has no live session in
  this browser's group, surface a hint pointing at "Add another
  account" — the only way to bootstrap two-in-group is to add the
  second without logging out first (logout deletes the current
  session, otherwise; see §6 again).
- "Add another account" button: `<a href={loginUrl}>` for Google,
  plus a dev-only "Add Maya (dev)" button when `/auth/config` says
  `dev_auth=1`. Both create a new session that joins the existing
  `sg` group via `ensure_session_group`.
- "Sign out everywhere" appears next to "Log out" only when there's a
  switch target (i.e. a linked partner with a live session here).

The Login screen was reverted to the original single-account flow.
Picker logic is in-app only — when signed out there's no current user
to gate on, so the "linked" semantic doesn't apply.

## 5. Last-view snapshot per account

Without this, every fast switch dumps the user at their personal-
workspace inbox (the hydrate fallback). With it, switch reloads to
exactly where the user was on that account.

`localStorage[fira:lastView:{userId}]` stores:

```ts
type LastView = {
  workspaceId: UUID | null;
  view: 'calendar' | 'inbox';
  projectId: UUID | null; // inboxFilter.project_id
};
```

A `useFira.subscribe` writes the snapshot whenever any of those four
fields change. Short-circuits on `playgroundMode` and on `meId === null`
(hydrate hasn't landed yet). Cheap — one localStorage write per
workspace/view/project change, not per keystroke.

`hydrate()` reads the snapshot after `/me` returns and before
`/bootstrap`, picks the saved workspace (falls back to the legacy
`fira:activeWorkspace` key for users who pre-date the snapshot, then
to the personal workspace). After `applyBootstrap`, restores `view`
and `inboxFilter.project_id` — overrides applyBootstrap's defaults
which would otherwise force inbox-on-empty and seed the first project.

Skipped restoring `selectedPersonIds`, calendar offsets, filters
beyond project. Can extend later if needed; kept the snapshot small
and the restore predictable.

## 6. Security model — what the cookies grant

**`sid` alone:** full account access. HttpOnly + Secure + SameSite=Lax,
unchanged from before this sprint.

**`sg` alone:** can't be sent by JS (HttpOnly), can't authenticate,
and every endpoint that reads it (`/auth/accounts`,
`/auth/switch`, `/auth/sign-out-everywhere`) also requires a valid
`AuthUser`. So `sg` in isolation grants nothing.

**Both cookies:** can call the picker and switch endpoints. The link
gate still applies — a switch only succeeds if the caller is linked
to the target. So even with both cookies, an attacker can only
rotate into accounts the legitimate user has already deliberately
linked to. Not "any account that ever signed in here."

**Cross-site (CSRF):** `SameSite=Lax` blocks the `sid` cookie on
cross-site POSTs, so `/auth/switch` and `/auth/sign-out-everywhere`
can't be triggered from a malicious origin. `/auth/accounts` is GET
but returns JSON — same-origin policy stops cross-origin reads, so
the picker contents don't leak across sites.

**Public-computer scenario:** `sg` persists across logouts on
purpose. If user A logs in, leaves, and stranger C arrives and signs
in via the normal Google flow, C inherits A's `sg` cookie. C can
*not* switch into A — they're not linked. C can't call
`/auth/sign-out-everywhere` to nuke A either: that endpoint
authenticates as C and only deletes sessions in the group whose
`user_id` matches C *or* a linked partner of C, never strangers'
sessions that happen to share the cookie.

## Decisions worth remembering

- **Link is the group, not the cookie.** I tried it the other way
  first — let any pair of sessions in the same `sg` group be
  switchable, with a generic picker on the Login screen. Showed it,
  reverted. The link gate is what makes "Switch to X" feel
  intentional rather than "list of randoms who used this browser."
- **Two gates beat one.** Link (DB) + group (cookie) together. Link
  alone would let an attacker with a leaked `sid` switch into any
  linked partner regardless of device. Group alone would let any
  two cookies-on-same-browser swap freely (public-computer
  attacks). Both required = safe to use the link relationship as a
  shortcut.
- **`Add another account` is a UI requirement, not a nice-to-have.**
  Logout deletes the current session row. Without an in-app
  affordance to log into a second account *without* logging out
  first, the picker has nothing to find. Took a user round-trip to
  catch this; documenting so the next person doesn't add multi-
  session features without the bootstrapping path.
- **Per-account `lastView` is a separate localStorage key, not a
  field on the persisted store.** The store blob (`fira:store-v1`)
  is wiped on every switch to prevent the previous user's
  projects/tasks from briefly hydrating into the new account's UI.
  The lastView keys are namespaced by user id and survive that wipe.
- **DISTINCT ON over `u.id`, ordered by `s.created_at DESC`.** The
  picker shows one chip per user, and the most recent session is the
  right one to point at — older sessions for the same user are
  stale but valid (created on a previous "Add account" pass).
- **Pre-migration sessions stay valid, just invisible to the picker.**
  No backfill, no forced re-login. Existing users are unaffected
  until they log in once after the deploy, at which point their
  next session enrolls in a fresh group.

## What we noticed but didn't fix

- **Hard logout still deletes the current session.** Means the user
  has to "Add another account" each time they want to bootstrap two
  active sessions. A soft-logout (mark inactive, keep the row, let
  switch reactivate) would let the picker work indefinitely without
  re-OAuth. Out of scope for this sprint; revisit if the friction
  shows up.
- **No "Add another account" route on the Login screen itself.** When
  the user is fully logged out, there's no UI to bootstrap a
  multi-session group; they have to log in once and then add the
  second from inside the modal. Could mirror the modal's affordance
  on Login if the bootstrap step turns out to be the rough edge.
- **`/auth/accounts` re-fetched on every modal open.** Cheap query
  but unnecessary churn — could store the last result in the
  Zustand store and refresh in the background.
- **`signOutEverywhere` clears the whole group, not just the
  caller-linked subset.** See §6 — same fix applies.
- **`lastView` doesn't include calendar people-pins or week offset.**
  Bounded scope by design (workspace + view + project), but switching
  with a weird `weekOffset` carry-over might surprise a user who set
  it on the previous account.
