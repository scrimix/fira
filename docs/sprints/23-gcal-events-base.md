# Sprint 23 — GCal events base

**Status:** shipped
**Date:** 2026-05-05

## Goal

Last sprint left a stub Connect button in the new account settings
modal and a `gcal_events` placeholder table that the calendar already
knew how to render but nothing wrote into. Close the loop end-to-end:
Connect → real Google OAuth grant → server-side sync on every
hydrate → events appear on the calendar with click-to-show details.

Read-only and one calendar (`primary`). Write-back, multi-calendar,
all-day events, and incremental sync (`syncToken`) are explicitly
out — they're each their own follow-up and would have stretched the
sprint past "make it actually work" into "make it complete".

## 1. Two OAuth flows, on purpose

The signup OAuth (`/api/auth/google/login`) keeps its scope at
`openid email profile`. Folding `calendar.readonly` into the login
scope would force every new user to grant calendar to even sign in,
which is wrong — calendar is opt-in.

So gcal gets its own incremental-authorization flow, started from a
signed-in session:

- `GET /api/gcal/connect` → builds a Google consent URL with
  `scope=https://www.googleapis.com/auth/calendar.readonly`,
  `access_type=offline`, **`prompt=consent`**,
  `include_granted_scopes=true`. Sets a `gcal_oauth_state` cookie
  for CSRF, redirects to Google.
- `GET /api/gcal/callback` → validates state, exchanges the code,
  persists `(refresh_token, access_token, expires_at,
  calendar_email)`, runs an *initial* `sync_user_calendar` inline
  so the very next bootstrap has data, redirects to
  `app_base_url`.
- `POST /api/gcal/disconnect` → best-effort revoke at Google's
  side, then deletes the credentials row + every cached event for
  the user (in one tx).

`prompt=consent` is mandatory and was the gotcha we'd have hit
later: without it, **Google omits the refresh_token on every
consent after the first**, even when `access_type=offline` is set,
because they treat the cached consent as already granted. The
callback rejects a token response that doesn't carry a
refresh_token, on the theory that landing in a no-refresh state
silently is worse than asking the user to retry.

Reusing `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` from the signup
flow; the gcal redirect URI (`…/api/gcal/callback`) is derived
from the existing signup redirect URI by suffix swap, with
`OAUTH_GCAL_REDIRECT_URL` as an env-var override. The new redirect
URI has to be added in Google Cloud Console alongside the existing
one — otherwise the consent screen rejects it.

## 2. Schema

Two migrations because the concerns are different.

**`0019_gcal_credentials.sql`** — server-managed credentials.

```sql
CREATE TABLE gcal_credentials (
    user_id            UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    refresh_token      TEXT NOT NULL,
    access_token       TEXT,
    access_expires_at  TIMESTAMPTZ,
    calendar_id        TEXT NOT NULL DEFAULT 'primary',
    calendar_email     TEXT,
    last_sync_at       TIMESTAMPTZ,
    last_sync_error    TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Tempting to put these on `user_settings` since both are per-user.
Resisted — `user_settings` is for *user-editable preferences*,
these are *credentials we manage on behalf of the user*. Different
write paths (PATCH vs OAuth callback), different secrecy posture,
different lifecycle (settings persist forever; credentials get
revoked / deleted on disconnect). Conflating them would force
weird code paths the moment a second integration shows up.

**`0020_gcal_events_metadata.sql`** — extend the placeholder.

```sql
ALTER TABLE gcal_events
  ADD COLUMN description       TEXT,
  ADD COLUMN google_event_id   TEXT,
  ADD COLUMN html_link         TEXT,
  ADD COLUMN updated_at_remote TIMESTAMPTZ;

CREATE UNIQUE INDEX uq_gcal_user_google_evt
  ON gcal_events(user_id, google_event_id) WHERE google_event_id IS NOT NULL;
```

Partial unique index (not full) so legacy seeded rows without
`google_event_id` don't block the constraint. The PK stays at the
existing `id UUID` so wire shape doesn't churn; `google_event_id`
is the *upsert key* for sync.

## 3. Sync routine

`api/src/gcal.rs::sync_user_calendar(pool, user_id)`:

1. Read credentials. No row → no-op (not connected, not an error).
2. If `access_expires_at` is past or within a 60 s skew, refresh
   via `oauth2.googleapis.com/token` (`grant_type=refresh_token`).
   Persist new access token + expiry. On `invalid_grant`, write
   `last_sync_error` and bail — the user needs to reconnect.
3. `GET …/calendars/{calendar_id}/events?timeMin=now-2w&timeMax=now+8w&singleEvents=true&orderBy=startTime&maxResults=250`.
4. For each event with a `dateTime` start *and* end (skip all-day
   for now — there's no row for them on the grid yet), upsert on
   `(user_id, google_event_id)`. Cancelled events filtered out
   client-side via `status != 'cancelled'`.
5. Delete every row in `[time_min, time_max)` with a
   `google_event_id` not in this response — covers cancellations
   that fell off Google's end and events moved out of the window.
6. Stamp `last_sync_at`, clear `last_sync_error`.

Window of −2 weeks / +8 weeks is wider than the visible week so
calendar nav doesn't show empty future days while a fresh sync is
in flight. Single-process loop today; chunking + paging is an
obvious follow-up if anyone has a calendar with >250 events in a
10-week window.

## 4. Hydrate-driven sync

The user's "each hydrate makes the read request" lined up with
two options:

- **Inline in `/api/bootstrap`**: blocks on Google. A Google
  outage degrades login, latency adds to every page load.
- **Fire-and-forget**: `tokio::spawn` the sync from the bootstrap
  handler, return cached rows. Fresh data lands on the next
  hydrate / changes tick.

Picked fire-and-forget. The first connection still gets a
synchronous initial sync inside the OAuth callback (so there's no
"connected but no events for a minute" gap), but every subsequent
bootstrap returns instantly and the spawned task fills in.

Net effect: events show up at most one rehydrate cycle later than
"truly live". The 5-min App-level rehydrate already exists for
missed WS nudges and picks them up for free.

## 5. Connect button + state

`AccountSettingsModal`'s stub row becomes live:

- Disconnected → `<a href="/api/gcal/connect">Connect</a>`. Full-page
  redirect (matches the signup login path; no popup juggling).
- Connected → `<button onClick={disconnectGcal}>Disconnect</button>`
  plus a "Connected as alice@gmail.com" sentence.
- Playground mode disables the link / button.

Connection state hydrates with the rest of the bootstrap. Added
`gcal_connected: bool` and `gcal_email: Option<String>` to
`UserSettings` (sourced from the presence of a `gcal_credentials`
row — not stored on the settings row itself, but exposed there
because the modal needs both the badge *and* the gcal state in one
shot). Mirror fields `gcalConnected` + `gcalEmail` on the web
store.

`disconnectGcal` does the round-trip then clears local
`gcalConnected` / `gcalEmail` *and* `gcal: []`, so the calendar
drops the events immediately rather than after the next bootstrap.

## 6. Click-to-show description

`.gcal-evt` had `pointer-events: none` — clicks passed through to
the day column underneath, which on touch was triggering
"create-block-here". Added a `.gcal-evt-clickable` modifier that
flips `pointer-events: auto` for *own* events; linked-partner
events stay non-interactive (we don't fetch their description today
anyway). Hover lifts opacity and switches to a solid border so the
hit target reads.

The popover is a portaled `<GcalEventPopover>` rendered at
`document.body`, anchored under the event via
`getBoundingClientRect` and flipped above when there isn't room.
Same idiom as `TagEditor` / `StatusEditor`. Closes on click-outside
+ Escape. Body shows title, formatted time range, optional
description (whitespace-preserving), and an "Open in Google
Calendar" link when `html_link` is present.

## Decisions worth remembering

- **Two OAuth flows, not one.** Calendar is opt-in. Bundling
  `calendar.readonly` into the login scope would force every new
  signup to consent to calendar access just to log in. Splitting
  the flow is the only way to keep "I just want to try it" honest.
- **`prompt=consent` is non-negotiable for `access_type=offline`.**
  Google only emits a `refresh_token` on the *first* consent unless
  you force-reprompt. Without it the second connect silently
  returns a useless access_token. The callback rejects responses
  that lack a refresh_token rather than letting the bad state
  persist.
- **Credentials table is its own home.** `user_settings` is for
  user-editable preferences; OAuth tokens are server-managed
  credentials with revocation semantics. Keeping them apart costs
  one extra query on bootstrap and saves us from conflating two
  unrelated lifecycles the next time we add an integration.
- **Fire-and-forget sync from `/bootstrap`.** Inline sync would
  put Google's latency / availability on the critical path of
  every page load. The spawned task lands data one tick later,
  which is fine — calendar isn't real-time-critical and the
  rehydrate cadence picks it up automatically.
- **Synchronous sync inside the OAuth callback.** The exception to
  the above: the *first* sync after Connect runs inline in the
  callback so the user lands back on the SPA with events already
  visible. "I clicked Connect and nothing happened" is the
  failure mode worth spending one round-trip to avoid.
- **Upsert key is `google_event_id`, PK stays `UUID`.** Lets
  re-syncs be idempotent without churning the row identity that
  the wire shape already commits to. Partial unique index covers
  legacy seed rows without `google_event_id`.
- **Window-fetch, not `syncToken` incremental sync.** A 10-week
  rolling window is good enough for v1 and avoids the state
  machine `syncToken` requires (storing the token, handling 410
  Gone, re-priming). Switch when somebody actually hits the
  performance wall.
- **All-day events: skip silently.** The calendar grid has no row
  for them. Surfacing them as zero-height ghosts would be worse
  than nothing. When the grid grows an all-day strip we'll start
  ingesting `start.date` rows.
- **Disconnect deletes the cached events.** Tempting to leave
  them so the user can re-Connect and see history — but if the
  user disconnected because they're separating accounts /
  devices, leaving stale data on the server is a privacy
  regression. Cheap to re-fetch on reconnect.

## What we noticed but didn't fix

- **Real incremental sync via `syncToken`.** Window-fetch reads up
  to 250 events every hydrate. Fine for normal calendars, wasteful
  for heavy ones. Add `gcal_credentials.sync_token` and use it
  when present, falling back to a window query on 410 Gone.
- **All-day events.** Need a dedicated row above the time grid
  (Google Calendar's pattern). When that lands, `RawTime.date`
  starts being parsed.
- **Multi-calendar.** Today we hit `primary` only. The next step
  is `calendarList.list` + a per-calendar checkbox in account
  settings, with a `gcal_event.calendar_id` foreign key on the
  events row.
- **Recurring events as a single source.** `singleEvents=true`
  expands every recurrence into a separate row, which is what the
  grid wants for rendering but blows up the events table. A
  `recurring_master_id` column would let us collapse on the read
  side.
- **All-day strip + cross-day events.** A meeting that crosses
  midnight currently renders only on the start day's column. The
  fix is the same renderer reshape that all-day events would
  need.
- **`description` rendering.** Today we render the raw text in
  the popover (`white-space: pre-wrap`). Google Calendar's
  description supports a small subset of HTML — links, bold,
  bullets. We're stripping all of that. A minimal markdown / HTML
  pass is the obvious follow-up, especially since meeting
  descriptions are where Google Meet links live.
- **`last_sync_error` never surfaces in the UI.** Stored on the
  credentials row but the AccountSettings modal ignores it.
  Should render a red sentence when set so the user knows their
  refresh_token expired without having to wonder why events
  stopped appearing.
- **No revoke-on-account-delete.** If a user deletes their Fira
  account, we drop `gcal_credentials` (FK cascade) but never
  call Google's revoke endpoint. Should hook the deletion path.
