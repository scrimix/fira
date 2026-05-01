# Sprint 12 — Snapshot-driven playground + subtask polish

**Status:** shipped
**Date:** 2026-05-01

## Goal

Two threads:

1. **Unify the playground seed with the real seeder.** Sprint 11 shipped a
   playground that hand-ported `seed.rs` into TypeScript. The duplication
   bit immediately — within a sprint of shipping, the two had drifted.
   This sprint replaces the hand-port with a build-time JSON dump of the
   real `/api/bootstrap` response, paired with a freezable "now" so the
   playground reads as a literal snapshot of the seeded backend.
2. **Subtask polish round.** Subtasks gained drag-to-reorder, the
   checkbox / close button / add-row icons grew up from CSS-art into
   proper Lucide glyphs, and the modal's section labels stopped looking
   like a different font from the body.

## 1. Snapshot-driven playground

### Architecture

A snapshot is a literal frozen view of the backend at one moment:

```json
{
  "snapshot_at": "2026-05-01T20:35:14Z",
  "me":          { "id": …, "email": "maya@fira.dev", … },
  "workspace":   { "id": …, "title": "Default", "members": [...] },
  "bootstrap":   { "users": […], "projects": […], "blocks": […], … }
}
```

The `bootstrap` field is byte-for-byte what `/api/bootstrap` would
return. Nothing in the frontend re-anchors timestamps; the playground
just calls `setFrozenNow(snapshot.snapshot_at)` and the calendar's
"today" reads from there. Same JSON structure could later represent
saved workspace snapshots, history-replay starting points, or a "send
me your repro" debugging dump — playground is the first user, not the
only one.

### Backend changes

- **Library refactor.** `api/src/main.rs`'s module declarations + the
  `AppState` and `Bootstrap` structs moved to a new
  [`api/src/lib.rs`](../../api/src/lib.rs). The `seed` module is no
  longer gated on the `dev_auth` feature (the gating was for the HTTP
  endpoint, not the data); now any binary in the crate can call it.
  Three binaries now share one module tree:
  - `fira-api` — the API server (was the only consumer of the modules,
    via `mod` declarations; now consumes via `use fira_api::*`).
  - `seed` — dropped its `#[path = "../seed.rs"] mod seed;` shim.
  - `dump-bootstrap` — new bin.
- **`load_bootstrap(pool, workspace_id, user_id)`** in
  [`lib.rs`](../../api/src/lib.rs) — extracted from the inline body of
  the HTTP `bootstrap` handler. Same `tokio::try_join!` of
  `db::list_*_in_scope` calls. The HTTP handler is now a one-liner.
  Every consumer that wants "what would the SPA see if Maya logged in
  right now" goes through this.
- **[`api/src/bin/dump_bootstrap.rs`](../../api/src/bin/dump_bootstrap.rs).**
  Wipes + re-seeds in a transaction, runs `load_bootstrap`, looks up
  Maya + the team workspace from raw SQL, wraps the three pieces with
  `snapshot_at = Utc::now()`, prints JSON to stdout. Wipes again on
  the way out so a developer's local DB doesn't end up holding fixture
  data after a dump.
- **Block state stops depending on wallclock.** The seed used to derive
  `state` per block from `Utc::now()` so a live demo always showed
  "morning done, afternoon planned" relative to *today*. With a frozen
  snapshot, that meant a Sunday-night dump shipped a JSON where every
  Mon-Sat block was already `completed` — no planned blocks left to
  demo. Block list in [`seed.rs`](../../api/src/seed.rs) now declares
  state explicitly per row: Mon-Wed-morning completed, Wed-afternoon
  through Sat planned. Wallclock-independent; the snapshot reads the
  same regardless of when it was taken.

### Frontend changes

- **`time.ts` "now" provider.** Module constants `WEEK_START_MS` /
  `TODAY_DAY_INDEX` / `NOW_TIME_MIN` (eager at import time) became
  functions `weekStartMs()` / `todayDayIndex()` / `nowTimeMin()` that
  read from a private `now()` helper. `setFrozenNow(iso | null)`
  swaps the helper between `Date.now()` (real auth) and a fixed
  timestamp (playground). The function-rather-than-const shape is
  load-bearing: each call re-reads the override, so the calendar grid
  re-renders correctly if `setFrozenNow` is called after any module
  has already imported.
- **`web/src/playground/seed.ts`** shrank from 200+ lines of
  hand-ported fixture data to ~25 lines of "import the JSON, return
  it as `PlaygroundSnapshot`." Type cast through `unknown` since the
  JSON's static type doesn't carry the protocol's UUID branding.
- **Shared `applyBootstrap(set, get, data, me, workspace, workspaces,
  playground)`** helper in [`store/index.ts`](../../web/src/store/index.ts).
  Both the real-auth and playground branches of `hydrate()` call it
  with the same shape:
  ```ts
  if (isPlayground()) {
    const snap = loadPlaygroundSnapshot();
    setFrozenNow(snap.snapshot_at);
    setActiveWorkspaceId(snap.workspace.id);
    applyBootstrap(set, get, snap.bootstrap, snap.me, snap.workspace, [snap.workspace], true);
    return;
  }
  setFrozenNow(null);
  // …real-auth path falls through, fetches /api/me + /api/bootstrap,
  //   then calls the same applyBootstrap.
  ```
  One flow, two data sources. `enterPlayground` collapsed to
  `markPlayground(); window.location.assign('/')` so first-entry and
  reload share the same code path.
- **Topbar `Playground` chip.** A small mono-uppercase pill in the
  topbar's right-hand status cluster, joined to the SyncPill via a
  shared seam border (`margin-right: -1px` on the chip). Replaced
  the earlier full-width banner; with the workspace named "Playground"
  and the chip pinned next to the sync pill, the framing reads at a
  glance without dominating the page.
- **Build/regen.** `pnpm playground:dump` runs the Rust bin and writes
  `web/src/playground/bootstrap.json`. The file is committed; CI can
  later add a check that re-running the dump yields the same JSON.

### Decisions worth remembering

- **JSON, not endpoint.** Considered serving the snapshot from a
  public endpoint at runtime so the SPA fetches it on first
  playground entry. Rejected: a build-time dump means the SPA bundle
  is self-contained — no extra request, works offline, no deploy
  coupling. The cost of "must regen + commit when seed changes" is
  preferable to a runtime dependency.
- **Frozen snapshot, no re-anchoring.** Considered shifting the
  snapshot's timestamps to "this week" at load time so the calendar
  always shows current dates. Rejected — the user's call: "playground
  is like a frozen snapshot." Re-anchoring is magic; calling
  `setFrozenNow` is one explicit handoff. Bonus: the playground date
  visibly being "April 27 – May 3 2026" or whatever is an honest
  signal that this is a snapshot, not a live workspace.
- **One bin, not a Vite plugin.** Could have written a Vite plugin
  that runs the dump at every dev start. Rejected for now — the
  fixture changes rarely (per-sprint, not per-edit), so an explicit
  `pnpm playground:dump` is fine. Plugin can come later.
- **`load_bootstrap` extracted, not duplicated.** The HTTP handler
  used to inline the `tokio::try_join!`. Pulling it into `lib.rs`
  means the dump bin and the handler can never serve different
  shapes — important because the playground is asserting "this is
  what the SPA would have gotten."
- **Library refactor was load-bearing.** Without `lib.rs`, the dump
  bin would have needed `#[path = ...]` includes for `db.rs` + every
  module it transitively imports — messy and brittle. The lib +
  multi-bin layout is also where the codebase was always headed
  (it's the standard Rust shape); the dump bin just made it
  necessary now.

### What we noticed but didn't fix

- **CI verification of snapshot freshness.** A check that running
  `dump-bootstrap` against a clean DB yields exactly the committed
  JSON would catch "seed changed but JSON wasn't regenerated."
  Adds a Postgres-required CI job; deferred until the seed grows.
- **Personal workspace not in the snapshot.** Real auth lists every
  workspace the user belongs to; the dump only emits the team
  workspace. The workspace switcher in playground therefore has one
  entry, which is correct for the demo but slightly less rich than
  real auth.

## 2. Subtask polish

### Drag + reorder

- **New op.** `subtask.reorder { task_id, ordered }` joins
  `task.reorder` as the second list-reorder op kind. Same SQL shape
  (UPDATE sort_key per id), same fixed-width `M{NNN}` key scheme.
  Backend in [`ops.rs`](../../api/src/ops.rs); type +
  `applyOpToState` + `reorderSubtasks` action in
  [`store/index.ts`](../../web/src/store/index.ts) +
  [`store/outbox.ts`](../../web/src/store/outbox.ts).
- **DnD UI.** Subtask rows in the task modal grow a `::` grip on the
  left (opacity 0 by default, 1 on hover, `cursor: grab`). Drag-over
  on a row computes `before` / `after` based on which half the
  pointer is in — same convention task rows use. Drop indicator is
  a 2px accent line as a `::before` or `::after` pseudo on the target.
  The pseudo selectors had to be specific
  (`.subtask[data-drop-mark="before"]::before`, not
  `.subtask[data-drop-mark]::before`) — the broader form rendered
  both pseudos for every drop-marked row, drawing a stray line at
  `top: auto`.
- **Layout alignment.** With grips on subtask rows, the "+ Add
  subtask" row needed mirror columns or its placeholder text
  laddered visibly left of the subtask titles. Both the grip and the
  checkbox got fixed-width 14×14 boxes (matching the `.sc`
  checkbox); the add row got an invisible `.grip-spacer` of the same
  width. The previous "let `::` content set the width" approach was
  fragile — at scale 1.15 the glyph rendered closer to 20px, not the
  12px the spacer assumed.

### Glyphs and labels

- **Lucide everywhere.** The subtask checkbox tick was a
  rotated-border CSS shape that looked ugly at the new 14px size.
  Replaced with `<Check size={11} strokeWidth={3} />` centered in a
  flex box. The close affordance was a `×` glyph in mono; replaced
  with `<X size={14} />` in a 22×22 button with a subtle
  hover-background. The add row's `+` placeholder was a mono `+`
  character; replaced with `<Plus size={11} strokeWidth={2} />`.
  Crisp at any DPI; consistent stroke-width with the rest of the
  Lucide icons in the app.
- **Modal label tone.** `modalH5` and `.modal-side h5` were mono
  uppercase with `letter-spacing: 0.1em` — wide-tracked enough that
  they looked like a different font from the body, not "the same UI
  speaking quietly." Three iterations:
  1. Tried `--font-sans` with no caps — too quiet, labels disappeared.
  2. User: "let's keep mono and uppercase, just less extreme."
  3. Final: mono, uppercase, `letter-spacing: 0.02em`,
     `font-size: var(--fs-sm)` (was `calc(10px * scale)` —
     awkwardly smaller than the body). Reads as a sibling face, not
     a stranger.
- **Estimate value sizing.** The estimate field's resting display
  ("4h") inherited the body `--fs-md` mono; the label above it was
  `--fs-sm`. Value ended up bigger than the label, which felt
  upside-down. Pinned the value to `--fs-sm` sans + tabular-nums.

### Decisions worth remembering

- **Pseudo-element selectors must be specific.** When using
  `::before` and `::after` to render conditional markers, write the
  selector for the *exact* state, not the attribute's existence.
  `[data-drop-mark]` matches whenever the attribute is set; both
  pseudos render with `content: ''` and the one without an
  explicit `top`/`bottom` ends up at `auto` — visible, in the wrong
  place. `[data-drop-mark="before"]::before` and
  `[data-drop-mark="after"]::after` is the right shape.
- **Fixed-width spacers beat content-driven widths.** When two rows
  need to align across a column and one row's content is dynamic
  (the `::` grip glyph in mono varies per font scale), give both
  the same fixed `width:` and stop trying to predict the glyph's
  rendered width.
- **"Make it different" doesn't mean "make it from a different
  font."** Mono vs sans is enough visual difference; a 0.1em
  letter-spacing on top of that pushes the label into "different
  language" territory. Calibrate restraint — 0.02em was enough.

## What we noticed but didn't fix

- **`.subtask-edit .subtask-del` is still keyboard-invisible.**
  `opacity: 0` until row hover means keyboard-only users can't see
  the focus ring. Worth fixing alongside a broader keyboard-nav
  pass. Deferred.
- **No keyboard reorder for subtasks.** Drag works; up/down with a
  modifier doesn't. Same deferral as the keyboard-nav pass.
- **The `enterPlayground` reload is observable** — the user sees a
  flash. Could push state synchronously and skip the reload, but
  the reload-through-hydrate path keeps the entry and rehydrate
  flows identical. Worth revisiting if it becomes annoying.
