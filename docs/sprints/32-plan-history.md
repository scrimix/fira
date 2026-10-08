# Sprint 32 — Plan history scrubber

**Status:** implemented locally
**Date:** 2026-10-08

## Goal

See how a project's plan changed over time without rewriting the live plan.
Sprint 31 supplied the live board, pure Rust projection, and backdated op
history. This sprint connects those pieces so scrubbing shows changes
through successive historical states.

## Behavior

- `GET /api/plan/at?project_id=…&t=…&seq=…` returns projected tracks, sprints and
  tasks, the effective timestamp, the earliest recorded plan op (`genesis`),
  the selected revision. Revision metadata comes separately from
  `/api/plan/history?project_id=…&since=…`; it loads once and then appends deltas
  after relevant project operations arrive through the change feed, including
  echoes of local edits. Scrubbing and reopening retain the list; unrelated
  operations do not refresh it. Bootstrap recovery checks deltas if its cursor
  skips unseen operations. Omitting `t` reads now; optional `seq` selects an exact revision
  and takes precedence over `t`, including when timestamps are identical.
- Reads require current workspace/project access. Queries filter by both
  workspace and project and by `PLAN_KINDS`. Each read uses a
  repeatable-read transaction. Outgoing project moves are filtered from the
  source's response; incoming moves supply their embedded task state.
- Requested timestamps clamp to the project's first recorded plan op and
  to now. No recorded history returns empty arrays and `genesis: null`.
- The reconstructed finished-work band and its row are named **Unplanned**.
  Its toggle remains separate from **Past**, which reveals the actual
  history scrubber. Loading and error status use a fixed-height footer caption
  that stays blank when idle; pending reads never add a row. Past
  starts hidden; hiding it while
  replaying returns to live and restores editing. Visibility persists,
  while historical selection does not.
- The history panel sits below the board, outside its scroll container. Its
  continuous time axis has independent zoom and pan; moving it never changes
  the roadmap's week scale or scroll position. Click the rail to select a time;
  drag it to pan without changing selection. Drag the playhead to scrub at
  millisecond precision. Scroll or use +/- to zoom down to a one-second
  window. Calendar month and year ticks replace date/clock ticks for larger
  ranges. Fit restores the genesis-to-now range; no state exists before genesis.
  The current-time boundary stays fixed while browsing and extends for newly
  recorded changes. Wheel zoom stops at the full range and at one second,
  without advancing Live or creeping the bounds on subsequent scrolls.
  The top history banner is removed.
- Change markers, an exact-revision picker, and previous/next buttons select
  individual operations. The selected revision/time appears in the picker;
  the duplicate footer timestamp and date input are removed.
  Left/right keys step earlier/later revisions in both the timeline and the
  focused newest-first picker; native option order does not reverse time.
  Home selects the first and End returns to
  live. Changes sharing timestamps remain individually selectable by sequence.
  Selecting Live restores the current editable plan.
- The board shows only the selected historical plan. Live comparison ghosts,
  drift labels and the then/now legend are removed; scrubbing shows placement
  changes through successive snapshots. Historical checklists retain deleted
  tasks, and badge codes are derived from that revision alone.
- Replay is read-only: no card movement, resizing, creation, rename,
  deletion, task ticking, reordering, unplanning, or opening a live task
  editor from a historical row. The inbox remains searchable and
  collapsible, with drag disabled.
- Unplanned remains viewable and toggleable during replay. Task creation and
  completion dates are reconstructed from op timestamps; reopening clears the
  finish date, and incoming moves preserve embedded dates. Historical buckets
  use finish dates (creation dates as fallback) without current calendar blocks.
  Promotion, dragging and opening live task editors stay disabled. Tag filters
  stay hidden because tags are not projected. Card counters
  remain removed; checklist ticks and all-done dimming show completion.
- Live returns to the current store immediately. The `now` button also
  returns to live and recenters the window. Project/workspace changes
  reset the historical selection; reload does not persist it.
- Requests are throttled during continuous dragging and stale responses
  ignored. The last completed projection stays visible with a loading status
  while the next read is pending. Failed reads clear the historical board and
  offer retry. Project/workspace changes clear the previous history metadata.

The snapshot-only playground has no op log, so history controls are not
shown there. The desktop restriction remains. Following UX acceptance, the
Plan sidebar entry is enabled in production as well as development.

## Validation

- Opt-in release-mode backend and production-browser performance harnesses
  cover up to 100,000 ops / 10,000 tasks and 50,000 revision markers/options.
  [Measured results and caching proposal](../performance/plan-history.md) show
  that large revision lists require bounded rendering. Metadata fetches are
  now separated; snapshot caching is proposed, not implemented.

- 22 pure projection tests and 9 existing plan-op DB tests pass.
- 7 DB integration tests cover replay/live equivalence for every
  seeded team project, deleted-task resurrection, genesis/future clamping,
  current access, workspace/project scope, outgoing/incoming moves, and exact
  sequence selection for changes with identical timestamps, and historical
  Unplanned completion dates independent of seeded current-date adjustments.
- Dev selfchecks cover snapshot assembly, badge codes, lane packing, and
  clamping the independently zoomed history window and calendar month/year ticks.
- `pnpm typecheck`, the production build, and the playground visual sweep pass.
- The authenticated visual sweep scrubs the seeded Atlas board, asserts
  resurrection, historical Unplanned visibility/toggling/read-only behavior,
  read-only controls and absence of live overlays, drags
  the playhead continuously, checks click selection, plain-drag panning, wheel
  zoom, stable bounds/timestamps when scrolling out at Fit, and exact revision
  stepping and independent zoom/pan, screenshots
  all three theme/style combinations, verifies retry after a failed read and
  unchanged board/footer geometry during loading, errors and completion,
  asserts that scrubbing makes no writes, checks the independent Unplanned
  and Past toggles, and verifies return-to-live editing:

```bash
cd web
VISUAL_CHECK_HISTORY=1 VISUAL_CHECK_URL=http://localhost:5173 pnpm visual-check
```

Point that URL at a dev frontend backed by the updated API and the standard
fixture. The sweep signs in as Maya; it does not reseed or edit task content.

- `web/scripts/plan-history-sync-check.mjs` exercises the real store and WS
  nudge handler with synthetic feed entries: scrub/reopen reuse, unrelated
  project and non-plan operations, own-write deduplication, incremental refresh
  and unchanged historical snapshots. It uses the dev frontend and makes no DB
  writes. The visual sweep also checks metadata request reuse.

A separate [browseable history stress seeder](../performance/plan-history-stress-seeder.md)
adds 1k/10k/50k revision projects to the existing Default workspace and
configured database, using the normal API/frontend ports. [Current browser measurements](../performance/plan-history.md#browser-measurements-after-metadata-separation)
confirm that rendering remains slow at 10k/50k despite one metadata fetch.
