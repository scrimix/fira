# Sprint 20 — Time-block polish + task-modal editing

**Status:** shipped
**Date:** 2026-05-04

## Goal

Two uncomfortable corners of the calendar / task modal that were
overdue:

1. **Time-block action buttons.** The inline tick / duplicate / trash
   row that sits at the top-right of every block was sized for a 1.0×
   `--fs-scale` desktop and unreadable on a hi-res monitor; it also
   crowded the drag surface so tightly that on overlapping or short
   blocks there was no room left to actually grab and move the block.
   Mobile inherited the worst of it: the icons were tappable in name
   only.
2. **Task modal couldn't manage its own time blocks.** The "Time
   blocks" section in `TaskModal` was read-only — the only way to
   delete a stray block or nudge its time was to find it on the
   calendar and act there. For blocks that landed at 2 AM next
   Tuesday that's painful, and there was no way to *create* a block
   from the task at all without dragging the task back onto the
   calendar.

A handful of smaller chores got rolled into the same sprint because
they kept tripping us during testing of the above.

## 1. Compact action row + popup menu

Old layout: three 16×16 buttons absolutely positioned at `top: 2px;
right: 2px` of every `.tblock`. Hidden by default, revealed on hover
(desktop) or `data-active` (touch). Worked, but:

- 16 px is small at 1.0× and tiny at user-bumped `--fs-scale`. On a
  1440p screen the icons read as four indistinguishable pixels.
- For a 30-min block the row took up the whole height; there was no
  empty surface left to start a drag from.
- For lane-overlapped blocks (3 tasks scheduled at the same time, ~46 px
  per lane) the row physically didn't fit and clipped the trash
  button.

The fix is two layers:

**Sizing scales with `--fs-scale`.** `.tb-action` is now
`calc(16px * var(--fs-scale))` square. Lucide icons inside are sized
via a CSS class `.tb-icon` (`calc(11px * var(--fs-scale))`) instead of
hard-coded `size={11}` props — Lucide writes width/height attributes
on the SVG, but a CSS rule on the class wins over the attributes. Same
fix everywhere we render Lucide inside an icon button now.

**Compact mode for short / narrow blocks.** When `dur_min ≤ 30 ||
lanes ≥ 2` (mobile devices follow the same rule — they don't get a
separate trigger), the inline row collapses to a single
`MoreVertical` kebab vertically centered on the block's right edge.
Tapping it opens a `.tb-popup` floating above the block (or below if
the block is at the very top of the day) with the same Tick / Dup /
Trash row at the larger sizes the regular row uses. The popup is
rendered as a sibling of `.tblock` inside `.cal-daycol` so
`overflow: hidden` on the block doesn't clip it. One open at a time;
opening another or pointer-down outside closes it (the existing
`document.pointerdown` deactivation handler already handled this once
we added `.tb-popup` to its allowlist).

The popup is anchored by its **right** edge to the block's right
edge, not the lane's left, so it sits directly over the kebab the
user just tapped — earlier iterations drifted to the lane's left
which was visually disorienting.

## 2. Touch: separate "drag" and "scroll" gestures

Existing model: `.tblock { touch-action: none; }` to prevent iOS from
committing to a vertical scroll on the first touchmove (which would
break the long-press → drag flow). Trade-off: a finger on a block
surface couldn't scroll the calendar at all. Users had to find empty
gutter space to pan, which on a busy day didn't really exist.

New model:

- `.tblock { touch-action: pan-y; }`. Single-press + move = browser
  scroll, no activation, no drag. Matches the user's mental model
  ("tap-and-drag" on iOS is the universal scroll gesture).
- The 220 ms long-press still locks the gesture into a *block drag*.
  The moment the timer fires, `freezeBlockDrag()` flips a flag that
  an always-on (`passive: false`) `touchmove` listener attached to
  `.cal-grid-wrap` reads to `preventDefault`. iOS won't honor a
  *late*-attached preventDefault listener mid-gesture, but it does
  honor an always-attached one that branches on a flag. Same trick
  the rail-task → calendar drop already used.
- `unfreezeBlockDrag()` runs in the drag's `onUp` so the next gesture
  starts back at "single press = scroll".

## 3. Tap activation, deferred until release

The previous handler called `setLastBlockId(b.id)` on `pointerdown`,
which is fine for mouse but wrong for touch: a swipe-to-scroll over a
block would activate it on the way past. Now:

- Mouse / pen → activate immediately (no scroll-vs-press ambiguity).
- Touch → activation is deferred to either the tap-release branch
  (`onPreUp`, fires only if movement stayed under 8 px and the
  long-press hadn't fired yet) or the long-press lock. Movement over
  8 px before the timer fires cancels the hold and never activates.

User-facing contract:

- **Tap** → activate (highlight + reveal action row).
- **Tap on an already-active block** → open the task modal.
- **Long-press still** → lock + drag. Long-press deliberately does
  *not* set `data-active` — the press visual carries the gesture, the
  active state is tap-only.
- **Tap + move** → scroll, no activation.
- **Tap outside** → existing document `pointerdown` handler clears
  both `lastBlockId` and `menuBlockId`.

## 4. Real-time clock + today highlight

`nowMin` and `todayDayIndex()` were computed once at render and never
re-evaluated, so the cyan now-line and the today-column highlight
froze at whatever the page-load minute was. Added a `setClockTick`
counter that bumps once per wall-clock minute (timeout aligned to the
next minute boundary, then a 60-s interval). Both values re-derive on
the bumped render. Deliberately doesn't touch `dayOffset` or
`weekOffset` — at midnight the highlight rolls over to the next day's
column but the user's view stays where they left it.

## 5. Task modal: edit + delete + add time blocks

`BlockRow` (new component, replaces the read-only `<div>` per row):

- **Date / start time / end time** are click-to-edit cells (a generic
  `BlockCell` swaps a span for a native `<input type="date|time">` on
  click; blur or Enter commits, Escape reverts).
- **Duration is read-only** — derived as `endMin - startMin` from the
  freshly-patched ISOs. Earlier iteration let the user edit duration
  too, which produced confusing UX where editing start time silently
  shifted the end (because we were preserving duration). Now each
  cell patches *only* the endpoint it owns; duration falls out of the
  difference on the next render.
- **Trash button** at the end of the row calls `deleteBlock`.

Data invariants:

- `saveStart` rejects values that would make new start ≥ existing
  end (so duration stays positive).
- `saveEnd` rejects values ≤ start, with **one** special case: if the
  user types `00:00` we save it as the *next day's* `00:00`
  timestamp, meaning "end-of-day". The native `<input type="time">`
  only emits 00:00–23:59 so there's no other way to express "block
  runs to midnight". Display reads `24:00` (because `fmtClockShort`
  naturally renders `endMin === 1440` as `24:00`); the edit-mode
  input value is `00:00`, which round-trips back through `saveEnd`.
  Multi-day blocks beyond that single midnight boundary are
  deliberately out of scope.
- `saveDate` shifts both endpoints to the new day at their existing
  times-of-day, preserving duration.

**+ Add block** lives in the section heading's trailing slot. Creates
a block with `user_id = meId`, `state = 'planned'`, ends at the next
15-min boundary (so 22:16 → 22:30) and runs back one hour. If
`end - 1h` would cross midnight (e.g. you click "Add" at 00:16) we
clamp the start to the same day's midnight, producing a < 1 h block
([00:00, 00:30] in that example) — multi-day is a separate feature.

## 6. Modal close: mousedown-AND-click on backdrop

The modal backdrop's `onClick={() => close(null)}` was firing on any
click event whose target was the backdrop, including the click that
synthesizes from a mousedown-inside / mouseup-outside drag (text
selection that overshoots into the backdrop). Now we track a
`downOnBackdropRef` set on `mousedown` only when the target is the
backdrop itself, and require both `mousedown` *and* `click` to be on
the backdrop before closing. Drag-select inside the modal that
releases on the backdrop is correctly ignored.

## 7. Subtasks: Enter creates the next subtask

Existing behavior: Enter on a subtask input committed and exited edit
mode — fine for one-off edits, frustrating for the common "I'm
typing my task list now" flow where every text editor on the planet
opens the next item on Enter. Now:

- **Enter on non-blank** → commit current title, create a new empty
  subtask immediately after this one, drop the new row into edit
  mode.
- **Enter on blank** → existing trim-to-empty contract: deletes the
  row, no new row spawned.
- **Escape** / **Backspace-on-empty** unchanged.

Two pieces had to move:

1. `addSubtask(taskId, title, afterId?)` in the store now accepts an
   optional `afterId`. When provided, it splices the new sub into the
   array immediately after the predecessor (the renderer iterates
   array order; bootstrap data is already in sort_key order so this
   keeps both in lockstep) *and* picks a sort_key strictly between
   the predecessor and its current next sibling using a new `midKey`
   helper. The earlier `cur + '~'` calc collided with any sibling
   that was itself a tilde-extension of `cur`; `midKey` walks the
   keys character-by-character and picks a midpoint code-point in
   the printable-ASCII range, falling back to `a + '~'` when the
   neighbours are adjacent. Empty title is allowed only on the
   "insert after" path so the new row can mount blank for the user
   to type into.
2. `SubtaskList` tracks a one-shot `focusId`; `SubtaskRow` reads it
   on mount, drops into edit mode, and calls `onAutoEditConsumed` so
   the parent clears the state. No `useImperativeHandle`, no refs
   threading.

## 8. Operational note: cross-workspace project move

Not a feature, just a thing we figured out and want recorded. To
move a project from one workspace to another (no admin UI for this,
deliberately — it's a once-in-a-while op), update three columns in
one transaction:

```sql
BEGIN;
UPDATE projects        SET workspace_id = :destws WHERE id         = :proj;
UPDATE project_members SET workspace_id = :destws WHERE project_id = :proj;
UPDATE processed_ops   SET workspace_id = :destws WHERE project_id = :proj;
COMMIT;
```

- `project_members.workspace_id` mirrors the parent project's; the
  trigger that maintains it only fires on `INSERT OR UPDATE OF
  project_id`, so the column-level update is required.
- `processed_ops.workspace_id` re-tags the op history so the
  destination workspace's `/changes` feed surfaces it. The
  workspace-scoped FK on this column was dropped in migration
  `0010_processed_ops_durable`, so the update is unconstrained.
- Workspace-only ops (`project_id IS NULL`) stay where they are —
  they belong to the *original* workspace.
- All current project members must already be members of the
  destination workspace; the composite FK
  `(workspace_id, user_id) → workspace_members` enforces this.

Tasks, subtasks, and time blocks reference the project transitively
via `project_id` and ride along with no further work.

## Decisions worth remembering

- **Lucide icon size via CSS class, not size prop.** `<Check />` etc.
  ship hard-coded width/height attributes; CSS `width: calc(...);
  height: calc(...);` on a class wins because attributes are
  presentational and CSS is later in the cascade. Means a single
  `--fs-scale` knob keeps every icon row legible; means we don't burn
  a magic number into every call site.
- **Action popup is a sibling of the block, not a child.** `.tblock`
  has `overflow: hidden` so mid-block confetti / decorations don't
  bleed; the popup needed to live outside that boundary, so it's
  rendered separately in the day column with absolute positioning
  computed from the same `start_min` / `dur_min` / `lane` / `lanes`
  as the block. One popup per calendar at a time; the rendering pass
  finds the menu-open block and emits the popup only in that
  block's column.
- **`touch-action: pan-y` + always-on `touchmove` listener** is the
  right shape for "single-press scrolls, long-press drags". iOS
  commits to scroll on the first touchmove and won't honor a
  later-attached preventDefault, so the listener is installed at
  mount and branches on a runtime flag set when the long-press
  fires. We've now used this pattern three times (rail drop, inbox
  reorder, calendar block drag); it's the only thing that reliably
  works on Safari.
- **Tap activation deferred to release on touch.** On mouse,
  pointerdown → activate. On touch, pointerdown is ambiguous (could
  be the start of a swipe-to-scroll), so activation moves to the
  release branch that confirms "no movement, no long-press".
- **End-time `00:00` = end-of-day, saved as next day midnight.**
  Single-day-block invariant preserved: end is always strictly after
  start in absolute time, even when the wall-clock end reads `24:00`.
  Multi-day is a separate feature.
- **Subtask sort_key midpoint via a real fractional-indexing helper.**
  The previous "append a tilde" trick worked when sort_keys were a
  monotonic sequence, but broke as soon as any sub had a tilde-
  extended key already. `midKey(a, b)` walks both strings, picks a
  code-point strictly between them at the divergence point, and
  appends a tilde when the neighbours are adjacent. Stable enough
  for the kinds of orderings users actually produce.
- **Modal backdrop: require mousedown AND click on the backdrop.**
  A click event's target is the deepest common ancestor of mousedown
  and mouseup. A drag that starts inside and releases outside
  synthesizes a click on the backdrop, which would otherwise dismiss
  the modal mid-text-selection. Track the mousedown target and gate
  the close on both events landing on the backdrop.

## What we noticed but didn't fix

- **Sub-30-minute blocks** still look cramped on the calendar even
  with the kebab-only collapse — the kebab button itself partially
  clips because the block is shorter than the button. We accepted
  this; the block is small enough that the user is going to drag-
  resize before doing anything serious with it. A future pass might
  render the kebab as a tab outside the block when the block is
  shorter than the kebab, but the current state is strictly better
  than the previous one (where three buttons clipped instead of
  one).
- **Mobile blocks beyond 2 lanes overlap** still produce blocks that
  are too narrow to read the title. The compact mode helps with
  affordances but not with information density. Cluster splitting or
  a "show more" affordance is future work.
