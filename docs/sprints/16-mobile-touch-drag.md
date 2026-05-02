# Sprint 16 — Mobile touch drag and calendar polish

**Status:** shipped
**Date:** 2026-05-02

## Goal

Sprint 15 fixed enough on mobile to make the dropdowns work and the
viewport readable. This sprint took the next pass: make the app
*actually usable* on a phone for the things people do most often —
reordering tasks in the inbox, editing subtasks, and moving time
blocks on the calendar.

The work split cleanly into two themes:

1. **Touch drag, end to end.** HTML5 drag-and-drop doesn't fire from
   touch on iOS, so every drag-shaped interaction in the app was a
   no-op on mobile. We needed pointer-events parallels for: inbox
   task reorder, inbox subtask reorder, time block move/resize, and
   the rail-task-onto-calendar scheduling flow. Plus a sane "long-
   press anywhere on the row" interaction that doesn't fight the
   page scroll.
2. **Mobile/touch UX polish.** Hover-only affordances were invisible
   on touch. Tap-to-open clobbered tap-to-edit. Time block rows in
   the task modal wrapped to three lines on phones. The calendar's
   action buttons were unfindable. The subtask body in the inbox was
   a click-trap. All small things; all together they were the
   difference between "I can use it" and "I'll wait until I'm at my
   laptop."

## 1. Touch drag — the pattern

The `Select` popover bug from sprint 15 already taught us that iOS
pointer events are layered over touch events in a way that makes
`preventDefault` on `pointermove` *not* suppress scroll. Touch
events with `{ passive: false }` are the only thing iOS Safari
respects mid-gesture.

So the drag pattern that works across every variant:

- **Pre-lock**: pointer events. They fire reliably for both mouse
  and touch, give us `clientX/Y`, and let the page scroll naturally
  if the user starts moving.
- **Lock**: when the gesture commits to a drag, attach a
  *document-level non-passive `touchmove` listener*. That listener
  calls `e.preventDefault()` (which iOS respects) and forwards
  `touch.clientX/Y` to whatever drag-tracker the caller wants.
  `touchend`/`touchcancel` listeners on the same path commit and
  clean themselves up.

How a gesture decides to lock varies by surface:

- **Explicit grip (`::`)**: locks immediately on `pointerdown`. The
  `.task-grip` / `.subtask-grip` elements have `touch-action: none`
  in CSS so iOS never tries to scroll touches that start there.
- **Whole-row long-press**: 220 ms hold timer. If the finger moves
  more than 8 px before the timer fires, cancel — the user was
  scrolling. If they hold still, lock with a faint
  `navigator.vibrate(8)` and switch to the document-touchmove path.
- **Time block drag**: locks on `pointerdown` because `.tblock` has
  `touch-action: none`. CLICK_THRESHOLD_PX (movement < threshold)
  vs `moved=true` distinguishes tap from drag.

Implemented in:

- [web/src/components/InboxView.tsx](../../web/src/components/InboxView.tsx) — task grip, long-press row drag, `applyTaskMove` extracted so the touch and HTML5 paths share one commit function.
- [web/src/components/TaskModal.tsx](../../web/src/components/TaskModal.tsx) — subtask grip, long-press subtask row drag, `reorderTo` extracted for shared commit.
- [web/src/components/CalendarView.tsx](../../web/src/components/CalendarView.tsx) — re-enabled time block move/resize on touch (the `pointerType === 'touch'` guard from sprint 15 came back off; pointer events drive it), and added `onTouchSchedule(taskId, x, y, phase)` for rail-task → calendar scheduling.

Hit-testing during a drag uses `document.elementFromPoint(x, y)` and
`closest('[data-task-id]')` / `[data-subtask-id]` / `[data-day-idx]`
/ `[data-assignee-id]` to find the target. The drop priority order
in the inbox (row > assignee group > section) is the same on touch
as on desktop.

## 2. Inbox UX

### Long-press anywhere drags the row

The `::` grip works for the patient and the precise. Long-press
anywhere on a row works for everyone else. The implementation
guards against accidental edits by:

- Excluding child elements that own their own behavior
  (`.task-check`, `.sc`, `.task-grip`) — touches there pass through
  to the child's handler.
- Setting a `suppressClick` flag after a locked drag ends, so the
  synthetic click that follows `pointerup` doesn't also trigger
  `onOpen` / `setEditing`.
- Cancelling the lock timer the moment the finger moves more than
  8 px — that's a scroll, not a drag intent.

### Subtasks blend into the parent row

In the inbox, the subtask body now behaves as part of the parent
task. Tap → opens the task. Long-press → drags the parent. Only
the `.sc` checkbox keeps its own handler (`stopPropagation` on its
click so toggling done doesn't also open the modal). The previous
"click subtask body to edit inline" affordance is gone — too easy
to hit while aiming for the row, and the resulting edit input
looked like a mistap. Subtask edits live in the task modal now,
where the precision tradeoff is the right way around.

### Unassigned bucket + auto-Later on unassign

Carryover from the visibility work: a Now task without an assignee
falls into a dedicated "Unassigned" group at the bottom of the Now
section, and `setTaskAssignee(null)` on a Now task auto-flips it to
Later. The bucket exists for legacy data and the rare explicit
"ownerless Now task" — under normal use it stays empty.

### Touch drag onto an empty assignee group

The first version of touch reorder only detected drops on rows or
sections — empty assignee groups (a member with no Now tasks)
weren't reachable. Added `data-assignee-id` to the group div and a
third detection branch in `onGripTouchMove`: if the finger is over
a group with no rows, we still light up the cyan band and reassign
+ move-to-Now on release. Feature parity with the HTML5 path.

## 3. Calendar UX

### Time block actions: tap to reveal, tap-again to open

`.tb-actions` (X / tick / duplicate) used to fade in on hover. On
touch there's no hover, so they were invisible-but-tappable —
which is the worst of both worlds. New behavior:

- Tap a block → it becomes active (`data-active="true"` set by the
  existing `setLastBlockId`). On touch, the actions reveal via
  `@media (hover: none) { .tblock[data-active="true"] .tb-actions { opacity: 1 } }`.
- Tap the same block again → opens the task modal.
- Tap a different block / empty area → previous one deactivates.

The "tap-to-reveal-then-tap-to-open" requires the drag handler to
distinguish first-tap from second-tap on touch:

- `DragState` carries `pointerType` and `wasActive` (whether the
  block was already the last-active one before this tap).
- On `pointerup` with `!moved`: if it's touch and not already
  active, suppress the `openTask`. Otherwise open as before. Mouse
  always opens on click.

### Time block move/resize on touch

Pure pointer events. `.tblock` already has `touch-action: none`
(set in sprint 15 when the drag was first wired up) so iOS doesn't
scroll. The drag implementation already uses window-level
pointer listeners that survive re-renders into a different day
column, which works identically for touch.

Drag-to-create on the day-column background stays disabled on
touch — too easy to confuse with a vertical scroll attempt, and
the explicit "+ New task" button in the rail covers the gap.

### Rail-task → calendar scheduling on touch

For tablet/landscape sizes where the rail is visible (>1000 px),
the rail-task gets the touch path: `setPointerCapture` on
pointerdown, `onTouchSchedule(taskId, x, y, phase)` callback into
CalendarView for hit-testing + commit. The day column `cal-daycol`
got `data-day-idx` so `elementFromPoint` can resolve which day the
finger is over; the existing drop preview band reuses the same
state path. Tap (no movement) still falls through to `openTask`.

### Time block row in the task modal — responsive grid

The "X time blocks" list inside the task modal had inline-styled
grid columns that ran out of room on phone widths and split each
cell onto its own wrapped line — three rows per block, unreadable.
Replaced with a CSS class using `grid-template-areas`:

- **Wide**: `avatar | date | time | duration | state` on one row.
- **Narrow** (`max-width: 520px`): two rows; avatar drops entirely
  (the user is almost always the assignee shown in the side panel);
  `date | state` on top, `time | duration` below.

All cells get `white-space: nowrap` so nothing wraps inside a cell.

## 4. Mobile viewport — practical compromise

The viewport meta is now `width=device-width, initial-scale=0.5`.
Iterations:

- `width=1280` (original) → everything fit but unreadably tiny.
- `width=device-width, initial-scale=1` → readable native size,
  but the calendar was off-screen.
- `width=1024` → middle ground, but still too cramped.
- `width=device-width, initial-scale=0.5` (current) → the desktop
  layout renders at half size. Pinch-zoom works for finer reading.

On top of that, a `@media (max-width: 1000px)` rule in the
calendar grid hides `.cal-rail` and collapses `.calendar` to a
single column — drag-from-rail doesn't work on touch anyway, and
the rail was eating a third of the screen.

## 5. Smaller fixes shipped along the way

- **Cyan assignee highlight stuck after drop.** Row-level
  `onRowDrop` now also clears `setAssigneeDropTarget(null)`. The
  child's `e.stopPropagation` prevented the assignee group's own
  drop handler from firing, so the highlight stayed.
- **Description ghost scrollbar.** `overflow: hidden` on
  `.desc-md.desc-md-edit`. Autosize already grows the textarea to
  `scrollHeight`; line-height rounding produced a 1–2 px scrollbar
  that didn't need to be there.
- **iOS text-selection during drag.** `user-select: none` plus
  `-webkit-touch-callout: none` on `.task-row` and `.subtask`.
  Pointer capture routes events to the captured element, but
  iOS's long-press text-select looks at whatever the finger is
  physically over; without these properties the row underneath
  triggered selection.
- **Touch grip permanently visible on touch devices.**
  `@media (hover: none) { .task-grip { opacity: 0.5 } }`. On
  desktop the fade-in is polish; on mobile, with no hover, it's a
  dead end.

## Decisions worth remembering

- **Pointer events for state, touch events for `preventDefault`.**
  The cleanest pattern for iOS Safari is hybrid. Use pointer
  events to track lifecycle (they fire reliably and give you
  `clientX/Y`), but if you need to suppress scroll mid-gesture,
  attach a non-passive document-level `touchmove` listener — that's
  the only thing iOS respects after the gesture is in flight.
  Don't try to do the whole thing in pointer events on iOS; you'll
  fight the platform.
- **Long-press 220 ms / 8 px threshold.** Long enough that a
  scroll-intent finger has time to start moving and cancel the
  timer; short enough that a held finger doesn't feel laggy. We
  tried 250 and 300; 220 felt like the sweet spot. The 8 px
  threshold is generous enough to absorb hand jitter but tight
  enough that a real swipe registers as a scroll.
- **Tap-to-reveal-then-tap-to-open** for calendar blocks. On
  desktop, hover reveals actions, click opens. The touch
  equivalent is two taps: one to expose the actions (and let the
  user choose between them and "open"), one to commit to opening.
  The alternative — single tap opens — made the X / tick /
  duplicate buttons unreachable on a phone, since you'd open the
  task before you could see them.
- **Subtasks-as-part-of-row in inbox, not in the modal.** The
  modal needs subtasks to be individually tappable for inline
  edit; the inbox needs them to be a unified visual chunk. Same
  data, different interaction model. Resist the temptation to
  share the row component.

## What we noticed but didn't fix

- **HTML5 rail-task drag-to-calendar on iPad.** We added the touch
  path, but the rail itself is hidden below 1000 px so most
  phones don't see it. Tablets do. Should work but only tested on
  desktop with mouse pointer-type forced via DevTools — real
  touchscreen tablet validation pending.
- **Drag-to-create on day column on touch.** Still gated off.
  Distinguishing it from vertical scroll without a long-press
  delay (which would conflict with block-tap) is non-obvious;
  punting until someone asks.
- **Drop on Unassigned bucket.** The bucket renders but isn't a
  drop target — dropping there *would* set assignee to null, which
  would also flip the section to Later, which is non-obvious for
  a user who just dragged something *into* Now. Left for a
  follow-up that thinks through the gesture explicitly.
- **Real mobile layout.** Everything we did in this sprint is
  "the desktop UI, made tappable." A proper mobile layout —
  collapsing the modal sidebar, single-column inbox, gesture-
  based week navigation, etc. — is a separate, larger sprint.
  The current state is "usable on a phone if you have to," not
  "designed for a phone."
