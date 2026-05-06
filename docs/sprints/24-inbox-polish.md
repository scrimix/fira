# Sprint 24 — Inbox polish

**Status:** shipped
**Date:** 2026-05-06

## Goal

A grab-bag of inbox-side UX work that piled up after the gcal sprint:
the inbox grew sections, sections grew time totals, and dragging
through a long list on desktop broke in ways that turned out to be
deeper than they looked. Also: strip the task-draft modal back to a
fast-capture form and share the bits with the full task modal that
should be shared.

No schema changes. No new endpoints. Almost entirely web/styles.

## 1. Per-section time totals + filtered totals row

Section heads (Now / Later / Someday / Done) now show the sum of
estimates next to the task count. Done shows actual completed time
(via `taskCompletedMin`) instead of an estimate — for finished work,
"how long did this take" is the load-bearing number.

A four-stat **totals row** under the tag filter shows
done / planned / total / est across the currently filtered task set —
useful when a tag filter is active, answers "how much work is in this
tag, and how much of it have I scheduled?". Centered (originally
left-aligned, looked stranded once the row was the only content
between the filter strip and Now).

Hidden when zero on most surfaces, always rendered on Done so the
section reads as a peer of the others.

## 2. Time-tracking visibility toggle

A Clock icon in the project header toggles all three time surfaces:
the totals row, the per-section ests, and the per-row "Xh left / Xh
over / no est" labels in the task trail. Calendar's ambient time
tracking is unaffected — calendar is the time-tracking surface, the
inbox is the planning surface.

State lives in the zustand store as `showInboxTimes` (default **false**
— the page reads cleaner with estimates hidden, and users who care
about the meter find the toggle in the project header) and rides the
existing `partialize` so the toggle survives reload.
Account-scoped via localStorage; no server roundtrip.

Off-state icon is Lucide's `ClockFading` (the long debate over a
custom Clock-with-X SVG didn't beat what the library already shipped).
Tinted via `color-mix(in oklab, var(--danger) 65%, var(--ink-4))` —
mixing against `--ink-4` (cool grey) instead of `--paper-3` (warm
beige) keeps it in the red family rather than drifting to terracotta.

## 3. Task draft → fast capture

`TaskModalDraft` was shaped like the full task modal: two-column
grid, side panel with Project / Assignee / Status / Estimate / Issue
link / Section. On mobile the 220px sidebar ate most of the viewport.

Restructured to a single column (`data-side="closed"` on
`modal-body`, the existing CSS toggle that collapses the grid).
Status field dropped — drafts are always `todo`, the "draft" chip in
the head already says so. Tags and Issue link removed entirely:
"this is for fast capture" — the full edit modal still has both for
follow-up edits.

Section field moved to the bottom of the column, matching where it
lives in the full modal, and switched to the shared `SectionEditor`
component (the previous inline `Now/Later` segmented buttons covered
half the section options).

Component sharing pass:
- Exported `SectionEditor` and `TagEditor` from TaskModal.
- Refactored `SubtaskList` to take a flat `subtasks` array + per-id
  callbacks instead of `Task` + store mutators. Both surfaces now
  pass through `onTick` / `onSetTitle` / `onDelete` / `onReorder` /
  `onAdd` and bind their own backings (store mutations vs.
  `setSubtasks` over local state). Drag-to-reorder, Enter-to-add-
  next, blank-on-Enter-deletes, long-press touch reorder — all work
  identically across both modals now.
- Did **not** merge `TaskModal` and `TaskModalDraft` themselves.
  After the strip-down they share less, not more — TaskModal does
  live store mutations on an existing task with time blocks, est
  progress bar, status, delete, and a sidebar toggle; TaskModalDraft
  is local-state composition with a Create button. A unified
  component would mean a `mode` prop branching most editors and
  most sections, which is more conditional logic than duplicated
  code. Right factoring is to extract leaf editors and let each
  shell stay a thin orchestrator. (See
  `feedback_taskmodal_split.md`.)

## 4. Drag-and-drop scroll on long lists

The headline bug: on a long inbox (~25 tasks), starting an HTML5 D&D
on the bottom row and trying to wheel-scroll up to drop near the top
silently dropped wheel events. User had to drop at an intermediate
position, scroll, drag again.

Wrong turns first, because the symptom looked like our code:

1. **Removed `e.stopPropagation()`** from row dragover (it was the
   one thing differing between row and section dragover handlers,
   and only over rows did scroll die). Didn't help.
2. **Disabled the long-press hook on desktop entirely** in case
   touch-flavored handlers were leaking through pointer events on
   touchscreen laptops. Didn't help.
3. **Removed `preventDefault()` from row dragover** as well. Drop
   broke (row was no longer a valid target) and scroll was *still*
   blocked.
4. **Deduped `setRowDropAt`** so a fresh `{id, pos}` object wasn't
   forcing all 25 unmemoized `TaskRow`s to re-render every dragover
   frame. Helps perf but didn't unblock scroll.

Then: a debug `wheel` listener at the document level. Wheel events
fired when the cursor was *not* over a drop target, and **didn't
fire at all** when the cursor was over a row. Browser-level
behavior. Chromium consumes wheel events over a valid drop target
during HTML5 D&D — they never reach JS, no listener phase catches
them, no `preventDefault` of ours is involved.

The fix the bigger reorder libraries (Trello, Linear, Notion) all
ship: **edge auto-scroll**. While a drag is in flight, run a rAF
loop that reads the cursor's last Y, and when it enters a band near
the inbox's top or bottom, call `inbox.scrollBy(0, dy)` ourselves.

Cubic ramp `dy = -MAX_SPEED * (1 - t)²`, `MAX_SPEED = 8 px/frame`.
Asymmetric zones: top 100px, bottom 160px — bottom wider because
the natural "tail" of the list (Someday / Done / new tasks) is
where the user typically wants to land, and a wider zone means
they don't have to push to the last few pixels.

Mobile path gets the same loop. Touch never fires `dragstart`, so
desktop's `dragover`-fed cursor source doesn't apply — instead
`onGripTouchStart` arms the loop, `onGripTouchMove` writes
`{x, y}` into a shared cursor ref, `onGripTouchEnd` stops it. The
rAF tick also reissues `onGripTouchMove(x, y)` on touch after each
scroll step so the blue line follows whichever row is now under
the still finger (the finger isn't moving, so no fresh touchmove
would refresh `elementFromPoint`).

## 5. Other inbox / draft fixes

**Now-section auto-`in_progress`.** `addTask` and `setTaskSection`
now track status to section: moving into Now flips status to
`in_progress` (unless already `done`); moving back to Later /
Someday with `in_progress` reverts to `todo` so a parked task
doesn't carry a stale "active" badge. `task.set_status` is pushed
alongside `task.set_section` as a compound op (same pattern
`setTaskAssignee` already used for the unassign-from-Now flip).

**View persists across reload.** `view` was excluded from the
persist `partialize` ("transient UI state"). Treated as a UX
preference now — added to partialize and bootstrap respects
`get().view` instead of unconditionally setting `'calendar'`. Empty
workspace still forces `'inbox'` because calendar can't render
without projects.

**Hover-after-drop suspension.** After a drop the cursor stays put
but the row at that screen position is now a different task, so
`:hover` lit up the wrong row. Added a `data-suspend-hover`
attribute on `.inbox` set on every drop, cleared by the first
`pointermove` or a 600ms timeout — whichever first.

**Description textarea alignment.** `.desc-md.desc-md-edit`
inherited a `margin-left: -6px` from the read-mode style (which
exists to pull the hover-bg padding back so prose stays aligned).
In edit mode the bordered box is visible, so the negative margin
made it stick out 6px to the left. Reset `margin-left: 0` and
`margin-bottom: 0` (the textarea is inline-block and doesn't
collapse with the next heading's top margin, so the read-mode
14px tail stacked on top of the heading's 18px = ~32px of dead
space below the box).

**Subtask `+` only when there are subtasks.** Matches `TaskModal`
behavior. Empty draft starts with a clean placeholder; the `+`
appears once the first subtask exists.

**"Click to set" estimate font.** Empty estimate state used the
mono / tabular-nums treatment that fits the value display ("1h30");
swapped to sans / `--fs-sm` / `--ink-4` so the placeholder reads
as a peer of "Add subtask…" instead of a number stub.

**Time-block popup tick state.** The popup carried a redundant
`.tb-popup .tb-action { background: var(--paper); }` rule that beat
`.tb-tick[data-checked="true"]` on specificity (same count, later
in source). Result: a completed compact-mode block showed white-on-
white in the popup. Removed the redundant override; default
already supplies `var(--paper)`.

**Mode-badge description trim** in the account settings modal. The
descriptive paragraph next to the segmented picker was a "huge text
wall" on mobile. Cut to one short sentence — the picker chips
already convey the choice.

## Decisions worth remembering

- **Section status follows section.** Now → `in_progress`,
  Later/Someday → `todo` (when leaving in_progress), Done → `done`.
  Hidden behind both `addTask` (initial state) and `setTaskSection`
  (transitions). The compound op pattern (`setTaskSection` pushing a
  `task.set_status` op alongside) keeps both fields consistent on
  the wire.
- **Don't merge the two task modals.** They share leaf editors
  cleanly; merging the shells would require a `mode` prop branching
  most controls between immediate-save and deferred-collect plus
  conditionals to hide what doesn't apply to drafts. More
  conditional logic than the duplication it would remove. Path
  forward is the one this sprint took: extract editors, keep shells
  thin.
- **Edge auto-scroll, not wheel intercept.** Chromium *consumes*
  wheel events during HTML5 D&D over drop targets — not propagates,
  not preventable, not catchable in JS. The only viable workaround
  is to manage the scroll ourselves while a drag is in flight. Same
  approach Trello / Linear / Notion / GitHub Projects all use.
- **Asymmetric edge zones.** Top 100px, bottom 160px. The bottom of
  a long inbox is the more common drop destination (Someday / Done
  / freshly-added tasks aggregate there) and a wider band means
  fewer dragger pixel-perfect adjustments.
- **`showInboxTimes` lives in localStorage.** Account preference,
  not project preference. Mode badge follows the same pattern. We
  keep the bar low for adding personal toggles — zustand `partialize`
  already serializes them.
- **Wheel-debug listener earned its keep.** The first three
  hypotheses (stopPropagation, long-press leaking, our preventDefault)
  all turned out to be wrong, and the listener was what proved
  it — wheel events literally don't reach JS over a drop target.
  Without that diagnostic we'd still be chasing ghosts.
- **`color-mix` mix base matters.** Mixing red against `--paper-3`
  (warm beige) drifted the result toward terracotta. Mixing against
  `--ink-4` (cool grey) keeps it in the red family. Worth thinking
  about whenever a "softened" version of an accent goes into
  `color-mix`.

## What we noticed but didn't fix

- **Draft can't pre-pick tags.** With Tags removed from the draft
  modal, you can't seed a new task with a tag from inside the
  capture flow. Add-task-row at the section level seeds tags from
  the active filter (existing behavior); the modal capture path
  doesn't.
- **`TaskRow` isn't memoized.** Dedupe of `setRowDropAt` masks the
  worst of the perf cost during drag, but a tag toggle / sort
  order change still re-renders all rows. `React.memo` with prop
  equality would help on long lists.
- **`EstimateEditor` and `ExternalLinkEditor` still duplicated.**
  TaskModal has the rich versions; TaskModalDraft has its own
  `DraftEstimateEditor`. Now that `SubtaskList` is shared, these
  are the obvious next candidates. Skipped this round —
  `ExternalLinkEditor` isn't even rendered by the draft anymore,
  so the duplication is moot for now.
- **Edge auto-scroll has no settle animation.** Drop while
  scrolling and the row lands at its target instantly; a brief
  ease would soften the transition. Low-value polish.
- **`showInboxTimes` is global, not per-project.** A project where
  every task has a real estimate benefits from labels; a personal
  inbox where nothing's timed doesn't. Per-project state would
  require an extra map and a UI for clearing it. Wait until
  someone actually wants both modes simultaneously.
- **Status revert when leaving Now is one-way.** If a user
  manually set a Later task to `in_progress` (rare but legal),
  moving it to Someday silently flips it back to `todo`. Could
  remember "user-set" vs "section-derived" to leave manual choices
  alone. Not worth the bookkeeping today.
