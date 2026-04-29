# Sprint 02 — Interactions

**Status:** done
**Date:** 2026-04-29

## Goal

Sprint 01 stood up the read-only stack. Sprint 02 turns it into something
you can actually plan with: drag tasks onto the calendar, edit them in
place, walk between weeks and people, and tell at a glance when something
is wrong with the plan. Mutations still don't hit the server — the outbox
keeps growing — but every visible interaction in the prototype now works
locally.

## What shipped

### Calendar

- **Drag-from-rail → block.** Tasks in the right-rail "Schedulable" column
  are HTML5-draggable; dropping on a day column creates a planned
  `TimeBlock`. Snap to 15 min. Default duration is **1 h** (clamped 15–120,
  uses `taskTimeLeft` as a hint when the task has an estimate).
- **Drop preview.** Dashed accent block under the cursor while dragging,
  so you see exactly where the block will land before releasing.
- **Drop user_id is the task's assignee** (falling back to active person,
  then me). Schedule someone else's task and the block lands on their lane.
- **`+ New task`** button (cyan accent) replaces the rail's title. Opens
  the new draft modal (see below).
- **Connected-overlap lane assignment** in `placeBlocks`. Lanes are
  computed per cluster of actually-overlapping items, so an unrelated
  block at 9:00 and 16:00 stop being shrunk to 50 % width.
- **Block resize / move stays correct across weeks.** `onBlockPointerDown`
  now reads grid coords against the visible `weekStartMs`, so the round-
  trip through `gridToBlock` doesn't drop the block 7 days back.
- **Duplicate block** — `⎘` button on each tblock + **Ctrl/Cmd+D** for the
  most-recently-interacted block. Places the copy at the same start time
  as the original, clamped to end-of-day.
- **Active block ring.** Pointer-enter / pointer-down tracks
  `lastBlockId`; that block gets a soft accent ring so you can see what
  Ctrl+D will copy.
- **Short blocks hide the meta line** when `dur_min < 60`. Title only;
  layout flips to row so the title centres.
- **24-hour clock everywhere.** `fmtClockShort` returns `13:30`, not
  `1:30pm`.

### Schedulable rail

- **Stacked fill bar.** Each card now shows `spent + planned + over` as
  three segments, with a thin "estimate" line where the budget ends when
  the plan exceeds it. The previous single-segment bar was indistinguishable
  for "0 m left" vs "4 h 30 m left".
- **Signed time-left.** `taskTimeLeft` returns negative when planned + spent
  exceeds estimate. Cards read `4 h 30 m left` / `done` / `1 h over` (warn
  colour).
- **Done tasks visually distinct** in the rail: paper-2 background,
  struck-through title, faded meta, `✓` in the corner.
- **Project filter applies.** Toggling a project off in the left pane now
  also hides its rail tasks.

### Inbox

- **Always-typeable add rows.** `Add task…` and `Add subtask…` are real
  inputs from the start — no click-to-edit step.
- **Per-assignee add row.** When the Now section is grouped by member,
  each assignee gets their own `Add task for {firstName}…` row that creates
  the task already assigned to that person.
- **Foldable assignee groups.** Caret on each `assignee-head` collapses
  one person without affecting the others.
- **Drag handle (`::`)** appears on hover at the row's left edge. Rows are
  only draggable when grabbed by the handle, so click-to-open on the body
  still works.
- **Drop-to-reorder.** Dropping a task on another row inserts before/after
  based on cursor Y. Cross-section drops also switch the section. Dropping
  on a different assignee group reassigns. Tasks render sorted by
  `sort_key`; reorders re-number with wide gaps.
- **Inline subtask add** under each task in the Now section.
- **Archive ticked → Done.** Button in the project header moves every task
  with `status: 'done'` from any other section into `section: 'done'` in
  one shot. Disabled when nothing is ticked.
- **Inbox row reads `0 m left`**, not `done`. The ✓-on-checkbox is the only
  done indicator. `Xh over` shows in warn colour when over budget.

### Task modal (view existing task)

- **Inline title editor** — click the heading to edit, Enter saves, Esc
  reverts.
- **Editable subtasks** — click name to edit, Enter saves, empty-on-blur
  or Backspace-on-empty deletes, hover shows an `×` button.
- **Editable estimate** — click-to-edit chip with a free-text parser
  (`1h30`, `1h 30m`, `90m`, `1.5h`, plain `30`). Bad input reverts; clearing
  unsets the estimate.
- **Click-to-edit Status** — colored mono text in the side panel. Click
  opens a popover listing the four statuses, each in its own tone, with a
  `✓` next to the current. Outline / arrow chrome removed; the open
  dropdown shows each option in its own colour.
- **Time-blocks list flags planned blocks of done tasks** with a `⚠` and a
  tooltip explaining why.
- Removed the redundant status pill in the modal header — single source
  of truth in the side panel.

### Task draft modal (new task) — `TaskModalDraft.tsx`

Split out of `TaskModal` once the two diverged. Same shell (head + main +
side), but every side-panel field is editable and the main pane has one
**Create** button.

- **Project** — `<select>` of all projects.
- **Assignee** — searchable popover listing **all** users (not just
  project members), name + email, arrow keys + Enter to pick.
- **Section** — Now / Later segmented toggle. **Now requires an
  assignee** — Create is disabled (with a tooltip) if Section = Now and
  no assignee is set; Later allows Unassigned.
- **Estimate** — text input, placeholder `1h`, parsed via the same helper
  as the view modal.
- **Subtasks** — editable rows with the same inline UX, kept in local
  state and committed via `addSubtask` only after the parent task is
  created.
- Single primary Create button. Cancel via × or Esc.

### Calendar user picker — switchable tabs

The toolbar now keeps a small **stack** of pinned people you can flip
between, similar to browser tabs. Adding a person makes them active;
clicking another tab switches without removing anyone. The lone "Me" tab
can't be removed when it's the only one left.

- Active tab is highlighted in cyan; inactive tabs are neutral.
- `+ Add` opens a search popover listing users **not yet in the stack**
  (no more highlight-but-include).
- Search filters by name or email; arrow keys + Enter to pick.

The store split this into two concepts: `selectedPersonIds` (the pinned
set) and `activePersonId` (the one currently visible). Calendar / GCal /
rail filters use `activePersonId`; only the picker UI cares about the
list.

### Week navigation

- Store: `weekOffset: number` + `setWeekOffset`.
- Time helpers: `weekStartFor(offset)`, `fmtWeekRange(ms)`,
  `dayOfMonthFor(ms, i)`. `blockToGrid` and `gridToBlock` now accept an
  optional `weekStartMs` (defaulting to the seeded anchor for backward
  compatibility).
- Toolbar: `‹ Today ›` cluster + the dynamic week label
  (`Apr 27 – May 3, 2026`). Today button highlights when offset = 0.
- The today indicator and now-line only render on the current real week.

### Done-task visuals

Ticking a task as done in the inbox now ripples through everywhere:

- **Time blocks** get `data-task-done="true"`.
  - **Completed** state: hatched overlay, struck-through title, dimmed
    border. Archived work.
  - **Planned** state: dashed border + corner `⚠` glyph. Title is **not**
    struck through. The block keeps its project colour. Tooltip:
    "Task is marked done, but this block is still planned. Delete the
    block or reopen the task." Reads as "stale, fix me".
- **Rail task** with `data-status="done"`: paper-2 background, struck
  title, dimmed meta, `✓` corner.
- **Task modal time-blocks list** mirrors the calendar with the same `⚠`
  + tooltip for done-task / planned-block rows.

### Top bar

- Removed the **`outbox: N`** pill (counter for pending local mutations —
  there's still no sync worker, the count was just noise) and the **`⌘K`**
  placeholder (no command palette wired up).
- Breadcrumb shows the **active person** with `(you)` suffix when it's me,
  not always me.
- Calendar title shows the visible week range, sourced from `weekOffset`.

### Store

New state:
- `selectedPersonIds: UUID[]` (pinned tabs) — replaces the old `selectedPersonId`.
- `activePersonId: UUID | null` (currently viewed).
- `weekOffset: number`.
- `creatingDraft: { project_id, section, assignee_id } | null`.

New actions:
- `addPerson`, `removePerson`, `setActivePerson` — replace `setPerson`.
  Removing the active tab snaps active to the closest remaining (preferring me).
- `setWeekOffset`.
- `openCreate(initial?)`, `closeCreate()` — drives the draft modal.
- `setTaskAssignee`, `setTaskStatus`, `setTaskEstimate`, `reorderTasks`,
  `setSubtaskTitle`, `deleteSubtask`, `duplicateBlock`.

New op kinds in [outbox.ts](../../web/src/store/outbox.ts):
`task.set_assignee`, `task.set_status`, `task.set_estimate`,
`task.reorder`, `subtask.set_title`, `subtask.delete`.

`addSubtask` now returns the new subtask id so the draft modal can chain
its pending subtasks after `addTask`.

### Time helpers

- `parseEstimate(s)` — accepts `1h30`, `1h 30m`, `90m`, `90`, `1.5h`.
- `weekStartFor(offset)`, `fmtWeekRange(ms)`, `dayOfMonthFor(ms, i)`.
- `blockToGrid` / `gridToBlock` now take an optional `weekStartMs`.
- `taskTimeLeft` is **signed** — negative means over-planned.
- `fmtClockShort` is 24-hour.

## Decisions worth keeping

- **Two task-modal components, not one with a `mode` flag.** We tried the
  unified shape; the divergence (subtasks staged locally vs. live, status
  editing only existing tasks, fields editable vs. read-only) made the
  unified component a `if (isDraft)` shotgun. Splitting clarifies the
  data flow at the cost of some shared sub-components (Field, Picker,
  autosize) duplicated across the two files. Worth it.
- **Tabs, not multi-select, for the user picker.** First pass let you
  pick a stack of people whose blocks were all rendered at once. That
  blew up the calendar (40-person company) and was misread as "active
  filter" anyway. Ended on: pinned stack of switchable tabs, only the
  active one's data is rendered. Search popover handles discovery.
- **`weekOffset` over a free-form `weekStartMs`.** Easier to round-trip
  ("Today" = offset 0), keeps the seeded anchor as the base of truth.
- **Status as a click-to-edit chip with a custom popover, not a `<select>`.**
  Native `<select>` repaints all options in the trigger's tone; users read
  it as "every option is in_progress". Custom popover lets each option
  carry its own tone.
- **Time-block warnings tied to *task* status, not block-level over-budget.**
  Tried showing `⚠` whenever cumulative planned + spent crossed the
  estimate. The user's read: that's not stale, that's just a long task.
  The genuinely-broken case is *task done, block still planned* — that
  one pair is what we flag now.

## Things that bit us

- `dataTransfer.getData()` returns empty during `dragover` in most
  browsers. Initial drop-preview tried to look up the dragged task to
  size the preview block; switched to a `draggedTaskId` state set in
  `onDragStart`.
- `blockToGrid` defaulting to the seeded `WEEK_START_UTC` looks fine until
  you resize a block in week +1 — `gridToBlock` writes back relative to
  the visible week, the round-trip drops the block 7 days back, and it
  vanishes. Fixed by threading `weekStartMs` through both ends of every
  drag.
- The first lane-assignment pass treated the whole day as one cluster, so
  a 9 AM block and a 4 PM block both rendered at half width. Cluster by
  connected overlap fixes it without changing the lane allocator.
- Inline subtask `+ Add` row had a 19 px left padding while regular
  subtasks had none — they didn't line up. Removed the offset.
- Subtask checkmark glyph relied on the font baseline and rendered low in
  the box. Replaced with a CSS-drawn tick (rotated borders).

## What's deferred

Still no:
- Write endpoints / sync worker (outbox keeps accumulating).
- Compare mode (two-person calendar side-by-side).
- Recurring tasks / snapshots.
- Real auth.
- Task tags / priority editing.
- Drag-resize across midnight.

## Verification

```
$ docker compose up -d
$ curl -s http://localhost:5173/api/health
ok
$ docker compose run --rm web pnpm typecheck
[no errors]
```

Manual smoke (per task this sprint surfaced):

- Drag a task from the rail onto Tuesday at 14:00 → 1-hour planned block
  appears.
- Tick the task done in the inbox → calendar block grows a dashed border
  and `⚠` corner; rail card fades and gets `✓`.
- Click the block's title → modal opens; estimate, status, subtasks all
  click-to-edit.
- Switch to next week with `›` → blocks for that week render; resizing
  one stays in week +1.
- Add a teammate's tab via `+ Add` search → click their tab to view
  their calendar; click `Me` to switch back.
- Click `+ New task`, fill in title + project + estimate `1h` + a couple
  of subtasks, hit Create → row appears in the right inbox section,
  subtasks created in order, estimate applied.
- "Archive ticked" in inbox header → all done tasks slide into the Done
  section.

## Next sprint candidates

In rough order of value:

1. **Write endpoints + sync worker** (still). Outbox shape is now stable
   enough to drain — every interaction in the UI emits an op kind that
   maps cleanly to a single REST verb.
2. **Compare mode.** Two `activePersonId`s, side-by-side grids. The
   layout primitives (per-person filtering, lane assignment) are already
   there.
3. **Inline editing in inbox** for title and estimate (currently still
   modal-only).
4. **Task tags + priority** as first-class side-panel pickers, matching
   the Status / Estimate UX.
5. **Drag-resize across midnight** — currently clamped to end-of-day.
   Mostly a coordinate-system fix in `gridToBlock`.
