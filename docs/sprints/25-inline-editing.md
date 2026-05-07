# Sprint 25 — Inbox inline editing

**Status:** shipped
**Date:** 2026-05-07

## Goal

Turn the inbox into a typing surface. Today the row is "click → modal";
this sprint makes the row the editor — click the title, type, Enter for
next, Tab to demote into a subtask, Up/Down to move the caret across
rows, Shift+Up/Down to physically move the row. Drag-onto-row merges
the dragged task into the target as a subtask, with content
(description / subtasks / blocks / estimate / tags) absorbed instead
of dropped.

Desktop-only. Phones keep the existing tap-row-opens-modal behavior —
there's no Tab key on a phone and adding modal-style toolbars to the
row was out of scope (see `feedback_taskmodal_split.md` for the same
"share editors, not shells" reasoning applied at a different surface).

No schema changes. No new ops on the wire — the merge composes
existing op kinds (`subtask.create`, `subtask.tick`,
`task.set_description`, `task.set_estimate`, `task.set_tags`,
`block.create`, `task.delete`). One new store action,
`addTaskAfter`, for sibling-with-`midKey` insertion when Enter mints a
new task between two existing ones.

## 1. Inline title editor

Click the `.task-title` text → `<textarea rows={1}>` swaps in.
`onBlur` commits via `setTaskTitle`; empty after edit `deletes` the
task (matches the subtask "trim-empty" contract — both editors feel
like one tool). The hit-zone is the **title text only**, not the
surrounding row body — clicking padding / trail / chip area still
opens the modal as before, so existing muscle memory keeps working.

Caret lands at end of the title on entry rather than start, mirroring
rich-editor convention. Cursor switches to I-beam over editable
titles on desktop (`[data-editable]`) so the affordance reads.

## 2. Keyboard structure ops on the title

| key             | what it does |
|-----------------|--------------|
| Enter           | Save current title, mint a sibling task right after it (same project / section / assignee / tag-filter), focus the new row's input |
| Shift+Enter     | Insert a literal newline in the title (rare; multi-line titles allowed) |
| Tab             | Demote current task into a subtask of the previous task in the same render group |
| Esc             | Revert the draft and exit edit mode |
| ↑ / ↓           | Move edit focus to prev / next visible row |
| Shift+↑ / ↓     | Move the *task* one slot in its render group (uses `applyTaskMove`) |

**Sibling insertion order.** New store action `addTaskAfter(afterId,
title?)` reuses `midKey()` (the same printable-ASCII midpoint helper
`addSubtask` uses for "insert after") to compute a `sort_key`
strictly between the source row and its successor. No section-wide
renumbering on every Enter. Empty title is allowed at create time so
the new row can mount in edit mode with a blank textarea.

**Tab demote, Stage-1 scope.** Demote is allowed only when the source
task has zero subtasks (can't nest) and there's a previous task in
the same render group. If allowed, the source's title becomes a new
subtask of the prev task and the source is deleted. Description /
blocks / estimate / tags are dropped — the typing flow that this
serves is "press Enter, type a sub-bullet, press Tab", so the source
is always empty in practice. The rich merge path lives on
drag-drop instead (§4).

**Subtask side.** Click `.sname` to edit (the previous "edit-on-click
disabled" guard from sprint 24 was the wrong call once the row
is *the* editor). Enter on a subtask appends the next subtask;
Shift+Tab promotes a subtask back to a task right after its parent
(round-trip is lossless because subtasks have no metadata beyond
title + done).

## 3. Per-task subtask toggle

A small `▸ / ▾` caret renders to the **right of the title text**
(before the `[ABC-12]` ext-id chip) when the task has at least one
subtask. Click toggles per-task expansion via `expandedSubs:
Record<UUID, boolean>` in the inbox-local state. Default is
collapsed for every task — the row is "the title" by default, and
subtasks are an opt-in dive.

Tab-demote and drag-merge auto-expand the parent so the user
immediately sees what they just produced.

Subtask rhythm tightened to 3 px top/bottom padding + a 3 px
container margin-top. Math: subtask→subtask = 3 + 3 = 6 px;
title→first-subtask = 3 + 3 = 6 px. Equal in both directions, denser
than the 6 + 6 = 12 px task→task cadence — subtasks read as a
secondary list inside the task without feeling cramped.

## 4. Drag-merge

Existing reorder used a 2-zone hit-test on each row (top half →
"before", bottom half → "after"). Replaced with **3 zones**: top
30 % → before (cyan line above), bottom 30 % → after (cyan line
below), middle 40 % → **merge** (target row lights up with
`accent-soft` + accent outline). Both desktop HTML5 D&D and the
touch grip-drag share the same hit-test via `resolveRowDropPos`.

Drop in the merge zone runs `mergeTaskInto(sourceId, targetId)`,
a new store action implementing the conflict-resolution contract
from the inbox brief:

1. **Title** — source's title becomes a new subtask of the target.
   Inherits `done` from the source's status so a completed task
   merging in doesn't silently re-open work.
2. **Subtasks** — source's own subtasks join as flat siblings
   under the target, preserving title and done.
3. **Description** — `target.description` then a `## ${sourceTitle}`
   heading then `source.description`. Tight join (single `\n`
   between heading and body) so the section reads as one block,
   not a heading floating above its paragraph. Skipped when source
   has nothing to add.
4. **Estimate** — sum, null-safe.
5. **Tags** — set union.
6. **Time blocks** — re-pointed to the target. Server's
   `block.update` op only patches `start_at` / `end_at` / `state`
   (no `task_id` change), so we delete + recreate: each
   source block becomes a new `block.create` with the target's
   `task_id`, and the originals get cascade-deleted server-side
   when the source task is removed.
7. **Source** — `task.delete`. Cascades remove its (now-stale)
   blocks; the local store mirrors that in `deleteTask`.

Cross-project merges refused silently — the source's `tag_ids`
wouldn't validate against the target's project tags anyway. Self-
merge refused at the call site.

## 5. Up/Down + Shift+Up/Down navigation

Up/Down on the title textarea or subtask input move edit focus to
the adjacent visible row. Resolution uses
`querySelectorAll('.task-row[data-task-id], .subtask[data-subtask-id],
.task-add')` against the inbox container — document order is the
correct order, collapsed sections / subtask groups aren't in the DOM
so they're skipped naturally, and the chain crosses every section
boundary (Now → Later → Someday → Done) for free.

`.task-add` rows are stops too. Their `<textarea>` doesn't have an
autoEdit handoff, so the navigator focuses the input directly via
DOM and parks the caret at end. Down from the last task in Now
lands on Now's add-row, then the first task in Later, etc — the
typing flow doesn't strand at section boundaries.

Multi-line guard: ↑ only navigates when the caret is on the first
line (`!before.includes('\n')`); ↓ only when on the last line. So
the rare multi-line title still gets in-text Up/Down behavior.

`Shift+↑ / ↓` reorders. For tasks: re-uses `applyTaskMove`
(same code path as drag-reorder, same op shape). For subtasks: a
two-element swap inside the parent's subtask list, sent through
`reorderSubtasks`. Won't escape the parent — at the boundary it
just refuses. Edit focus stays on the moved row because React
preserves DOM nodes across re-orders when keys are stable
(`key={t.id}`).

## 6. Visual cleanup

- **Toggle placement.** Caret moved from before the title to after
  it — the title is the load-bearing element and should read first;
  the toggle is meta.
- **In-progress checkbox stripes removed.** The diagonal accent-soft
  / paper striping on `.task-row[data-status="in_progress"]
  .task-check` was distracting more than meaningful — section
  membership already conveys "active" in Now, and tag chips do the
  rest. Plain checkbox now.
- **Click on row body still pops the modal.** With inline edit
  scoped to `.task-title` text, the rest of the row preserves its
  pre-sprint click target for opening the full modal. The two
  affordances coexist — title for fast typing, body for full-edit.

## Decisions worth remembering

- **Stage the typing flow ahead of the merge.** Stage 1 was Enter /
  Tab / inline edit / toggle / row sizing — typing-only. Stage 2
  was the merge contract on drag. Splitting let the user feel the
  typing UX (which dominates day-to-day) before bikeshedding the
  edge cases of merge content semantics. Tab demotion's "drops
  description / blocks / estimate / tags" caveat is only OK because
  the typing flow that uses Tab always operates on freshly-minted
  empty tasks.
- **Edit hit-zone is the title text, not the row.** Tempting to
  make the whole row click-to-edit since the title is most of the
  row visually, but the row's "click → open modal" behavior is
  load-bearing for everything that *isn't* the title (chips,
  subtask body, padding edges). Scoping the edit hit-zone to
  `.task-title` lets both affordances coexist without a `mode` flag.
- **Block re-point via delete + create.** `block.update`'s
  `BlockPatch` doesn't accept `task_id` — adding it would mean a
  server op extension, a migration of intent, and a new validation
  path. delete+create reuses existing ops, the calendar slot stays
  put visually, and the only consequence is a new block id, which
  isn't user-visible.
- **3-zone merge with thirds, not pixels.** Percent-based zones
  (30/40/30) keep the merge band predictable across `--fs-scale`
  variations — a user with bigger inbox text gets a proportionally
  bigger merge zone, not a constant 12 px sliver buried in their
  taller rows.
- **DOM order is the navigation order.** Resisted the urge to build
  a parallel "navigation graph" in component state. The rendered
  DOM is the source of truth for what's visible, and
  `querySelectorAll` is fast at this scale (~50 rows). Collapsed
  groups, assignee buckets, sections — all already correctly absent
  from the chain because they're not in the DOM. Less code to
  drift than an in-memory mirror.
- **Description merge: single newline after the heading.** A blank
  line between heading and body made the merged-in section look
  like a heading floating above unrelated prose. Tight join reads
  as one block while keeping the blank line *between* sections
  (so adjacent merges don't run together).
- **Stable `key={t.id}` preserves focus across reorders.**
  Shift+↑/↓ relies on this — if React unmounted and remounted the
  TaskRow on every sort_key change, the focused textarea would
  blur on every keystroke. Documented as an invariant of the
  navigation contract.

## What we noticed but didn't fix

- **Tab demote is title-only.** A task with description / blocks /
  estimate / tags can be Tab-demoted, and its non-title content
  vanishes. The drag-merge path covers all of it correctly; Tab
  could route through `mergeTaskInto` too once the typing flow is
  validated. Skipped this sprint to keep Stage 1 small.
- **No auto-expand on navigation into a collapsed subtask group.**
  Down from the last task in a parent skips its (collapsed)
  subtasks and lands on the next task. Auto-expanding on entry
  would let the user "fall into" subtasks, but it'd surprise
  users who collapsed deliberately. Wait for someone to ask.
- **Drag-merge has no in-flight preview of the absorbed content.**
  The cyan row highlight signals "merge target" but doesn't
  preview "your blocks will land here". Fine for the typical flow
  (merging an empty placeholder); could matter when merging two
  tasks each with rich content.
- **Block re-create is visible if a peer client is watching.** A
  peer's calendar will see the original blocks vanish and new ones
  appear at the same time slot. Identity changes; visually it's a
  flash. Could ship a `block.set_task` op later if this becomes
  noticeable in real workflows.
- **`addTaskAfter` doesn't carry the active tag filter.** Sibling
  tasks created via Enter inherit nothing — the section / project /
  assignee come from the source, but tag_ids start empty. The
  AddTaskRow path *does* seed `inboxFilter.tag_ids` (sprint 21);
  Enter-created tasks don't. Probably should match.
- **`TaskRow` still isn't memoized.** Same caveat as sprint 24 —
  a tag toggle re-renders every row, and inline-edit added more
  props that change per-row. `React.memo` with a focused equality
  check would help once the row count grows.
- **Inline-edit / keyboard flow is desktop-only by design.** Phones
  retain tap-to-open-modal, no inline edit, no keyboard nav (no
  keyboard). Touch *does* get drag-merge though — the touch
  grip-drag pipeline runs through the same `resolveRowDropPos`
  3-zone hit-test as desktop, so a long-press-and-drag onto the
  middle of another row triggers `mergeTaskInto` exactly the same
  way. That's the path to the merge content semantics on mobile;
  the typing flow stays a desktop-only affordance because there's
  no Tab key on phones and modal toolbars were out of scope.
