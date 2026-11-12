# Sprint 37 — sprint descriptions, task order, `task-cli sync`

**Status:** built
**Date:** 2026-11-12

## Goal

Close two gaps found while dogfooding task-cli: the sprint description was
local only because Fira had nowhere to keep it, and task order was never
compared, so reordering a sprint in Fira or in the file left the other side
silently different.

This reverses part of sprint 35's decision ("Fira holds the plan"): the
order of a sprint's tasks is now synced. Priority and status history stay
in Fira.

## Sprint description

- [x] `sprints.description_md` (migration 0039), counted in the sprint's
      revision so a concurrent edit is a conflict.
- [x] Op `sprint.set_description`, allowed through `/api/cli/apply`.
- [x] Web: a Description field in the Edit sprint modal, shown read-only
      at the top of the sprint card's `?` information popover.
- [x] CLI: the text between a sprint file's title and its first task is
      compared as the sprint's `description` and written either way.
      Against a server without the column it is not compared.

## Task order

The order of task headings in a sprint file is compared with the order of
the sprint's checklist in Fira (`sort_key` in byte order, as the web
sorts), as the sprint field `order`.

- Only tasks on both sides are compared. A task only in Fira or only in
  the file is handled by the absence rules and keeps its place.
- What's compared is the order the run will produce. `publish` appends the
  tasks it creates to Fira's checklist, and `import` appends the tasks it
  adds to the file. So a new task placed at the top of a file already shows
  as an order difference, and choosing local places it correctly in the
  same run.
- **Local → Fira:** one `task.reorder` with the whole project's task order
  (`/api/cli/fetch` now returns `task_order`). The sprint's tasks swap
  slots among themselves and every other task keeps its position, which is
  what a drag in the Plan board does. Sent after creates, so new tasks can
  be placed.
- **Fira → local:** task blocks are reordered in the file after all other
  edits. Blocks keep their bytes; only the blank lines between them are
  normalised.
- Guarded like every other field. Order has no revision (`sort_key`
  doesn't bump one), so it is checked by value: the CLI sends the project
  order it fetched as a `task_order` precondition, and `/api/cli/apply`
  locks the project's tasks and rejects the batch if the order changed (a
  drag in the UI, a task created meanwhile). Nothing is written; run again.
- All sprints whose order is chosen local go into one `task.reorder`, so a
  second sprint's reorder can't undo the first's.

## `task-cli sync fira [files…]`

`publish` creates in Fira, `import` creates locally. `sync` is the merge
for what already exists on both sides. It runs the same diff and the same
per-field choice over the named files (default: all of `tasks/`), and
creates nothing on either side. Tasks not in Fira yet are listed and left
for `publish`, and Fira work in no file is listed and left for `import`.

## Tests

- CLI: end-to-end build → plan tests on a temp repository for order in
  both directions, a new task placed mid-file, a Fira-only task keeping
  its slot, old servers, description in both directions, and `sync`
  creating nothing.
- API: `sprint.set_description` round-trips and bumps the revision;
  `task.reorder` is accepted and `task_order` follows byte order.
