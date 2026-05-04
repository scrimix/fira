# Sprint 21 — Tags

**Status:** shipped
**Date:** 2026-05-04

## Goal

Tags as a real entity with identity, color, per-project scope, and a
filter on the inbox. Up to this point `tasks.tags` was a `TEXT[]`
column populated by the seed and never editable from the UI — a
playground fiction. This sprint promotes tags to first-class data with
their own ops, picker UI on tasks, an editor on projects, and a
sticky filter strip on the inbox.

Why now: the next integration we're sketching is Jira epics, and
"epic" is shaped almost identically to "tag" (id, label, color, M:N
attached to tasks). Building tag plumbing first means epic semantics
slot in later without a second schema pass. It also unblocks
analytics groupings and rolled-up estimates that the inbox couldn't
do against unstructured strings.

## 1. Schema and ops

`tasks.tags TEXT[]` is gone. Migration `0015_tags.sql` adds:

```
tags(id UUID, project_id UUID FK, title TEXT, color TEXT, created_at)
  UNIQUE(project_id, lower(title))
task_tags(task_id UUID, tag_id UUID, PK(task_id, tag_id))
```

Per-project scope, not per-workspace: matches how the seed already
used tags ("auth", "billing", "perf") and lines up with future
Jira-epic semantics where epics belong to a project. Cross-project
sharing is deliberately not supported — promoting "billing" in two
projects to a single tag would force a workspace-level rename pass we
don't want yet. The case-insensitive unique index on `(project_id,
lower(title))` mirrors how a user thinks about duplicates ("Auth" and
"auth" should clash).

No backfill: the previous string-array column was demo-only, the seed
re-emits proper rows. `seed_tasks` walks every distinct
`(project, tag-title)` pair, inserts a real `tags` row with a
deterministic UUID and a palette color, then writes `task_tags` for
each task → tag attachment. The `dump-bootstrap` snapshot got
regenerated against this; the playground bootstrap.json now carries
12 tag rows and `tag_ids` arrays on tasks.

Five new ops, all routed through the existing outbox / per-op /
processed_ops loop:

- `tag.create { tag: { id, project_id, title, color } }`
- `tag.set_title { tag_id, title }`
- `tag.set_color { tag_id, color }`
- `tag.delete { tag_id }` — server `DELETE` cascades `task_tags` via FK
- `task.set_tags { task_id, tag_ids: UUID[] }` — replaces the whole
  set in one op

Plus `task.create.tag_ids` replaces `task.create.tags`. Authorization
reuses `require_project_access` / `ensure_task_in_scope` plus a new
`ensure_tag_in_scope` helper. `task.set_tags` validates that every
tag id belongs to the same project as the task before overwriting —
no silent filtering, the whole op rejects if any id crosses projects.

`Bootstrap` grows a `tags: Tag[]` array; `list_tasks_in_scope` adds a
parallel `task_tags` join to populate `tag_ids` on each task. Two
SQL queries instead of two-then-one — `tokio::try_join!` runs the
subtask + tag-link fetches concurrently.

## 2. `task.set_tags` over per-add / per-remove ops

The first sketch had `task.add_tag` / `task.remove_tag`. Discarded:
under concurrent edits two clients could each commit a `remove_tag`
of A and an `add_tag` of B and end up converging to neither tag
removed nor added depending on order. With `task.set_tags` the
intent is the entire set the user saw when they clicked, last-write-
wins matches what the user saw. The TaskModal picker fires one
`task.set_tags` per toggle, which is one more op than strictly
necessary for a single click but keeps the wire shape simple.

## 3. ProjectModal — tag editor

New "Tags" section under "Members" (workspace owner / project lead
only — gated the same as the rest of the project modal). Each row:
swatch dot, title, usage count (`unused` / `N tasks`), pencil,
trash. Pencil expands the row into an inline edit panel with a
title input and the same 8-color swatch grid the project picker
uses (re-used the `COLORS` constant, not a separate palette — keeps
the design system tight). Trash opens a single-step `ConfirmDelete`
with body wording that surfaces the affected task count: "*billing*
will be removed from 4 tasks and deleted from this project."

All four mutations fire immediately as their own outbox op — no
batching with the project's "Save changes" button. Mirrors the
WorkspaceModal pattern (member role changes ship live too); avoids
the worst-case where a stale edit panel state silently overwrites a
peer's tag rename.

## 4. TaskModal — multi-select picker

Read-only chip list replaced with a `<TagEditor />`. Selected tags
render as `.tag-chip`s with × to remove. A small `+` button
(matching chip height, dashed outline) opens a popover anchored to
the whole Tags section row, not just the `+` button — this matters
when chips wrap and the popover would otherwise float below the wrap
column.

The popover lists every project tag with the search input on top,
chip-style rows below, an inline "Create *<query>*" footer when the
query doesn't match an existing tag. Toggle commits a single
`task.set_tags`; create commits `tag.create` + `task.set_tags`.
Position is computed via `getBoundingClientRect` against the section
row and rendered through `createPortal(..., document.body)` so it
escapes the modal sidebar's `overflow: auto`. Z-index 1300 (above
the `modal-backdrop` at 50). A `ResizeObserver` re-runs `place()`
when chips are added or removed inside the row — without it the
popover stayed pinned at its original Y while the row grew below it.

**Mobile placement.** The task modal's right sidebar defaults closed
on phones, so the side-pane Tags field would be invisible until the
user toggled it. `useIsMobile()` gates the Tags block: rendered in
the main pane (between the estimate bar and the Description heading,
under a `<SectionHeading>`) on phones, in the side pane on desktop.
One `<TagEditor>` instance, conditional placement.

## 5. Tag chip styling

All tag chips share `.chip.tag-chip` typography (mono caps,
`calc(10px * --fs-scale)`, 0.04em tracking) so the inbox row chip,
the TaskModal selected chip, and the popover row all read as the
same atom. Color treatment is a **faint, desaturated outline**
derived from the tag's hex via
`color-mix(in srgb, var(--tag-color) 35%, var(--paper))`. The chip
background stays paper-white; the popover row gets an 8% wash on
hover and 12% when selected. No colored circle — earlier iterations
had a 10×10 dot which read as visual noise without paying much
information dividend on chips already labeled in caps mono.

The `--tag-color` CSS variable is set inline per chip via `style`
prop; CSS rules pick it up via `color-mix`, so adding tag colors
later (or reskinning the palette) doesn't require touching the
chip code path.

## 6. Inbox sticky filter strip

New `<InboxTagFilter />` between the project header and the Now
section. Sticks to the top of the `.inbox` scroll container so the
active filter stays visible as the user scrolls Now / Later /
Done. Hidden entirely when the project has zero tags — the strip
would otherwise be empty visual debt.

Layout is a 2-column grid (`minmax(0, 1fr) auto`):

- Left column: chip toggles, wrap-flow.
- Right column: a 2-segment OR/AND toggle and a Clear button.

Both controls are **always rendered** — clear gets `disabled` when
no tags are selected, OR/AND works as a pre-set when nothing is
selected. The previous shape (controls appearing/disappearing as
selection changed) made the chip strip jump horizontally, which was
worse than a slightly inert button.

On mobile the controls stack vertically in the right column
(`flex-direction: column; align-items: stretch`) so they don't
crowd against the wrapped chips. Chip sort in the strip is **by
title length descending** (alpha tiebreak): seeding each row with
the longest chip lets shorter ones slot into the trailing space,
fewer ragged half-empty rows on narrow widths than alphabetical
order would produce. The TagEditor popover and project tag editor
stay alphabetical — those are scan-by-name surfaces, the filter
strip is a pack-tight surface.

`scrollbar-gutter: stable` on `.inbox` reserves the scrollbar's
track width whether the doc overflows or not. Toggling a tag chip
that drops the doc below viewport height no longer shifts the
column horizontally.

`:has(+ .inbox-tag-filter)` on `.inbox-proj-head` drops the header's
own border-bottom + bottom margin when followed by the filter strip,
so the strip docks flush under the header with one shared rule
between header zone and content. When no filter strip renders, the
header keeps its original border.

## 7. Filter behaviour

`InboxFilter` grew `tag_ids: UUID[]` and `tag_mode: 'and' | 'or'`.
`projectTasks` filters `every` (AND) or `some` (OR) before splitting
into Now / Later / Done. `inboxFilter` is now in the `partialize`
list so the active filter survives reload.

Two pruning paths so a phantom filter never references a deleted
tag:

- `applyBootstrap` filters `tag_ids` against `data.tags` before
  applying. Catches the case where a peer deleted a tag while we
  were offline.
- `tag.delete` (both the local mutator and the `applyOpToState`
  path) strips the tag from `inboxFilter.tag_ids` in the same set
  call that drops the tag and rewrites task tag_ids.

**OR / AND vocabulary.** First sketch labeled the toggle `any` /
`all` — discarded after testing. Users say "billing AND bug AND
security" out loud, not "billing all bug all security". The toggle
labels are the words in the user's mental model.

**Two-segment toggle.** A single button cycling `or` ↔ `and`
required the user to read state to know what clicking would do.
Rendered as two adjacent buttons with the active one filled (`--ink`
background) and the inactive one ghost (`rule-2` border) — the
current mode is unambiguous and clicking the other segment switches.
Borders collapse between segments so the pair reads as one control.

## 8. Quick-add seeds the active filter

Creating a task while a tag filter is active automatically attaches
those tags. Without this, typing "Stripe webhook idempotency" into
the Now add-row under filter `[billing]` produced a task that
immediately disappeared from the row it was just typed into.

Implementation: `addTask(projectId, section, title, assigneeId?,
tagIds?)` accepts an optional fifth arg, defaults to empty. Every
inbox quick-add call site (assignee groups, no-groups Now row,
Later, Done) passes `inboxFilter.tag_ids`. The new task carries the
tag ids both in its local `Task` shape and in the outbound
`task.create` payload — server validates them via the existing
project-scope guard.

## 9. Task row chip rendering

The inbox row trail shows up to 3 chips with a `+N` overflow chip
when more exist. Sort prioritizes filter-matched ids first (stable
secondary on insertion order) so the cap always surfaces the tags
the user is actively filtering on, regardless of how the task was
tagged.

When a filter is active (`data-has-filter` on the trail),
**unmatched chips fade to opacity 0.45** and matched chips get a
stronger color-mix outline (60% / paper) plus a 14% wash background.
With no filter active every chip renders at full weight.

On phones the row caps at **1 chip** (filter-match wins the slot if
present, otherwise the first sorted tag) plus a `+N` overflow if
more. The estimate-meta tail stays desktop-only — phone rows are
already cramped. Restored a 6px right padding on `.task-row` so the
mobile chip doesn't kiss the viewport edge.

## 10. Smaller fixes that came along

- `--done` swapped from Tailwind green-700 (`#15803D`) to a muted
  sage (`#4D7C5A`). The ticked time-block button was the loudest
  thing on the calendar in the previous color; sage reads as "done"
  without competing with the editorial ink/paper neutrals. The
  `chip[data-tone="done"]` border now derives from `--done` via
  `color-mix` instead of a hardcoded `#B0D6BD`, so the two stay in
  tune if the token shifts again.

## Decisions worth remembering

- **Tag identity is a UUID, not a title string.** Renaming was the
  feature that forced this shape; without it a rename meant
  rewriting every task that referenced the old string. Worth doing
  before there were lots of stored rows.
- **Per-project scope, not per-workspace.** Matches the seed's
  existing usage and Jira-epic semantics. Cross-project tag sharing
  is a workspace-level rename problem that we deliberately punted.
- **Single `task.set_tags` op replaces per-add / per-remove.** Set-
  shaped ops converge cleanly under last-write-wins; per-element
  ops produced order-sensitive divergence under concurrent edits.
  Trade-off: one op per click instead of one op per session, which
  is fine because clicks are slow.
- **Tag color is rendered as a faint `color-mix` outline, never as
  a solid fill or a separate dot.** The chip is a labeled rectangle;
  the color is a hint, not the identity. `color-mix(in srgb, hex
  35%, paper)` desaturates without picking a second hardcoded color.
- **Tag chips in the inbox filter strip sort by title length desc.**
  flex-wrap is a one-pass left-to-right layout; seeding rows with
  long chips lets short chips slot in. Alpha order produced
  visibly more wasted whitespace in the same width.
- **Match-first sort in the task-row trail.** With a 3-chip cap, the
  sort decides which 3 chips the user sees. Putting the matched
  ones first means filtering by `[billing]` always shows the
  billing chip, regardless of how the task was tagged. Stable for
  the rest so the visible set is predictable as the user scrolls.
- **`scrollbar-gutter: stable` on `.inbox`.** Toggling chips can
  shrink the doc below viewport height. Without the gutter
  reservation the column shifts horizontally as the scrollbar
  appears / disappears, which read as the inbox jumping around.
  Reserving the gutter even when the doc isn't tall enough is a
  better UX than a snappy column.
- **Filter controls always rendered, disabled when not applicable.**
  Conditional rendering (clear shows when ≥1 selected, OR/AND
  shows when ≥2) made the chip strip jump as the user toggled.
  Always-rendered with disabled state is calmer.
- **Auto-attach the filter on quick-add.** A task created under a
  filter that doesn't match it is functionally lost — it just
  isn't visible from the row it was typed into. Seeding the active
  filter into the new task's tag_ids is the obvious right thing,
  and it generalizes: if we add more filter axes later (epic,
  sprint), the same pattern applies.
- **`:has(+ X)` over a JS prop or a wrapper class.** Drops the
  proj-head's border + spacing only when the filter strip is
  rendered, without threading "is the strip showing?" through the
  React tree. Adjacent-sibling has support is recent enough to
  matter; we already use modern CSS like `color-mix` and grid
  `minmax(0, 1fr)` so this isn't a new floor.
- **`useIsMobile()` for "place this section in the main pane vs
  side pane" decisions.** The side pane is closed by default on
  phones; surfaces buried there are effectively hidden. We've now
  done this twice (estimate, tags); pattern is "render once,
  conditionally place".

## What we noticed but didn't fix

- **No per-tag detail modal.** The original plan had a tag-detail
  modal with rolled-up stats (planned hours, completed hours,
  done/planned task counts). The project tag editor covers
  rename / recolor / delete / usage count today; the rolled-up
  stats are nice-to-have but didn't unblock anything. Worth
  picking up if analytics surfaces lean on it.
- **Calendar rail tag filter.** The inbox is the main consumer
  today; the calendar rail (right side, schedulable tasks) doesn't
  honor the tag filter yet. Mostly a question of whether scheduling
  a non-matching task should be allowed at all — if yes, the rail
  needs its own filter UI; if no, sharing the inbox filter is the
  obvious path.
- **Tag color in the chip itself.** Currently the color drives only
  the faint outline + the popover wash. It would be reasonable to
  also tint the chip text or use it for the dot when chips are
  small, but the current restraint reads cleanly and we'd rather
  add color in response to a real ask than speculate.
- **Mobile filter strip behavior at >12 tags.** With many tags the
  strip can take 3–4 rows even with length-desc packing. Acceptable
  for now (the strip is sticky, so it shrinks the visible task list
  predictably); a "show first N + …more" affordance is the obvious
  follow-up if a project's tag count gets long.
