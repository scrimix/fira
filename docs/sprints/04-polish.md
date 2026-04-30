# Sprint 04 — Polish

**Status:** done
**Date:** 2026-04-30

## Goal

Sprint 03 made the app deployable but ugly. The login screen looked flat,
project "icons" were unicode glyphs hardcoded in seed data, the calendar
view squandered horizontal space on a left rail that mostly duplicated
data shown elsewhere, the user picker dropdown clipped off-screen at
common widths, and dozens of small interaction details (subtask edit,
add-task alignment, draft estimate) didn't match between views. Time to
fix the seams.

## What shipped

### Project icons → Lucide

- New `ProjectIcon` component is the single icon registry. 12 curated
  Lucide icons (`Diamond`, `Triangle`, `Hexagon`, `Circle`, `Star`,
  `Sparkles`, `Zap`, `Flame`, `Compass`, `Rocket`, `Code2`, `Box`) —
  geometric → symbol → tools, easy to extend.
- Backwards-compatible: when the stored icon string isn't in the
  registry, the component falls back to rendering the literal text.
  The seed projects' `◆ ▲ ◇` glyphs still render unchanged.
- The picker in the project modal renders actual Lucide SVGs (4×3 grid,
  was 1×8 stretched row). The active state frames the chip with `--ink`
  to match the icon and color picker visual language.
- Icons surface everywhere a project shows up: sidebar nav buttons (in
  the project's color), inbox project header (20 px, centered against
  the H1), top-bar breadcrumb (13 px, inline with the title), modal
  preview header.

### Color palette

Dropped the harsh Tailwind-rainbow first pass for an editorial set: all
~700 shades, distinguishable by hue at the same perceived weight on
paper. Each swatch carries a human-readable name (used as the `title`
tooltip):

| Teal `#0F766E` | Cyan `#0E7490` | Blue `#1D4ED8` | Violet `#6D28D9` |
| Pink `#BE185D` | Amber `#B45309` | Green `#15803D` | Slate `#334155` |

Swatch design changed too — instead of the whole button being the color,
the chip sits inset in a paper-colored frame that frames in `--ink` when
active, mirroring the icon picker.

### Project edit

- New API endpoint `PATCH /projects/:id` — auth-required, accepts
  `{title?, icon?, color?}` (any subset), `COALESCE`s untouched fields,
  scoped to `WHERE owner_id = caller` so non-owners get 404 (doesn't
  leak existence).
- `NewProjectModal` → `ProjectModal`: one component for create + edit,
  branched on optional `project` prop. Pre-populates from the project
  when editing, button disables when nothing changed (no useless API
  calls).
- Store: `creatingProject: boolean` collapsed into a discriminated
  `projectModal: { kind: 'new' } | { kind: 'edit'; id: UUID } | null`.
  One source of truth; can't be in both states.
- Trigger lives next to "Archive ticked" in the inbox project header — a
  small `Pencil`-icon ghost button. (First-pass: clicking the breadcrumb
  in the topbar opened the edit modal. Reverted — invisible
  affordance. The pencil button is discoverable.)

### Calendar layout

- **Killed the 200 px left rail.** It held a project filter and a "This
  week" stat block; the latter duplicated the toolbar totals exactly,
  and the former found a better home (see below). Grid changes from
  `200px 1fr 320px` → `1fr 320px`. Calendar columns get back the
  reclaimed width.
- **Project filter relocated** to the top of the right rail, above the
  task list. Sits on `--paper-2` background with a 2 px `--rule-2`
  bottom divider so it reads as filter chrome distinct from the task
  list (which is on `--paper`). Single section with toggle rows
  (swatch / name / week-total minutes). Removed the per-color
  allocation tape — redundant with the per-row counts and visually
  noisy.
- **Toolbar totals recolored** to match the original left-rail palette:
  `done` is `--done` green, `planned` is `--accent` cyan, `total` is
  `--ink`.

### Time-block icons

The `✓ ⎘ ×` glyphs on the hover-only block actions were getting confused
for the title text. Replaced with Lucide `Check`, `Copy`, `Trash2` at 11
px / 1.75–2.25 stroke. Existing color states (green-fill on
checked-tick, accent-on-hover for duplicate, danger-on-hover for trash)
carry over via `currentColor`.

### User picker

Two issues fixed:

1. **Dropdown clipped off-screen** when the picker had only "Me" pinned
   (small wrapper, right-anchored popover extended past x=0). New
   `useLayoutEffect` measures wrapper + popover after paint, decides
   `data-align` = `"right"` if right-anchor fits, otherwise `"left"`.
2. **Popover too wide** (was 280–360 px min/max, often clipped under the
   topbar's logout button). Shrunk to a fixed 220 px and switched the
   row layout to compact-stacked (avatar on the left grid-row 1/span 2,
   name above email on the right) — same trick as the modal's
   `AssigneePicker`. Fits everywhere.

### Login screen redesign

- Layout collapsed to one row of `[Mark] Fira` + tagline + button (was
  three centered rows: blocky letter F, "Fira", tagline).
- Wordmark in **Instrument Serif** (loaded from Google Fonts) — high-
  contrast display serif lifts the editorial-utilitarian feel above the
  blocky Inter Tight default.
- Mark redesigned: 44 × 44 square framing three stacked time-block bars,
  middle bar in cyan accent. Visualizes a planned day, ties to the
  product.
- Soft radial-gradient background + subtle drop-shadow on the card. Feels
  less like a flat error page.

### Inbox

- **Inline subtask edit.** New `InboxSubtaskRow` — click the subtask name
  → inline input, Enter or blur saves, Esc reverts, Backspace on empty
  deletes. Click the parent task title still opens the modal because
  `.subtask` already stops propagation.
- **Add-task alignment.** `.task-add` was free-floating at `margin-left:
  44 px` and the input cursor landed off the title column. Switched to
  the same 4-column grid as `.task-row` (14 px grip / 18 px check /
  1 fr title / auto trail) so the `+` sits in the check column and the
  cursor lines up exactly with the title text above.
- **Project header alignment.** Wrapped `meta + edit + archive` in a
  `.proj-actions` cluster with `align-items: center` (so the icon
  button, archive text, and meta text share a vertical centerline) and
  `align-self: baseline` against the H1 (so the cluster reads as a
  natural meta line beside the title).
- **Project header icon.** The unicode glyph `<span>{project.icon}</span>`
  → `ProjectIcon` rendering an actual Lucide SVG in the project color.
  Legacy unicode-glyph projects fall back through the same component.

### Task modal

- **Add-subtask input is always-on.** Was a two-step "click '+ add
  subtask' → input appears". Now matches the inbox: input is there from
  render, click anywhere on the row focuses it.
- **Draft modal estimate matches the regular modal pattern.** Click-to-
  set: read mode shows `Click to set` (or the formatted estimate), edit
  mode shows the input with full placeholder. Same UX as
  `EstimateEditor` so users don't have to re-learn between views.

### Calendar rail

- **Dropped the `'done'` label** when `left === 0`. Done-ness is conveyed
  by `data-status="done"` styling already; the label was confusing
  ("done" as a separate signal from the done status).

### Top bar

- **Removed the user-name crumb.** It was always the same value (the
  logged-in user) — pure noise. Bread crumb is now `Fira / [icon]
  Title`.

## Decisions worth keeping

- **Lucide for project icons, not custom SVGs.** It's tree-shaken by
  Vite, matches the existing thin-stroke aesthetic of the sidebar
  navigation icons, and a deep enough catalog that adding a new icon
  is one line in `PROJECT_ICONS`.
- **Unicode-glyph fallback in `ProjectIcon`.** Migrating seed data
  to Lucide names would have been one extra mental step and a
  schema-coupled gotcha if any external integration ever wrote raw
  glyphs. Falling back to literal text means the registry can grow
  freely without breaking the past.
- **Tailwind-700 palette, not a custom one.** It's a known-good chroma
  range against paper-white, and the existing seed projects (teal,
  amber, violet) already lived there.
- **One `ProjectModal` for create + edit.** The diff between the two
  was just initial values + button label; splitting into two
  components like we did with `TaskModal` / `TaskModalDraft` would
  have been a category mistake (those two diverged structurally; this
  one didn't).
- **Edit affordance: pencil icon next to Archive, not click-the-
  breadcrumb.** Discoverable wins over clever. The breadcrumb-as-
  button experiment was reverted because nobody was going to find it.
- **Project filter on `--paper-2` panel, task list on `--paper`.** The
  background shift at the divider does more work than any line weight
  could. It tells you "this is filter chrome, that is content".
- **220 px fixed-width user popover with stacked rows.** Wider would
  clip; the AssigneePicker proves stacked rows are perfectly
  readable.

## Things that bit us

- `align-items: baseline` on flex parents and SVG-only icon buttons:
  flexbox falls back to using the bottom edge as the synthesized
  baseline, which lands the icon center above where neighboring text
  baselines sit. Fix is a wrapper with `align-items: center` so the
  cluster shares a centerline, anchored to the parent baseline as a
  whole.
- `right: 0` on absolutely-positioned popovers is fine until the
  trigger is small and near the left edge — popover width pushes off
  the viewport. Always measure and pick an anchor side.
- The `outbox: enqueue(...)` → `...pushOp(...)` rewrite in sprint 05
  builds on the `pushOp` helper introduced here as a drop-in
  replacement; doing it in this sprint kept those 17 call sites from
  needing to be touched twice.

## What's deferred

- Sidebar still drops the seed unicode glyph for projects with `icon`
  values not in the Lucide registry. Migrating seed data to Lucide
  names is a one-line change but unimportant — the fallback works.
- The login screen mark is not the favicon yet.
- Drag-resize across midnight (carry-over from sprint 02).
- Compare mode (carry-over).

## Verification

```
$ pnpm typecheck                      → no errors
```

Manual smoke (highlights):

- Click `+` in sidebar → modal with 12-icon picker, 8-color palette,
  live preview. Create → project appears in sidebar, topbar, inbox
  with the chosen Lucide icon in the chosen color.
- Click pencil in inbox project header → edit modal pre-populated.
  Change icon + color → save → updates everywhere live.
- Open user picker with only "Me" pinned → popover anchored to left
  edge, fits without clipping.
- Inbox: click a subtask → editable inline. Type, Enter, saved.
  Empty + blur → deleted.
- Add-task input cursor lines up under the title column.
- Calendar: hover a time block → `Check / Copy / Trash2` icons appear
  in the corner, properly readable.

## Next sprint candidates

1. Push side of sync — wire the outbox to `/ops`, surface the sync
   state in the topbar.
2. Pull side of sync — change feed so other tabs / devices see
   updates without a refresh.
3. Inline editing of task title and estimate in the inbox row (still
   modal-only).
