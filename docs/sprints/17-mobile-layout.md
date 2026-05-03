# Sprint 17 — Mobile layout (3-day calendar, slide-over sidebar, decluttered inbox)

**Status:** shipped
**Date:** 2026-05-03

## Goal

Sprint 16 ended with a clear admission: the app was "the desktop UI,
made tappable" — usable on a phone if you had to be, but not designed
for one. This sprint took the next step: a real mobile layout. Not a
rewrite — the desktop surface stays untouched — but a set of
phone-width overrides that turn the same tree of components into
something you'd actually pull out of your pocket to plan a day with.

The tentpoles:

1. **3-day calendar centered on today.** A 7-day week is the wrong
   unit on a 360 px screen. Yesterday / today / tomorrow with single-
   day prev/next stepping is.
2. **Slide-over sidebar with hamburger toggle.** The 56 px nav rail
   ate ~15 % of a phone viewport for icons the user mostly never
   needed once they knew the keyboard shortcuts they don't have on a
   phone. Now it's a hamburger in the topbar that slides in over the
   content.
3. **Topbar diet.** Strip everything that isn't breadcrumb / sync
   pill / Log out so the title actually fits. The inbox gets the
   same treatment.
4. **Inbox row, plain text.** Tags / "Xh over" / external_id chips
   removed. The row is now grip · check · title — and the title
   column extends to the viewport edge instead of stopping mid-
   row for trailing meta.
5. **Stacked task rail on phones.** Hidden below 1000 px since
   sprint 16; now back, stacked under the calendar with a long-
   press touch path mirroring the inbox row. Drag-to-schedule from
   the rail finally works on a phone.
6. **No more iOS pinch-zoom or focus-zoom.** Viewport locked at
   `initial-scale=1, maximum-scale=1, user-scalable=no`. Inputs
   bumped to `≥ 16 px` on mobile so iOS Safari doesn't auto-zoom
   on focus.

## 1. 3-day calendar centered on today

The original 7-day grid is parameterized by a single `weekStart`
timestamp threaded through `blockToGrid` / `gridToBlock` /
`placeBlocks`. Two observations that made the mobile mode cheap to
add without forking the component:

- `blockToGrid(b, anchor)` is anchor-agnostic — it doesn't care that
  the anchor is a Monday. Pass any date and `day` becomes "days from
  that anchor."
- The day-column rendering loop maps over `DAY_LABELS` (length 7).
  Replace that with a derived `dayLabels` array, and the grid
  shrinks naturally.

Implementation:

- New `dayOffset` in the store, separate from `weekOffset`. The
  desktop and mobile cursors are independent — rotating the device
  or resizing the window doesn't fight, and each layout owns its
  own time cursor.
- New helpers in [time.ts](../../web/src/time.ts):
  `dayAnchorFor(dayOffset)` returns the local-midnight ms of
  "yesterday relative to today + dayOffset" (column 0 of the 3-day
  grid), and `dayOfWeekLabelFor(anchor, idx)` produces "MON"/"TUE"
  labels for a date.
- A new [hooks.ts](../../web/src/hooks.ts) carries
  `useMediaQuery(query)` and `useIsMobile()` so all components
  answer the same "are we on a phone" question instead of each one
  inlining its own `matchMedia` width threshold.
- In [CalendarView.tsx](../../web/src/components/CalendarView.tsx)
  `weekStart` was renamed to `gridAnchor` throughout. On mobile,
  `gridAnchor = dayAnchorFor(dayOffset)` and the grid renders 3
  columns; on desktop, `gridAnchor = weekStartFor(weekOffset)` and
  it renders 7. The "today" highlight collapses to a `todayCol`
  index (1 on mobile when `dayOffset === 0`, otherwise -1), and
  `isCurrentRange` drives the `Today` button's active state for
  both modes. The toolbar's `‹ Today ›` buttons step `dayOffset`
  on mobile and `weekOffset` on desktop.
- CSS phone block at the end of
  [calendar.css](../../web/src/styles/calendar.css):
  `.cal-grid { grid-template-columns: 56px repeat(3, 1fr); min-width: 0 }`.
  The base rule sets `min-width: 700px`; the phone override has to
  live at the bottom of the file so cascade order beats it (see
  decision below).

The "yesterday / today / tomorrow" framing is the part that
actually clicks for mobile use. The user opens the app and sees
*now*, with one day of context on either side. Prev/next are
single-day steps so navigating to a specific day takes 1–3 taps,
not "scroll a week, locate the day."

## 2. Slide-over sidebar + hamburger

Sidebar redesigned around two flags: `useIsMobile()` for layout
mode, and `sidebarOpen` in the store for whether the slide-over is
visible. On desktop neither matters and the existing 56 px rail
stays in the grid. On mobile:

- `.app { grid-template-columns: 1fr }` — the sidebar leaves the
  grid.
- `.sidebar { position: fixed; transform: translateX(-100%); transition: transform 160ms ease-out }`
  — sits off-screen by default.
- `.sidebar[data-open="true"] { transform: translateX(0) }` — slides
  in when the hamburger toggles `sidebarOpen`.
- `.sidebar-scrim` is a fragment-level sibling rendered only when
  open — clicking it closes.

Every nav button calls `close()` on click so the user lands on
the destination view without an extra tap-outside step. The "F"
brand mark on desktop is replaced by a Lucide `Menu` icon in the
topbar at phone widths.

[Sidebar.tsx](../../web/src/components/Sidebar.tsx) wraps the
existing markup in a fragment + scrim; [TopBar.tsx](../../web/src/components/TopBar.tsx)
swaps the `Fira` crumb for the hamburger when `useIsMobile()`.

## 3. Topbar / cal-toolbar diet

User direction: *cut horizontal space as much as possible*. On
mobile keep only breadcrumb (workspace switcher + project icon),
sync pill, Log out.

Hidden at `≤700px`:

- `topbar-me` (own avatar + linked-partner avatar)
- `link-pair` button
- `playground-pill`
- The week title (`Week of …`) — the calendar's own toolbar
  already shows the day numbers, so the topbar copy was redundant
- `crumb-sep` between Fira and the workspace (Fira itself is gone
  on mobile, replaced by hamburger)

Same trim on the calendar toolbar:

- `.user-picker` (the multi-person tab strip) — hidden on phones
- `.link-toggle` (Show linked / Show personal) — hidden on phones

What's left: `‹ Today ›` nav + the totals strip below. Fits a
360 px row.

## 4. Inbox row → plain text

The pre-sprint task row was: `:: · check · title (small grey
external_id) ··· tag chip · "Xh over" / "Xh left" / "no est"`.
Five visual elements compete for the eye on a row that's mostly a
title. User wanted the title to be the row.

Removed from the JSX in [InboxView.tsx](../../web/src/components/InboxView.tsx):

- The `task-trail` div (tag chips + left-est indicator + "no est")
- The `ext-id` span after the title

Result: row is `:: · check · title` with subtasks below. The grid
template lost its trailing `auto` column and the right-side `8 px`
padding so the title can run to the row edge.

Side-effect cleanup: `taskTimeLeft` and `fmtMin` imports dropped
from `InboxView.tsx`; `left` / `lowLeft` calculation removed from
`TaskRow`.

The same row layout still hosts the long-press drag from sprint 16,
unchanged.

## 5. Inbox padding tightened on phones

`@media (max-width: 700px) { .inbox-doc { padding: 16px 8px 80px } }`.
Editorial 48 px side margins on a phone left ~18 % of the viewport
empty per side; now the row runs near the edges. The
project-header meta ("10 tasks · 3 members") is hidden at the same
breakpoint to keep the header on one line with the Archive button.

## 6. Stacked task rail with long-press drag

Sprint 16 hid `.cal-rail` below 1000 px because HTML5 drag from
the rail wasn't a touch path and the rail was eating two-thirds of
the viewport for a non-functional list. Both reasons are fixed:

- **Stacked, not side-by-side.** Phone breakpoint flips
  `.calendar` from `grid-template-columns: 1fr 320px` to
  `grid-template-columns: 1fr; grid-template-rows: minmax(0, 1fr) minmax(160px, 38vh)`.
  Rail sits below the calendar, takes ~38 % of viewport height,
  scrolls independently.
- **Long-press matches the inbox.** The pre-sprint touch path on
  `.rail-task` was `setPointerCapture` on `pointerdown` and
  immediate-drag on `pointermove`. That made vertical scroll
  impossible — every touch became a drag, and `touch-action: none`
  on the row blocked native scroll. Replaced with the inbox
  pattern: 220 ms hold timer with 8 px scroll-cancel; on lock,
  attach a non-passive document-level `touchmove` listener that
  `preventDefault`s page scroll and forwards coords to
  `onTouchSchedule`. A `suppressClickRef` swallows the synthetic
  `onClick` after a successful drop. Vibrate on lock so the user
  feels the commit.

`touch-action: none` removed from `.rail-task` — the row's natural
scroll behavior is restored, the long-press path takes over only
when intent is clear.

## 7. Viewport + iOS focus-zoom

Pre-sprint viewport was `width=device-width, initial-scale=0.5`
(sprint 16 — "the desktop layout renders at half size"). With a
real mobile layout in place, the half-scale is no longer needed.

New viewport: `width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover`.
Disables both pinch-zoom and the focus-zoom Safari does when an
input lands in viewport.

iOS Safari still auto-zooms a text input whose effective font-size
is below 16 px, even when `user-scalable=no` says no. The fix is
in CSS, not viewport meta:

```css
@media (max-width: 700px) {
  input, textarea, [contenteditable="true"] {
    font-size: max(16px, var(--fs-md));
  }
}
```

`max(16px, var(--fs-md))` keeps the desktop token in charge when
the phone scale is bigger than 16, but floors at 16 to satisfy
Safari's threshold.

## 8. Calendar can't be text-selected anymore

Long-press on the day grid was selecting hour gutter labels and
day-header text. `.cal-grid-wrap { user-select: none }`. Time
blocks already opted out individually; this catches everything
underneath.

## 9. Safari "Hide My Email" suggestion suppressed

A regular text input in the inbox add-task field surfaced
"Hide My Email" in the iOS keyboard chip strip. iCloud's heuristic
fires on un-named text inputs that look like signup fields. Fix
on both add-task and subtask-edit inputs in
[InboxView.tsx](../../web/src/components/InboxView.tsx):

```jsx
name="task_title"
type="text"
autoComplete="off"
autoCorrect="off"
autoCapitalize="sentences"
spellCheck={false}
```

`name` + `autoComplete="off"` + `type="text"` together is what
defuses the suggestion. Each one alone wasn't enough.

## 10. Smaller fixes

- **Project modal stops grabbing focus on the name field.**
  `autoFocus` removed from the name input in
  [ProjectModal.tsx](../../web/src/components/ProjectModal.tsx) so
  the modal opens neutral — iOS doesn't pop the keyboard the moment
  you tap a project icon to edit it.

## Decisions worth remembering

- **Two cursors (`weekOffset` + `dayOffset`), not one mode-aware
  cursor.** The desktop user and the mobile user are *the same
  user*, often within minutes of each other. Sharing one cursor
  meant rotating the phone from portrait to landscape, or
  resizing a desktop window past 700 px, would either reset their
  position or interpret the number wrong (5 weeks ≠ 5 days).
  Independent cursors cost 16 bytes of state and avoid every
  mode-switch question.
- **Phone CSS at the end of the file.** Both `globals.css` and
  `calendar.css` had top-of-file `@media (max-width: 700px)` blocks
  that lost the cascade to base rules later in the same file (CSS
  specificity is the same; later wins on tie). The `.cal-grid
  { min-width: 700px }` base rule was clobbering my mobile
  `min-width: 0` override and producing a 3.5-column grid that
  scrolled horizontally. Moved all phone overrides to the bottom.
  Lesson: when in doubt, *put the override after the rule it's
  overriding*. Don't rely on `@media` to win specificity.
- **`useIsMobile()` instead of inline `matchMedia` per component.**
  Three components had their own copy of the same `useState +
  useEffect + matchMedia.addEventListener` block before this
  sprint. Centralized into one hook with a single breakpoint
  literal. The breakpoint is the kind of thing future-you will
  want to tune in one place; spreading it across three files makes
  that a search-and-pray refactor.
- **Long-press anywhere is the default touch interaction.** The
  inbox proved this in sprint 16 — long-press to drag, tap to
  open. The rail-task in this sprint adopted the same pattern,
  not because it was the cheapest, but because *interaction
  consistency across the app* matters more than per-surface
  cleverness. A user who learned the gesture once should be able
  to use it everywhere drag is possible.
- **No mobile-specific component tree.** The whole sprint was
  CSS overrides + a `useIsMobile` flag in three components. The
  alternative was spinning up `<MobileCalendar />` /
  `<MobileSidebar />` and forking the render trees. The "render
  the same JSX, override at CSS / a single boolean" path keeps
  the desktop and mobile behavior provably aligned — when we add
  a feature, we don't have to remember to add it twice.

## What we noticed but didn't fix

- **Drag-to-create on the day column on touch.** Still gated off
  from sprint 16. With a 3-day grid and stacked rail, the gesture
  has more room to work, but distinguishing it from a vertical
  scroll without a long-press conflict with block-tap is still
  non-obvious. Punted.
- **Calendar block move/resize at phone widths.** Works (pointer
  events drive it), but the 100 px-wide day column makes
  cross-day drags fiddly — a 1 px finger tremor counts as a
  cross-column intent. No fix yet; might want a small
  drag-confirm threshold per column width.
- **Inbox header on phones is still tight when the project name
  is long.** "10 tasks · 3 members" is hidden, but the title can
  still wrap above the Archive button. Acceptable; not pretty.
- **Tablet (700–1000 px) layout is the awkward middle.** The rail
  is hidden at this breakpoint (sprint 16's `max-width: 1000px`
  rule), but the 7-day calendar is still active. Long-press drag
  from the inbox works, but you can't drag from the rail because
  the rail isn't there. Either drop the breakpoint to 700 px
  (rail visible everywhere ≥ 700) or design a tablet-specific
  rail. Left as-is.
- **The slide-over sidebar doesn't lock body scroll when open.**
  Background can still scroll on iOS while the menu is up. Low
  priority — the menu auto-closes on selection — but a known
  paper cut.
