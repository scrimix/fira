# Sprint 18 — Mobile touch, mark 2 (the hard one)

**Status:** shipped
**Date:** 2026-05-03

## Goal

Sprint 17 gave us a *layout* that fits a phone. This sprint tackled the
gestures that actually live on it. The "real mobile layout" hadn't been
real-world tested in a browser — once it was, every touch interaction
that worked on desktop fell apart in slightly different ways:

- Inputs auto-zoomed; the inbox couldn't scroll past Safari's bottom
  toolbar; the task modal didn't fit; long-press on a block triggered
  the system context menu; tapping a block fired the X button under
  the finger; the rail couldn't scroll without dragging a task; the
  rail-task drag worked but tore the rail's scroll position around;
  nothing felt like it had any feedback.

We rewrote large parts of the touch handling instead of patching. The
new mental model is: **gestures lock at 220 ms hold; pre-lock is
exactly the same as a tap; post-lock is a drag with explicit
visual + haptic feedback; the surface beneath the gesture freezes
without flickering its scrollbar.**

## 1. Dynamic viewport — `100dvh` everywhere

`100vh` on iOS Safari is the *layout* viewport (always tall enough to
include both toolbars). Anything sized to `100vh` extends below the
visible area when the URL bar / bottom toolbar are showing. The inbox
couldn't scroll to its last item. The modal's `max-height: 88vh` was
relative to a viewport taller than what was on screen, so the modal
top and bottom went out of reach.

Switched to `100dvh` (with `100vh` fallback) on `.app`, `.inbox`,
`.calendar`, and `.inbox-empty`. Modal capped at `calc(100dvh - 24px)`
on phones, with `width: 100vw` so it edge-to-edges.

The dvh unit is supported by every browser we target.

## 2. Inputs — defeating iOS focus-zoom for real

Sprint 17's rule was `font-size: max(16px, var(--fs-md))` inside
`@media (max-width: 700px)`. It got clobbered: `--fs-md` is
`calc(13px * 1.15) ≈ 15px` (under 16) and several inputs declare
their own font-size further down the cascade, winning on specificity.
Safari kept zooming.

Fix: `font-size: 16px !important` on `input, textarea,
[contenteditable="true"]` inside the mobile media query. We don't care
about visual size variance on phones; preventing the auto-zoom is the
priority and `!important` is the only thing that wins reliably.

## 3. Long-press, the hybrid touch pattern (revisited)

Sprint 16 documented the pattern (pointer events for state,
non-passive document touchmove for `preventDefault`). This sprint
*operationalized* it across two more surfaces — calendar time blocks
and rail tasks — and shook out the corner cases that made the inbox
version look easy in retrospect.

### Time blocks

`.tblock` started this sprint with `touch-action: none` (great:
gesture stays with us; bad: page can't scroll past a block). We
tried `pan-y` to allow scroll — but iOS commits to a vertical pan
*on the first touchmove*, and any later-attached `preventDefault`
listener is ignored. So the long-press timer would fire after
220 ms, but iOS had already chosen "scroll" 200 ms earlier and
wouldn't honor our drag.

Solution: `touch-action: none` is correct on `.tblock`; users scroll
the calendar by touching the gutter or empty day-column space. Same
constraint that `.task-row` has in the inbox.

The `onBlockPointerDown` handler now runs:

1. Record a `blockHoldRef` with origin coords + the 220 ms timer.
2. Window-level `pointermove` cancels the timer if movement exceeds
   8 px (it's a scroll, not a hold).
3. Window-level `pointerup`/`pointercancel` cancels too.
4. When the timer fires: `setLastBlockId`, `setPressingBlockId`,
   `navigator.vibrate(8)`, and only *then* enter the existing drag
   state machine. Pre-lock did nothing visible; lock fires the
   visual + haptic + behavior in one tick.

### Rail tasks

Same long-press pattern, but with one twist: the rail-body is its own
overflow container. `preventDefault` on a *document-level* touchmove
listener doesn't stop iOS from scrolling that inner container; iOS
treats it as a separate scroll context.

We tried a few approaches before landing on the right one:

- `overflow: hidden` on lock → flickers the scrollbar visibly.
- Snapping `scrollTop` back via a `scroll` listener → fights the
  browser mid-gesture, makes the rail stutter.
- Toggling `touch-action: none` mid-gesture → iOS doesn't honor
  `touch-action` changes inside an in-flight gesture.
- Attaching a non-passive `touchmove` listener *to the rail-body
  element itself* on lock → races with iOS's commit. A fast finger
  that started moving before 220 ms still scrolled.

Final answer: a non-passive `touchmove` listener is permanently
mounted on the rail-body via a ref-callback. It consults a mutable
`railFrozenRef` and `preventDefault`s when frozen, otherwise no-ops.
Listener is always present → iOS sees it from the start of every
gesture and waits for our verdict each tick. No race, no leak, no
flicker.

```ts
const setRailBodyEl = (el: HTMLDivElement | null) => {
  if (prev) prev.removeEventListener('touchmove', prev.__freezeHandler);
  railBodyRef.current = el;
  if (el) {
    const handler = (ev) => { if (railFrozenRef.current) ev.preventDefault(); };
    el.addEventListener('touchmove', handler, { passive: false });
    el.__freezeHandler = handler;
  }
};
```

The pattern generalizes: any inner overflow container that needs to
freeze mid-gesture wants a permanent listener on itself, not on
document, gated by a flag.

## 4. The "press" visual — at lock, not before

Initial implementation showed the scale-up + shadow as soon as the
hold timer was armed. That made every quick tap flash the visual on
its way to opening / activating the block, which felt broken: the
block grew, then shrank, then opened. Worse, fast-drag attempts
(movement before 220 ms) flashed the visual then cancelled, looking
like the gesture had registered when it hadn't.

Fixed model: `setPressingBlockId(b.id)` is called *only* inside the
hold-timer callback — the same line that calls `vibrate` and
`setDrag`. Pre-lock has no visual; lock fires visual + haptic + drag
in the same tick. Drag-end clears the pressing state in the global
`onUp` handler, so the block stays scaled-up the entire drag and
shrinks only on release.

Same rule for rail tasks: `pressingRailTaskId` is set in
`lockRailDrag`, cleared in `onEnd`/`onCancel`. CSS:

```css
.tblock[data-pressing="true"],
.rail-task[data-pressing="true"] {
  transform: scale(1.03);
  box-shadow: 0 4px 14px rgba(0,0,0,0.2);
  transition: transform 100ms ease-out, box-shadow 100ms ease-out;
}
```

The "yes, the gesture registered" signal is now consistent across
every long-press surface.

## 5. Action buttons — render, hover, and the "first tap" trap

`.tb-actions` (X / tick / duplicate) had three subtle bugs:

1. **Tappable while invisible.** Default `opacity: 0` left the buttons
   in the DOM with full pointer-events; touch users hit them without
   ever seeing them. Added `pointer-events: none` to the default
   state, flipped to `auto` only inside the hover/active rules.

2. **Sticky hover after tap.** `:hover` rules on touch leave the
   button looking hovered until the user taps elsewhere. Wrapped
   every `.tb-action:hover`, `.tb-tick[data-checked]:hover`,
   `.tb-dup:hover`, `.tb-close:hover` in `@media (hover: hover)`.

3. **First tap activates *and* fires the button.** When the user taps
   in the corner where the X button will appear: pointerdown fires on
   `.tblock` (no button there yet), `setLastBlockId` runs, React
   schedules a render, the buttons appear before pointerup, and the
   click event lands on the now-rendered button. The block deletes
   itself from the same tap that should've just woken it up.

   We tried *not rendering* the buttons until `lastBlockId === b.id`
   — that broke desktop hover (which the user wanted to keep) and
   didn't even fix touch (the click target was determined at pointerup,
   by which time the buttons had appeared anyway).

   Final fix: a one-shot grace window. On a *touch* `pointerdown` that
   transitions a block from inactive → active, `recentTouchActivationRef`
   stores `{ blockId, at: now() }`. Each action button's `onClick`
   calls `consumeRecentTouchActivation(b.id)` — if a fresh activation
   exists for this block (≤ 500 ms), the click is swallowed and the
   ref is cleared. The next tap finds the ref empty and the action
   runs. Mouse users never write to the ref → single-click works on
   desktop.

   This is the contract the user asked for: *tap to reveal, tap again
   to act.*

## 6. Click anywhere clears block active state

Touching the calendar background (or scrolling the page, or tapping
anywhere off a block) used to leave a block stuck in
`[data-active="true"]`. New `useEffect` adds a document-level
`pointerdown` listener: if the press isn't on `.tblock` or
`.tb-action`, `setLastBlockId(null)`. Works on both desktop and
touch — same gesture model both places.

## 7. Rail body — projects collapse + shared scroll

Sprint 17 had `.rail-projects` as a sibling of `.rail-body`, each
with its own scroll context. On phones the rail is height-constrained
(~38vh stacked under the calendar) and the projects list ate the
entire space before any tasks were visible — the user couldn't see
a single task without scrolling the projects panel away.

Restructured: `.rail-projects` is now *inside* `.rail-body`, so the
projects panel and the task groups share one scroll container. Added
a chevron toggle on the "Projects" header: collapsed by default on
mobile, expanded on desktop, persisted via local state. With the
panel collapsed, the rail-body opens directly onto tasks.

## 8. Inbox row — random opens while scrolling

Touch users reported that scrolling the inbox sometimes opened a task
modal. Cause: iOS dispatches a synthetic `click` on `pointerup` even
after a scroll gesture, and the row's `onClick` opens the task
without checking whether the gesture was a scroll.

Added `t.suppressClick = true` to the threshold-exceeded branch in
`onRowPointerMove` (when movement past 8 px cancels the long-press
timer). `finishRowTouch` keeps the ref alive for ~50 ms after the
pointerup so the synthetic click can read the flag and bail out.
Quiet fix; users who scrolled report the random opens are gone.

## 9. Subtask rows — multi-line wrapping in the modal

The task modal's subtask rows had `align-items: center` with no
`min-width` on the title, so a long subtask title overflowed the
modal instead of wrapping. Switched `.subtask` and `.subtask-edit`
to `align-items: flex-start`, gave `.sname` `flex: 1; min-width: 0;
word-break: break-word;`, and added `margin-top: 2px` to `.subtask
.sc` so the checkbox aligns with the first line of a wrapped title.

## 10. Project modal — no auto-focus on edit

Tapping a project icon on mobile to edit it popped the keyboard,
which then blocked the modal. `autoFocus` removed from the project
name input. New-project flow doesn't auto-focus either, but that
flow is rare on phones and tapping the field works fine.

## 11. Smaller fixes

- **Project header `10 tasks · 3 members`** — hidden at `≤700px`
  via CSS. The Archive button was wrapping below the title because
  the meta string ate horizontal room. Desktop unchanged.
- **Show linked / Show personal toggles** stay visible on phones
  (sprint 17 hid them; turns out they're load-bearing for users with
  linked accounts). Compressed padding + smaller font so they fit.
- **Inbox padding** dropped to `16px 8px 80px` on mobile so titles
  reach near the viewport edges.
- **Browser context menu on long-press** — added
  `onContextMenu={(e) => e.preventDefault()}` to `.tblock` and
  `.rail-task`. Combined with the existing `-webkit-touch-callout:
  none`, the system menu doesn't pop on a held finger.
- **Viewport meta** — reverted to `width=device-width,
  initial-scale=1, viewport-fit=cover`. The `user-scalable=no,
  maximum-scale=1` from sprint 17 broke trackpad scroll in Chrome
  DevTools' mobile emulation (some browsers treat the combination as
  "block all gestures"). The 16-px input rule is the only thing
  needed to defeat iOS focus-zoom; locking the page scale was
  unnecessary.

## Decisions worth remembering

- **Always-on non-passive listeners beat lock-time attachments.**
  iOS commits the intent of a touch gesture *on the first
  touchmove*. Any listener attached after that — even by 1 ms —
  is too late if the page is going to scroll instead. If you need
  to be able to suppress scroll mid-gesture, mount the
  `preventDefault` listener at *element-mount time* and gate it on a
  ref-flag. Don't try to attach it on lock.
- **Visual at lock, not before.** The pre-lock window has to feel
  like a tap to a tap-er and like silence to a hold-er. Showing any
  visual feedback during pre-lock makes quick taps flash the
  acknowledgment for a gesture that never registers, and makes
  cancelled holds look like the system rejected something the user
  thought they had committed to. Lock is the contract; visuals fire
  there.
- **Two-tap is a state machine, not a styling problem.** The "tap
  to reveal, tap again to act" contract sounded like a CSS thing —
  hide the buttons until active, show them after. It isn't. The
  click target and the activation transition fire in the same
  React batch, and styling can't separate them in time. The fix is
  a one-shot grace ref the action handlers consult before running.
- **Inner overflow containers are their own scroll universe.** Any
  pattern that "freezes scroll" by attaching to `document` won't
  work for a `overflow: auto` div — the browser scrolls the
  container without ever asking the document. If the container
  scrolls, that's where the listener has to live.
- **`@media (hover: hover)` for every hover style on a touch
  surface.** Otherwise `:hover` sticks after a tap and the button
  looks "hovered" until the user taps somewhere else. Cheap to
  apply; pays back tenfold in feel.

## Post-deploy fixes (production iteration)

The "real-world testing" pass took several iterations beyond what was
written above. Capturing the deltas here so the file reflects what
actually shipped, not what we *first* shipped.

### 12. PWA install / iOS home-screen icon

Two problems with the home-screen flow:

- **Safari tab favicon showed a white halo.** The original
  `favicon.svg` had `rx=14` rounded corners; Safari's tab background
  showed through the transparent corner pixels as a halo. Squared
  the icon (full-bleed dark `#18181B` rect, no rounded corners) and
  reordered the icon links so PNG variants come first — Safari
  prefers PNG for tab favicons and renders SVG with extra background
  framing on some builds.
- **Add-to-home-screen showed a plain "F".** iOS Safari ignores SVG
  favicons for the home-screen icon; it needs an `apple-touch-icon`
  PNG. Added 32 / 180 / 192 / 512 PNGs (generated via `rsvg-convert`)
  plus a `manifest.webmanifest` with name / theme color / icon set,
  the `apple-mobile-web-app-*` meta tags so the launched PWA is
  standalone with the right title and translucent status bar, and a
  `mask-icon` for Safari pinned tabs.

### 13. iOS notch / status-bar overlap in standalone

`apple-mobile-web-app-status-bar-style=black-translucent` makes the
status bar overlay our content; the topbar landed under the notch
with the iOS clock printed on top of it. The viewport already had
`viewport-fit=cover` so `env(safe-area-inset-*)` is exposed; added:

```css
.app {
  padding-top: env(safe-area-inset-top);
  padding-right: env(safe-area-inset-right);
  padding-bottom: env(safe-area-inset-bottom);
  padding-left: env(safe-area-inset-left);
  background: var(--paper);
}
```

With `box-sizing: border-box` and `height: 100dvh` already in place,
the grid content area shrinks below the notch and above the home
indicator. Browser-tab mode reports zero insets — no-op there. The
mobile slide-over `.sidebar` is `position: fixed` so it doesn't
inherit the parent padding; it got its own
`padding-top: calc(14px + env(safe-area-inset-top))` etc.

### 14. Long-press, take three: the inbox saga

Sprint 18's first cut had inbox rows using a hand-rolled long-press
(rowTouchRef + setTimeout). It worked sometimes; mostly it didn't.
Three rounds of debugging:

- **Round 1.** `:hover` was sticky on iOS, leaving a grey
  "background trail" behind whichever row the finger had grazed
  during a scroll. Wrapped `.task-row:hover` (and `.task-grip:hover`,
  `.task-row:hover .task-grip`) in `@media (hover: hover)`. Same
  treatment we already had for `.tb-action`.
- **Round 2.** Drag-on-lock fired immediately, and iOS jitter
  touchmoves at lock time hit-tested to the row's *own* assignee
  group, lighting up the cyan accent before the user moved at all.
  Rewrote `lockRowDrag`: at lock, only set the press-visual + arm a
  document `touchmove` listener; only call `onGripTouchStart` once
  the finger has travelled ≥ 4 px from the lock origin. Held still →
  row enlarges, no group accent. Move → drag engages.
- **Round 3, the real cause.** The visual still didn't show — the
  user reported "nothing changes" even though the CSS rule
  (`.task-row[data-pressing="true"]`) was in place. We hardcoded
  `data-pressing="true"` on every row and confirmed the CSS *did*
  paint, which meant the React state setter wasn't reaching the
  DOM. The root cause turned out to be the **task grip's parallel
  drag path** — `.task-grip` had its own pointer handlers
  (`onPointerDown`, `onPointerMove`, `onPointerUp`, `onPointerCancel`)
  that called `onGripTouchStart` directly, bypassing the long-press
  hook entirely. Touches that landed on the grip went down the
  grip's path and never set `isPressing`; the user thought they were
  testing the row hook but were actually exercising a different code
  path.

  The fix was structural: collapse to **two** drag paths total,
  split by *input type*, not by which child element the user
  touched:

  - **Desktop drag** = HTML5 drag-and-drop, armed by `mousedown` on
    the grip (still useful — grip is a visible drag handle).
  - **Mobile drag** = `useLongPress` on the row body, single path,
    grip included as just visual.

  Stripped the grip's touch handlers entirely. Removed
  `.task-grip` from the long-press exclusion list. The grip on
  mobile is now a pure visual cue; long-press on the grip drags the
  row exactly like long-press on the title.

  While we were rewriting, we extracted a proper
  [`useLongPress`](../../web/src/useLongPress.ts) hook —
  `holdMs` + `cancelPx` options, returns
  `{ isPressing, bind, shouldSuppressClick }`. The TaskRow's
  long-press section dropped from ~80 lines of `setTimeout` /
  `clearTimeout` / refs to a single hook call. Calendar's long-press
  for time blocks could move to it later; left as-is for now since
  the calendar wasn't broken.

### 15. Touch drop on assignee groups: top/bottom resolution

Touch-dragging into an assignee group's empty area was committing
to "wherever the finger last hovered over a row" — usually the row
the user dragged *past* on the way in. Rewrote the assignee branch
in `onGripTouchMove`:

- Read the `assignee-group` element's bounding rect.
- If the finger is in the upper half of the group, point the drop
  to **before** the group's first task; lower half points to
  **after** the group's last task.
- Show the cyan target line on the resolved row (so the user sees
  exactly where the drop lands).
- Empty group: fall back to the assignee-only branch (group accent,
  reassign + section-flip on release).

Same convention `onRowDragOver` uses for individual rows, just
scoped to the whole group's box.

### 16. Time block: visual at lock, click-outside-clears-active,
two-tap grace for action buttons

Three blocks of fixes for the calendar that mirror the inbox work:

- **Visual flash on quick taps.** Original press-visual fired on a
  100 ms pre-lock timer. Quick taps flashed the scaled-up frame on
  their way to opening / activating; cancelled holds (movement past
  8 px before 220 ms) flashed the visual and then shrank, looking
  like the system rejected a gesture the user thought registered.
  Removed the pre-lock timer. `setPressingBlockId` fires *only*
  inside the 220 ms hold-timer's callback, on the same line as
  `vibrate` and `setDrag`. No flash, ever. Press visual rides the
  drag and clears in the global drag-`onUp`.
- **Click anywhere clears active.** Block stayed in
  `[data-active="true"]` after the user moved on (scrolled, tapped
  elsewhere). Added a document-level `pointerdown` listener: if the
  press isn't on `.tblock` or `.tb-action`, `setLastBlockId(null)`.
  Mouse and touch alike.
- **Action buttons firing on the first tap.** When a tap activates
  a block, the buttons render mid-gesture and the trailing click
  hits one of them. Tried CSS-only fixes (`pointer-events: none`
  until active) — didn't help, because the click target is
  determined at `pointerup`, by which time React has already
  rendered the buttons. Final fix: a one-shot grace ref. On a touch
  pointerdown that transitions a block from inactive → active,
  `recentTouchActivationRef` records `{ blockId, at: now() }`. Each
  action button's onClick calls `consumeRecentTouchActivation(b.id)`
  first; if a fresh activation exists (≤ 500 ms, same block), the
  click is swallowed and the ref is cleared. Mouse hover never
  writes to the ref so single-click works normally on desktop.

### 17. Smaller in-flight tweaks

- **Inbox topbar title hidden on mobile, even for inbox view.** The
  project name was duplicated (topbar breadcrumb + page header
  below) and pushed Log out off-screen on narrow widths. Title is
  now `''` whenever `isMobile`, regardless of view; the
  `.title-icon` ProjectIcon next to it is also gated on `!isMobile`.
- **Own-user avatar back on mobile.** The `topbar-me` chip moved
  out of the `!isMobile` block so it always renders. The link
  button + partner avatar stay desktop-only — user said the slot is
  earmarked for a settings menu later.
- **Totals strip centered on mobile.** `.cal-totals-strip` got
  `justify-content: center` inside the phone media query so the
  `Xh done · Xh planned · Xh total` row reads as a banner under
  the toolbar.
- **Show linked / Show personal restored on mobile.** Sprint 18's
  first cut hid `.link-toggle` along with `.user-picker`. Only the
  user-picker should be hidden; the link toggles got compressed
  padding + smaller font to fit the narrow row.
- **Subtask multi-row in modal.** `.subtask` and `.subtask-edit`
  switched to `align-items: flex-start`; `.sname` got `flex: 1;
  min-width: 0; word-break: break-word`; `.subtask .sc` got
  `margin-top: 2px` so the checkbox aligns with the first line of
  a wrapped title.
- **Project modal stops grabbing focus on edit.** `autoFocus`
  removed from the name input — tapping a project icon to edit no
  longer pops the iOS keyboard.
- **`10 tasks · 3 members` hidden on phone widths.** The Archive
  button was wrapping below the title.
- **Inbox-doc padding.** `padding: 16px 8px 80px` on phones so
  titles run near the viewport edges.
- **`100dvh`** on `.app`, `.inbox`, `.calendar`, `.modal`'s
  `max-height`. Inbox can finally scroll past Safari's bottom
  toolbar; modal fits with both toolbars visible.
- **Viewport reverted to `initial-scale=1, viewport-fit=cover`.**
  Sprint 18's first cut had `user-scalable=no, maximum-scale=1` to
  defeat iOS focus-zoom. That broke trackpad two-finger scroll in
  Chrome DevTools' mobile emulation (some browsers treat the
  combination as "block all gestures"). Removed both directives;
  the user opted to live with whatever zoom remains rather than the
  16-px input rule that made fonts ugly. Final `<meta name="viewport"
  content="width=device-width, initial-scale=1, maximum-scale=1">`
  is the user's choice during testing.

## Decisions worth remembering (added)

- **One drag path per input type.** When two child elements (row vs
  grip) had their own touch handlers running in parallel, debugging
  was hopeless — the user thought they were testing the row's
  long-press but the grip's path silently won every time. The right
  split is by *input type* (Desktop = HTML5 drag, Mobile = touch
  long-press), not by *which element* the touch landed on. Make
  the grip a visual cue with no mobile handlers and let the row's
  long-press cover everything.
- **Custom hooks for cross-surface gestures.** Sprint 16 / 17 / 18
  shipped three different long-press implementations across the
  inbox row, the rail task, and the time block — same pattern,
  three slightly different bugs. The
  [`useLongPress`](../../web/src/useLongPress.ts) hook
  consolidates one of them; the calendar versions are next when we
  touch them. Long-press is *the* reusable touch primitive; treat
  it as such.
- **Don't trust "the React state isn't updating" — check
  whether the handler is even called.** We chased a phantom
  React-batching bug for two rounds because the visual wasn't
  showing. The actual cause was that the grip's parallel pointer
  handlers were intercepting every touch, so the row's hook never
  saw a pointerdown. Hardcoding the styled state confirmed the CSS
  was fine, which then pointed the finger at the JS path, which
  pointed at the parallel handlers.
- **iOS PWA standalone needs `env(safe-area-inset-*)` padding.**
  Browser-tab mode hides this entirely; you only see the broken
  layout once the app is installed to the home screen. Add the
  padding even if you're not testing standalone yet — it's a
  no-op everywhere else.

## What we noticed but didn't fix

- **Right-click menu on slow long-press in some Chrome configs.** The
  `onContextMenu` handler suppresses the React-bubbled event, but a
  fraction of holds still seem to trigger the system menu before the
  React handler runs. Possibly a per-platform race; not reproducible
  reliably. Punted.
- **Drag-to-create on the day column on touch.** Still off. The
  3-day calendar gives more room but distinguishing it from vertical
  scroll without conflicting with block-tap is still non-obvious.
- **Tablet middle width (700–1000 px).** Same awkward range as
  before — rail hidden, 7-day calendar, no real design for the
  band. Decisions either way require user research we don't have.
- **Block move/resize on phone widths.** The 100 px-wide day column
  makes cross-day drags fiddly on touch — single-finger tremor
  registers as cross-column intent. No fix yet; might want a
  per-column drag-confirm threshold.
- **Body scroll lock when the slide-over sidebar is open.** Still
  not implemented. Low priority since the menu auto-closes on
  selection.
- **Calendar long-press not yet on `useLongPress`.** Time blocks
  and rail tasks still use bespoke long-press code from sprint 18
  rounds 1–2. Migrating them to the hook is a small, mechanical
  refactor — left for the next time someone touches that file.
