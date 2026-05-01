# Sprint 11 — In-browser playground + UI polish

**Status:** shipped
**Date:** 2026-05-01

## Goal

Two unrelated tracks landed together because they were small enough to share
a sprint:

1. **Playground mode.** A "Try as Maya in your browser" path on the login
   screen that drops the user into a fully populated workspace with no
   account, no backend, no network. The product story is "let people poke
   at the app before they sign in"; the architectural story is "prove the
   store can run the whole app against an in-memory seed."
2. **A typography + iconography pass** sweeping the parts of the UI that
   read as "scaffold" rather than "polished" — sidebar icons, font sizes,
   login mark, seeded project icons, the inbox row composition, a copy-as-
   markdown affordance on the task modal.

## Playground mode

### Topology

The playground is **the same store, the same components, the same persist
layer** — just with the network short-circuited and a JS-baked seed fed in
at startup. There is no parallel "playground store" or shadow component
tree. A single `playgroundMode: boolean` field on the store gates every
network-touching action.

```
       Login screen
         │
         │  click "Try as Maya in your browser"
         ▼
   markPlayground()  ──┐  localStorage["fira:playground"] = "1"
                       │
   buildPlaygroundSeed()
                       │  hardcoded users/projects/.../blocks
                       ▼
   set({ ...seed, playgroundMode: true })   ─── normal store, normal UI
                       │
                       │  zustand persist saves snapshot to localStorage
                       ▼
       reload  →  hydrate() sees flag → rehydrate from snapshot
```

### What landed

- **[`web/src/playground/seed.ts`](../../web/src/playground/seed.ts)** — TS
  port of a trimmed `api/src/seed.rs`. Same characters (Maya/Anna/Bob/Jin),
  same projects (Atlas/Relay/Helix), 9 tasks across now/later/done, 13
  time blocks anchored to the local week's Monday, 6 GCal events. IDs
  minted with `crypto.randomUUID()` at first-enter and frozen by the
  persist layer — we don't need cross-session-stable IDs because the
  localStorage snapshot is the source of truth from then on.
- **[`web/src/playground/index.ts`](../../web/src/playground/index.ts)** —
  `isPlayground()` / `markPlayground()` / `clearPlayground()` over a tiny
  localStorage flag. Re-exports `buildPlaygroundSeed` so callers have one
  module to import from.
- **[`web/src/store/index.ts`](../../web/src/store/index.ts)** — added the
  `playgroundMode` field (persisted), `enterPlayground()` action,
  short-circuits in `syncOutbox` / `pollChanges`, and per-method playground
  branches in the REST helpers (`addProject`, `updateProject`,
  `setProjectMembers`, the workspace mutators) so a click in playground
  builds the result locally and merges it into state instead of going to
  the network. `loadAllUsers` / `loadWorkspaceUsers` no-op (the user roster
  is whatever the seed shipped).
- **[`web/src/App.tsx`](../../web/src/App.tsx)** — WS nudge socket gated on
  `!playgroundMode` so the reconnect loop doesn't spin against a server
  that isn't there.
- **[`web/src/components/Login.tsx`](../../web/src/components/Login.tsx)** —
  "Try as Maya in your browser" button styled like the existing dev-login
  affordance (dashed outline, transparent), plus a hint line below.

### Decisions worth remembering

- **No shadow components, no parallel store.** The whole point of the
  feature is that playground is "the real app, just with the network
  pulled out." If we had built a separate `<PlaygroundApp>` or a
  `playgroundStore`, every product change would need to be done twice.
  By adding one boolean and a handful of `if (playgroundMode)` short-
  circuits, new features automatically work in playground unless they
  introduce a *new* network call we forgot to gate.
- **`hydrate()` re-derives `inboxFilter` from the cached projects on
  rehydrate.** First-cut bug: `inboxFilter` is intentionally not in the
  persist `partialize` (it's UI state), so on reload after entering
  playground, `project_id` would be `null` and the inbox said "Pick a
  project from the sidebar" until the user clicked one. Fix: when the
  playground rehydrate branch fires, derive `inboxFilter.project_id`
  from `cached.projects[0].id`. Same trap likely exists for the
  offline-cache rehydrate of real auth — out of scope here, noted for
  a future fix.
- **Seed has its own ID space, baked at runtime.** Considered
  deterministic UUIDs (UUID-v5 per slug, mirroring `seed.rs`) for nicer
  debugging across visitors. Decided against: needs a hash library or
  async SubtleCrypto, and persist already pins the IDs at first-enter
  for the lifetime of the snapshot. `crypto.randomUUID()` per slug is
  one line, no deps.
- **Logout drops the playground flag.** Without that, "exiting"
  playground (which uses the same Logout chrome — there's no real
  session to invalidate) would re-enter playground on the next paint
  because the flag was still set.
- **Decided NOT to ship a banner.** First cut had a cyan strip across
  the top reading "Playground · changes saved only in this browser ·
  Exit". The user's call: the workspace is named "Playground" in the
  topbar workspace switcher, which is clear enough; the strip read as
  noise in steady state.
- **Why not a server-backed ephemeral account.** Shorter route, no
  duplicated seed, but: real DB cost per visitor, abuse surface,
  per-visitor GC. Playground keeps prod free of throwaway accounts and
  costs nothing per visitor. The duplication of the seed file is a real
  but bounded cost (one TS file mirroring one Rust file; both are mostly
  data, not logic).

### What we noticed but didn't fix

- **Sub-features that aren't represented in the seed** (epics list in
  task modal, sprint membership across multiple sprints, etc.) work but
  feel sparse. The seed has one active sprint per project; that's
  enough for the calendar to look populated but not enough to exercise
  the multi-sprint picker. Noted; expand if real users wander there.
- **No "Reset playground" button.** Currently the only escape is
  "Logout" (which drops the snapshot via the existing logout flow).
  A reset that *keeps* the user in playground but re-seeds would need
  a separate action; deferred.
- **Drift risk.** When the backend seed grows a new fixture project or
  task kind, the playground seed silently doesn't. A drift-detector
  test is overkill for now; the duplication is tolerable as long as the
  feature surface settles.

## UI polish pass

A scattershot of small fixes that came up while testing the playground.
Each is a one-or-two-line touch but together they shifted the app from
"functional but rough" to "I'd ship this to a stranger."

### Typography

- **Global font scale knob.** Added `--fs-scale: 1.15` in
  [`globals.css`](../../web/src/styles/globals.css) and rewrote every
  `--fs-*` token plus every hardcoded `font-size: NNpx` declaration in
  the three CSS files and every inline `fontSize: NN` in the .tsx files
  to be `calc(NNpx * var(--fs-scale))`. Single knob to dial readability
  up or back down to 1.0 without per-component edits. The `font-size: 0`
  literal in `inbox.css` (icon-only button whitespace collapse) is the
  only literal still in the file, by design.
- **Login wordmark refit.** Was `Instrument Serif 44px / 400`, which
  looked like an italic sample sitting next to a sans-serif marketing
  page. Replaced with `var(--font-sans) 32px / 600` so "Fira" reads as
  the same family as the rest of the UI.
- **"Continue with Google" weight.** Dropped 500 → 400 — at 500 the
  button looked subtly off-balance against the editorial-weight body
  copy. Plain weight + a 1px hairline outline is the resting state;
  hover bumps the background.
- **Description body shrunk.** `.desc-md` was at `--fs-md` and competed
  visually with the mono-uppercase tracked-out "Description" label
  above it (the label is smaller in px but heavier in optical mass).
  Dropped to `--fs-sm` so the body sits *under* the label rather than
  alongside it.
- **Member name weight.** `.np-member-name` was `font-weight: 500`,
  reading as bold next to a quiet role tag. Dropped to 400 so the row
  presents as plain text + chip rather than label + chip.

### Iconography

- **Calendar / Inbox sidebar icons** swapped from inline SVG to Lucide
  `CalendarDays` and `Inbox` at `size 16 / strokeWidth 1.75`. Matches
  the weight of the existing `Settings` icon.
- **Brand mark size** in [`Sidebar.tsx`](../../web/src/components/Sidebar.tsx)
  fixed. Setting `<BrandMark size={N}>` did nothing because
  `.sidebar .brand` had `width: 32px; height: 32px;` overriding the SVG.
  Resized CSS + prop together to 22px so the F glyph sits at the same
  visual mass as the 14px nav glyphs.
- **Seed project icons** in [`api/src/seed.rs`](../../api/src/seed.rs)
  switched from unicode glyphs (`◆ ▲ ◇`, which fell through to the text
  fallback in [`ProjectIcon.tsx`](../../web/src/components/ProjectIcon.tsx))
  to names from the `PROJECT_ICONS` registry: `Compass` (Atlas/infra),
  `Zap` (Relay/sync engine), `Sparkles` (Helix/R&D). Now the seeded
  projects use the same icon set the picker offers, so users can
  re-select them.

### Inbox row composition

- **`external_id` placement.** Started before the title, which created a
  laddered look (mono "ATL-412" in front of every variable-length sans
  title). Moved to the right `.task-trail`, then user feedback said the
  trail was too crammed; final landing is **after the title inline**,
  with a 6px left margin, mono and dimmed via `--ink-4`.
- **Empty subtasks gap removed.** The `.subtasks` wrapper was rendering
  even when a task had zero subtasks, leaving stray vertical margin
  between rows. Now gated on `task.subtasks.length > 0`.
- **Inline "Add subtask" affordance removed from inbox rows** in
  [`InboxView.tsx`](../../web/src/components/InboxView.tsx). Subtasks
  still render and tick; new subtasks now require opening the task
  modal. Inbox rows were getting noisy with adds inline; the modal is
  the right place for the editing affordance.

### Task modal

- **Copy-as-markdown affordance.** Lucide `Copy` icon docked at the
  right edge of the "Description" h5 row. Builds `# title` + description
  + `## Subtasks` checklist (`- [x] done` / `- [ ] open`) and writes via
  `navigator.clipboard.writeText`. Click flips to a green `Check` for
  1.5s then reverts. Used for pasting tasks into Notion / Jira / Linear
  with their formatting intact.
  - Iterated three times on visual weight: started at 70% opacity which
    read as faint, then full-opacity at `--ink-4` which still read as
    faint, finally `--ink-2` which is clearly visible without grabbing
    attention. Lesson: "ghost button" affordances need higher ink than
    intuition suggests when sitting next to mono-tracked-out labels.

## Decisions worth remembering (cross-cutting)

- **One readability knob.** When a designer or user wants "make
  everything bigger," the answer is editing one variable, not a
  per-component PR. The cost: one CSS calc indirection per font-size
  declaration. Worth it.
- **CSS regex sweeps for tokens.** Used `sed -E` across all `.tsx` and
  `.css` files to wrap `font-size: NNpx` and `fontSize: NN` in `calc()`
  and the scale variable. Faster than reviewing 60+ sites by hand;
  caught the "missed inbox.css and calendar.css" bug on the second pass
  (initial sweep was scoped to `globals.css` only, which is why the
  user noticed assignee/subtask text not scaling).
- **"Almost invisible" is rarely what looks right.** When in doubt on
  ghost affordances, default to `--ink-2` (clearly visible) and let the
  user ask for fainter — it's easier to dial down than to coax a "where
  is it?" complaint into a fix.

## What we noticed but didn't fix

- **`fontSize: 11`-shaped literals in components were a one-time sweep.**
  Future contributors will reintroduce them by reflex; nothing in CI
  flags them. Could add a lint rule, but the cost-benefit on a
  three-CSS-file project doesn't justify it yet.
- **Description vs label optical balance** is fixed for now but the real
  question is whether `modalH5` (mono uppercase tracked-out) is the
  right label style at all. Sans-serif `font-weight: 600` would carry
  less optical mass and not require shrinking the body. Defer.
- **Seed drift between Rust and TS** mentioned above.
