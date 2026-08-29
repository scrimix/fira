# Sprint 29 — Monthly dashboard + goals

**Status:** reviewed, in progress
**Date:** 2026-08-29

## Goal

A third top-level surface next to Calendar and List: a **month view** that
answers two questions the week grid can't —

1. *Where did my hours actually go this month?* (distribution by project /
   tag / workspace, planned vs. done, day-by-day rhythm)
2. *Am I keeping my commitments?* — **goals**: a named filter over
   tasks/blocks with a daily or weekly target, rendered as a block grid.

> Naming: the tracked commitment is a **goal** (the brief already talks
> about "weekly goals and daily goals"). Its `target_min` is its
> **target**; a day/week that clears the target is **met**. Avoid the
> word "goal" for the target amount to keep the entity name unambiguous.

Scope held for the whole sprint: **personal stats only**. No team
roll-ups, no per-person picker, no "how did the team spend August". The
dashboard always shows *your* blocks (`activePersonId` is ignored — it's
always `meId`).

## The unit is still the time block

Nothing new in the core model. A time block is `(task_id, user_id,
start_at, end_at, state)`. The dashboard is pure aggregation over blocks
the client already has:

- `state = 'completed'` → real hours, counts for past days.
- `state = 'planned'` → intent; shown separately, and only counts toward
  "today / rest of month" projections, never toward historical totals.
- Project comes from `block → task → project`; tags from
  `task_tags`; workspace from `project.workspace_id`.
- **Filter to the caller first.** `db::list_blocks_in_scope` returns
  *every* member's blocks in the project scope — it has no `user_id`
  predicate, and the calendar filters by `activePersonId` at render
  time. The aggregator's entry point does `b.user_id === meId` before
  anything else, or a team workspace's dashboard reports the whole
  team's hours as yours.
- `task.spent_min` is **not** counted. `taskCompletedMin` (`time.ts`)
  adds it on top of block minutes, so list totals and dashboard totals
  can disagree for tasks carrying it. Nothing in the UI ever writes
  `spent_min` (it's 0 on create; only seeded/imported rows have a
  value), so the dashboard stays block-pure and we accept the drift.

`/api/bootstrap` already returns **every** block in the active
workspace's project scope, unbounded in time (`list_blocks_in_scope` has
no date filter). So for the active workspace the entire month view is
derivable client-side with zero new endpoints. The only data we don't
already have on the client is *other* workspaces' hours — see
"Cross-workspace" below.

## Navigation & breadcrumb

- Store: `view` union grows to `'calendar' | 'list' | 'dashboard'`.
  New `monthOffset: number` cursor (0 = current month), independent of
  `weekOffset` / `dayOffset` for the same reason those are independent of
  each other — each surface owns its own time cursor. Persisted in
  `partialize` alongside `view`.
- New `dashboardProjectId: UUID | null` — the dashboard's own scope,
  **separate from `listFilter.project_id`**. The sidebar project buttons
  are list-only: they always `setView('list', id)`, and `listFilter`
  never carries a "no project" state (it defaults to the first project
  and only goes null when the workspace has zero projects). The dashboard
  needs a real unscoped state, so it owns its own. Default `null` =
  workspace overview. Not persisted — a session always opens on the
  overview. See section 3 for how it's set/cleared.
- Sidebar: third nav button (lucide `LayoutDashboard` or `CalendarRange`),
  keyboard shortcut `d` (mirrors `g` / `i`). Project buttons stay
  list-only and stay unhighlighted in dashboard view (`showProjectActive`
  already gates on `view === 'list'`).
- `time.ts` gains month helpers next to the week ones:
  `monthStartFor(offset)`, `monthRangeFor(offset)` → `{start, end}` local
  midnights, `fmtMonth(offset)` → `"August 2026"`, `daysInMonthFor`,
  `weekdayGridFor(offset)` → the Mon-anchored 6×7 cell layout (leading /
  trailing days from adjacent months flagged so the grid can dim them).
- **Breadcrumb**: `TopBar` title becomes `fmtMonth(monthOffset)` when
  `view === 'dashboard'`, and grows a second crumb —
  `August 2026 / Atlas` — when `dashboardProjectId` is set. The month
  crumb is a button: clicking it clears `dashboardProjectId` back to the
  workspace overview. (Same clickable-crumb idea as the existing
  `Fira / workspace / title` breadcrumb, just with behaviour on the
  segments.) The dashboard's own toolbar carries the `‹ Today ›` stepper —
  same `week-nav` markup/CSS as the calendar toolbar, just stepping
  months. `Today` resets `monthOffset` to 0 and is lit (`data-active`)
  when already there.
- **The breadcrumb does not exist on mobile.** `TopBar` suppresses the
  title outright when `isMobile`, so the clickable month crumb can't be
  the way out of a project scope on a phone. The dashboard toolbar
  therefore carries a `‹` back button whenever `dashboardProjectId` is
  set — **mandatory, not an alternative to the crumb**. Desktop shows
  both; mobile has only the button.
- Clicking a day cell in any grid → `setView('calendar')` +
  set `weekOffset` (desktop) / `dayOffset` (mobile) so that day is
  in view. One-way jump; no back-stack beyond the existing view toggle.

## Layout (top to bottom)

A single scrolling column, `max-width` like the list doc. Sections:

### 1. Month summary strip

Row of stat tiles (reuse `.totals` styling, scaled up):

- **Done** `Xh` · **Planned** `Yh` · **Total** `X+Y`
- **Active days** `N / 31` (days with ≥1 completed block)
- **Avg / active day** `Xh`
- **vs last month** `+Xh` / `−Xh` (completed only; muted when
  `monthOffset` has no prior data loaded)

### 2. Month heatmap (the block grid)

6×7 calendar grid, one cell per day. Cell fill intensity = completed
hours that day, bucketed (0 / <2h / 2–4h / 4–6h / 6h+) against a
project-neutral ramp of `--accent`. Today ringed. Planned-only future
days get a hatched fill, not a solid one.

- Weekday columns make "no weekends" / "light Fridays" jump out.
- Hover/tap → mini popover: date, done vs planned, top project.
- Click → jump to calendar (above).

This same grid component is reused per-goal in section 4.

### 3. Distribution — drill down by clicking, not a sidebar pick

Scope lives in `dashboardProjectId` (see Navigation). You **enter** a
project scope by clicking its bar / heatmap segment inside the dashboard;
you **leave** it via the breadcrumb month crumb (or a `‹` back button in
the dashboard toolbar). The sidebar is not involved — clicking a project
there is still "take me to that project's list".

**`dashboardProjectId === null` → workspace overview:**

- Horizontal bars, one per project in the active workspace, sorted by
  hours desc, project color, `Xh (NN%)` label. Completed = solid,
  planned = lighter tail on the same bar. **Click a bar → set
  `dashboardProjectId`.**
- Below a divider: **one aggregate bar per other workspace**, by
  workspace title, so a glance shows the work/life split without leaving
  the current workspace. Hours only — no project breakdown, by design;
  that's the whole point of an aggregate bar. Not clickable in v1. See
  "Cross-workspace" for the small server change this needs.
- Toggle chips: **by project** (default) / **by tag** / **by day of
  week**.
- **Tags are project-scoped, not workspace-scoped** (`tags.project_id`,
  migration 0015 — there is no workspace column). So the workspace-level
  "by tag" cut cannot group by `tag_id`: the same `meeting` tag is a
  *distinct row* in every project that uses it. Group by
  `lower(title)` instead, and when two projects disagree on a tag's
  color, take the one from the project with the most hours in the
  bucket so the choice is stable across renders.

**`dashboardProjectId` set → project view:**

- Per-tag bars *within that project*, tag color, untagged blocks in a
  muted "untagged" bucket. This is the "meetings vs. real work" cut the
  brief asks for — it works as soon as meeting-type tasks carry a
  `meeting` tag.
- Secondary: top tasks in the project by hours this month (small list,
  `Xh` each), so a project that's all one runaway task is visible.
- Sections 1 and 2 (summary strip, heatmap) also re-scope to the
  selected project so every number on the page agrees.

### 4. Goals

One card per goal:

```
  Drawing practice           🔥 6-day streak      18 / 31 days met
  [ month block grid: target met = filled, partial = half, miss = empty ]
  target: 1h daily · Helix / #art
```

- The block grid is the same component as section 2, but the fill rule
  is per-goal: `metMinutes(day) / target_min`, clamped, so a day locks
  to full at target and shows partial progress below it.
- Weekly-cadence goals render one cell per *week* (5-6 wide) instead of
  per day, filled by the week's total against the weekly target.
- Streak = consecutive met periods ending today (or yesterday if today
  isn't met yet — don't break a streak before the day's over).
- "Add goal" opens a small modal: name, cadence (`daily` / `weekly`),
  direction (`at least` / `at most`), optional target (`1h30` parsed by
  the existing `parseEstimate`), and a scope picker — project (optional)
  + tag (optional) + specific task (optional), AND-combined. Empty
  target = "any block counts" (frequency goal — the period is met if a
  matching block exists).

### Floors and caps

`direction` is `at_least` (a floor — "1h of drawing a day") or
`at_most` (a cap — "no more than 30m of meetings a day"). Both are worth
having; the cap is how "meetings vs. real work" becomes a commitment
rather than just a chart.

They are **not symmetric**, and the grid has to respect that:

- Met is `total >= target` for a floor, `total <= target` for a cap.
- An empty period *passes* a cap — no meetings is the ideal outcome — so
  a blank day is a success state, not a miss. The fill rule inverts
  accordingly: a floor fills toward the target and locks full at it; a
  cap starts full and the interesting cell state is **overshoot**, which
  gets its own "blown" treatment rather than reading as "very complete".
- "18 / 31 days met" counts days you stayed *under* for a cap.
- Streaks work unchanged — consecutive met periods — but a cap's streak
  is much easier to hold, which is correct.
- `target_min` NULL ("any block counts") is floors-only; "at most, no
  amount" is meaningless. Enforced by `goals_cap_needs_target` in the
  schema and re-checked in `validate_goal` so the client gets a readable
  error rather than a raw constraint violation.

## Goal storage

Goals are user config that must follow the user across devices, so:
server-persisted, through the existing op/outbox path (not a REST
side-channel, not `user_settings` JSON).

```sql
-- 0033_goals.sql
CREATE TABLE goals (
    id           UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    cadence      TEXT NOT NULL DEFAULT 'daily'
                 CHECK (cadence IN ('daily','weekly')),
    direction    TEXT NOT NULL DEFAULT 'at_least'
                 CHECK (direction IN ('at_least','at_most')),
    target_min   INT,                             -- NULL = "any block counts"
    project_id   UUID REFERENCES projects(id) ON DELETE CASCADE,
    tag_id       UUID REFERENCES tags(id)     ON DELETE CASCADE,
    task_id      UUID REFERENCES tasks(id)    ON DELETE CASCADE,
    sort_key     TEXT NOT NULL DEFAULT 'M',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- a cap needs something to cap
    CONSTRAINT goals_cap_needs_target
        CHECK (direction = 'at_least' OR target_min IS NOT NULL)
);
CREATE INDEX goals_ws_user ON goals (workspace_id, user_id);
```

### Personal, but not personal-*workspace*

Goals are strictly personal: the `user_id` column means they are never
shared, never shown to anyone else, and never aggregated across people.
There is no team-level goal, now or later.

That is delivered by `user_id` alone. Confining the *row* to the user's
personal workspace was considered and rejected:

- Every goal worth seeding references team-workspace entities —
  "Daily standup" (`task = t_atlas_standup`), "Deep work on Atlas"
  (`project = p_atlas`), "Research time" (`tag = research`). A
  personal-workspace-only table can't express any of them, and the
  goals section would be empty exactly where most tracked hours live.
- Worse, such a goal would be **unscoreable**. From the personal
  workspace the client's only view of work hours is the `work_calendar`
  overlay — bare blocks with no project or tag attribution (see
  Cross-workspace). "2h/day on Atlas" cannot be scored from there.
  Cross-workspace goals need the `/api/stats/month` endpoint that this
  sprint defers; they are not a cheap scoping decision.

So: **workspace-scoped, keyed also by `user_id`** — one goals set per
workspace, project/tag/task references resolving inside that workspace's
scope. Cross-workspace goals stay in "Out of scope".

Because tags are project-scoped, a goal's `tag_id` already implies a
project, making `project_id + tag_id` partly redundant — that's fine,
the AND still reads naturally and matches the `Helix / #art` label in
the mockup above. The consequence to accept: *"1h drawing, #art,
wherever it lives"* is not expressible in v1. Matching tags by name
instead of id would fix it but invents a second tag-identity model;
deferred, see "Out of scope".

### Ops and the change feed

- `Bootstrap` gains `goals: Vec<Goal>` (filtered to the caller).
- New ops: `goal.create`, `goal.update` (partial patch — name / cadence
  / target_min / scope fields / sort_key), `goal.delete`. Add handlers
  to `applyOpToState` and the server `apply_payload` dispatch.
- **Not** the same delivery shape as `tag.*`. `get_changes` (`ops.rs`)
  fans an op out by *project*: rows with a `project_id` reach everyone
  who can see that project, and rows with `project_id IS NULL` reach
  **every active workspace member**. Either path broadcasts a personal
  goal's name to the whole team. Goals are the first private-to-user
  entity in the op log, so:
  - goal ops leave `out_project_id` as `None`;
  - `get_changes` grows an authorship arm for private kinds —
    `AND (po.kind NOT LIKE 'goal.%' OR po.user_id = $2)`. Write it as a
    general "private op kinds" predicate, not a goals special case; it
    will come up again.
- Note this guard is needed even though personal workspaces are
  single-member in practice: `set_members` refuses to touch an
  `is_personal` workspace, but the invite-create path never checks
  `is_personal`, so single-membership is a UI convention rather than a
  DB invariant — and goals are workspace-scoped regardless.
- Add `CHECK (cadence IN ('daily','weekly'))` to the table; it's free
  and the client relies on the union.
- No goal *history* table — "was the target met on Aug 3" is always
  recomputed from blocks, never stored. Keeps goals definitional and
  lets a redefinition retroactively re-score the grid, which is the
  behaviour you want while still tuning a goal.

## Cross-workspace hours

The brief: when a workspace is open, show its per-project split **and**
the other workspaces as aggregate blocks of hours.

Bars are **per workspace, by workspace title** — hours only, no project
breakdown. That's deliberate: the other workspace's internal structure
is not what this section answers.

- The active workspace's blocks: already in bootstrap.
- Other workspaces: the existing `/api/personal/calendar` and
  `/api/work/calendar` overlay endpoints already return the caller's own
  blocks on the other side of the personal/work split, unbounded in
  time, and `App.tsx` already loads them (`personalBlocks` /
  `workBlocks`) on every workspace switch — not gated on the overlay's
  visibility toggle. The dashboard reuses those arrays.
- **Exactly one of the two arrays is ever populated.** `personal_calendar`
  returns empty when the active workspace *is* the personal one;
  `work_calendar` returns empty when it isn't. So this is never a
  "Personal *and* Work" pair of bars — it's the other side of whichever
  split you're currently on.
- **The server change this needs.** Neither endpoint attributes a block
  to a workspace. `list_blocks_in_work_workspaces_for_user` returns bare
  `TimeBlock` rows, and the `LinkedTask` projection alongside it selects
  only `t.id, t.title, t.status, p.color`. Every non-personal workspace
  therefore collapses into one undifferentiated pile — "Work: 34h", with
  no way to split Atlas Corp from a side project. One bar per workspace
  needs `workspace_id` + `workspace_title` on the tasks projection in
  the `work_calendar` response; the client joins
  `block.task_id → task → workspace`.
  - Put those fields on a **response-local struct, not on `LinkedTask`
    itself** — that struct is shared with the partner-overlay endpoint,
    where adding them would start exposing a link partner's workspace
    names.
  - This is a widening of an existing response, not a new endpoint, and
    leaks nothing: they are the caller's own blocks in workspaces the
    caller is a member of.
- Remaining limitation: the personal side is still a single bar (there
  is only one personal workspace), and a true breakdown across *every*
  workspace in one query still wants the stats endpoint below.

### The stats endpoint we're *not* building yet

`GET /api/stats/month?offset=N` returning pre-grouped buckets
(`by_project`, `by_tag`, `by_workspace`, `by_day`, planned vs completed)
across every workspace the user belongs to, computed with a SQL
`GROUP BY`. This is the right long-term home — it makes month ranges
beyond the loaded window work, gives a true per-workspace breakdown, and
keeps the client light (the stress-test sprint already flagged
"bootstrap ships every block" as a scaling problem). We're deferring it
because everything in v1's scope is derivable from data the client
already holds, and shipping the UI first tells us which cuts people
actually use before we carve them into an API. Cutover is invisible to
the components if the client-side aggregator and the endpoint return the
same shape — build the aggregator to that shape now.

## Seeder

The dashboard needs history to render anything. Current `seed_blocks`
only lays down the current week (days 0-6 from this week's Monday).

- Extend `seed_blocks` to emit **~6 weeks** of blocks: the current week
  as-is, plus five prior weeks. Past weeks are all `state='completed'`
  (the existing "don't derive state from wallclock" rule still holds —
  we're declaring history as completed, not computing it).
- Pattern per past week: 3-5 weekday blocks/day, 1-2h each, weighted to
  mornings, a believable project mix (heavier Atlas, lighter Helix), a
  couple of empty days, no weekend work except the occasional Helix
  block. Enough variance that the heatmap and the day-of-week chart look
  alive.
- Seed **four goals** for Maya, one of each shape, so the goal card has
  to handle all of them on first run: "Daily standup" (daily floor, 30m,
  `task = t_atlas_standup`), "Deep work on Atlas" (daily floor, 2h,
  `project = p_atlas`), "Research time" (weekly floor, 3h,
  `tag = research` on Helix), and "Keep meetings down" (daily **cap**,
  60m, `tag = review` on Atlas). The cap is there to keep the inverted
  fill rule honest — an empty day must read as a pass, not a miss.
- Regenerate the playground fixture with `npm run playground:dump` from
  `web/` (the bare `cargo run --bin dump-bootstrap` writes to stdout and
  wipes the dev DB afterwards, so reseed after). The snapshot freezes
  "now", so the six weeks of history land relative to the frozen anchor
  automatically. `web/src/playground/bootstrap.json` is committed.

## UI plumbing checklist

- `web/src/types.ts`: `Goal`, `Bootstrap.goals`, `view` union.
- `web/src/store/index.ts`: `monthOffset` + `setMonthOffset`,
  `dashboardProjectId` + `setDashboardProject` (also cleared on
  workspace switch, like the other per-workspace caches),
  `view` union + `setView`, `goals` in state / `applyBootstrap` /
  `rehydrate` (goals are server data — they ride `blocks`'s treatment,
  *not* `partialize` UX state), goal CRUD actions, `applyOpToState`
  cases.
- `web/src/store/outbox.ts`: `goal.create` / `goal.update` /
  `goal.delete` op kinds.
- `web/src/time.ts`: month helpers only (`monthStartFor`,
  `monthRangeFor`, `fmtMonth`, `daysInMonthFor`, `weekdayGridFor`,
  `localMidnight`, `weekStartOf`, `todayMidnight`, `weekdayIndexOf`,
  `blockMinutes`) — pure time, no entity knowledge.
- `web/src/stats.ts` (new): the aggregator and the goal scorer. Split out
  of `time.ts` on purpose — it's written to the shape
  `/api/stats/month` will return, so the eventual cutover swaps one
  module rather than editing a formatting file. Exports `monthStats`,
  `topTasks`, `otherWorkspaceBuckets`, `scoreGoal`, `goalStreak`,
  `goalMetCount`.
- `web/src/components/DashboardView.tsx` (new), `MonthGrid.tsx` (new —
  exports `MonthGrid` for daily grids and `WeekStrip` for weekly-cadence
  goals; a separate component rather than a mode flag, since MonthGrid's
  whole geometry assumes 7 columns), `GoalModal.tsx` (new).
- `web/src/components/Sidebar.tsx`: third nav button.
- `web/src/components/TopBar.tsx`: month-aware title.
- `web/src/App.tsx`: render `DashboardView`, `d` shortcut, `GoalModal`.
- `web/src/styles/`: new `dashboard.css`.
- API: `0033_goals.sql`, `models::Goal`, `db::list_goals_for_user`,
  `Bootstrap.goals`, `ops.rs` goal dispatch + the private-kind arm in
  `get_changes`, `links.rs` / `db.rs` workspace attribution on the
  `work_calendar` response, `seed.rs` blocks + goals, `dump_bootstrap`
  regen.

## Notes from building it

Things that only showed up once it rendered:

- **A cap's grid can't share the floor's colors.** In accent blue a full
  cell reads "achieved" and a blank grid reads "failing" — exactly
  inverted for a cap, where an empty day *is* the win. Cap cards ramp in
  amber instead (a consumption color) and escalate to red on overshoot;
  the success signal lives in the card's "28 / 29 days met" and streak,
  which state it plainly. See `.goal-card[data-cap="true"]` in
  dashboard.css.
- **Tag bars show minutes, not percentages.** A block on a task with
  three tags counts in full toward all three — the honest reading of
  "how much time touched #auth" — so tag buckets sum past 100%. A
  "% of total" label next to them invites a meaningless sum, so
  `Bars` takes `showPct` and the tag cut turns it off. Project, weekday
  and workspace cuts are mutually exclusive and keep theirs.
- **Cap goals score every untracked past day as met.** Zero minutes is
  under any allowance, so the seeded cap reads "28 / 29 days met" on
  history that predates the goal. That's the direct consequence of goals
  being definitional and recomputed rather than stored — the same
  property that lets a retuned target re-score its whole grid. A
  `created_at` floor on scoring would fix it; deferred, and the column
  is already on the table if we want it.
- Day numbers flip to `--accent-fg` past ~50% fill (`data-dark` on the
  cell). The first attempt used `mix-blend-mode: luminosity`, which dims
  the label further at exactly the intensity it needs more contrast.
- `.goal-modal` needs `height: auto`. The base `.modal` sets
  `height: min(88vh, 1080px)`, which turns a short form into a
  screen-tall box — the same trap `.np-modal` opts out of.

Verified against ground truth: the aggregator's August numbers (80h30
done, 19h planned, 18 active days, Atlas 48h30 / Helix 19h / Relay 13h)
match a direct SQL `GROUP BY` over the seeded fixture exactly. The
change-feed privacy filter was tested live — Maya's `goal.create`
returns 1 row for Maya and 0 for Bob, a co-member of the same workspace.

## Deliberately out of scope

- Team / multi-person stats, per-person picker.
- The `/api/stats/month` aggregation endpoint (client-derived for v1).
- Cross-workspace goals — and with them, goals scoped to a tag *by
  name* across projects ("#art wherever it lives"). Both want
  `/api/stats/month`.
- Team-level goals, in any form. Not a v1 deferral — a permanent no.
- Goal reminders / notifications.
- Time-of-day histogram, estimate-accuracy analytics — candidate v2 cuts,
  not v1.
- Export / CSV.

## Resolved in review

1. **Third nav view**, not a mode toggle inside the calendar. Confirmed.
2. **Goal scope stays AND-combined** project+tag+task. No OR in v1.
3. **Planned blocks: hatched, today-forward only.** They never count
   toward a historical total.
4. Day-cell click → calendar **does not** lose the dashboard position —
   `monthOffset` lives in the store and is persisted via `partialize`,
   so toggling back lands on the same month. No back-stack needed; the
   original concern was unfounded.
5. **Drill-in stays click-a-bar**, exit via the month crumb on desktop
   and the toolbar `‹` on mobile. Sidebar project buttons remain
   list-only — "click project = go to list" is unchanged.

Settled during the same review, from reading the code:

6. Tags are project-scoped — the workspace-level "by tag" cut groups by
   lowercased title. See section 3.
7. Goals are workspace-scoped with a `user_id`, **not** confined to the
   personal workspace. See "Personal, but not personal-workspace".
8. Goal ops need a private-kind arm in `get_changes` or they broadcast
   to the whole workspace. See "Ops and the change feed".
9. Other-workspace bars are per workspace, which needs workspace
   attribution added to the `work_calendar` response. See
   "Cross-workspace hours".
10. The aggregator must filter blocks to `meId` first; `spent_min` is
    deliberately not counted. See "The unit is still the time block".
11. The breadcrumb doesn't render on mobile, so the toolbar back button
    is mandatory. See "Navigation & breadcrumb".
