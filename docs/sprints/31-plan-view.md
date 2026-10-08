# Sprint 31 — Plan view (project roadmap board)

**Status:** built (scrubber deferred to 32)
**Date:** 2026-10-08

## Goal

A fourth surface. Calendar, List and Dashboard all answer questions
about days and hours; none answers the one above them — **what shape is
this project over the next three months, and is it holding?**

X axis is weeks under month headers. Y axis is tracks. Cards are sprints
spanning a week range, each holding a checklist of real tasks from the
same `tasks` table, so ticking one on the board ticks it in List and
Calendar.

## 1. The model went through three versions before it was right

The first draft made tracks a kind of tag: `tags.kind ∈ {basic, track,
milestone}` with `parent_id`, `starts_on`, `ends_on`. It reused a table
that already had identity, colour, per-project scoping and a picker.

It was wrong, and the objection was one sentence: *many tasks have
multiple tracks at the same time.* `task_tags` is M:N. A task tagged
`auth` **and** `perf` renders in two rows; nothing stops one carrying
both `A2` and `O1`; and the `3/4` counters double-count. Every fix for
that is a validation rule — and a rule that has to be enforced in the
store, in the op handler and in the UI is a rule that will be violated.

What landed instead is three hops, **single-valued at every one**:

```
task ──sprint_id──▶ sprint ──track_id──▶ track ──▶ board row
         (or track_id directly when a task has a track but no sprint)
```

Nothing can render twice, so **no validation rule is needed to prevent
it.** That's the whole argument. Tags are untouched by this sprint — no
`kind` column, no widened unique index, no change to `TagEditor` /
`TagsEditor` / `ListTagFilter`. A task keeps as many tags as it likes;
they're orthogonal to its position on the board. Deleting that phase
also deleted every regression risk to existing tag UX.

`tasks.track_id` keeps a real meaning: a task in a workstream but not
yet scheduled into a sprint — the per-track backlog. The resolution rule
runs at render time so it can never drift:

> a task's track is its *sprint's* track if it has a sprint, else its
> own `track_id`.

No mirrored column, no trigger.

## 2. Rename, don't add

`epics` had sat in `0001_init.sql` since day one — `(id, project_id,
title)`, an index, a `tasks.epic_id` FK, a `Bootstrap.epics` field, an
`Epic` type, a store array, a project-delete cascade, and `moveImpact` /
`move_task` handling. All correct, all wired, all unused by any UI. A
rename inherits the lot:

```sql
ALTER TABLE epics RENAME TO tracks;
ALTER INDEX idx_epics_project RENAME TO idx_tracks_project;
ALTER TABLE tasks RENAME COLUMN epic_id TO track_id;
```

Deliberately *not* keeping the word "epic": `/api/jira/epics` and the
TaskModal epic picker already mean *Jira* epics, fetched live from their
API. Two unrelated "epics" in one codebase is a trap.

**`[starts_on, ends_on)` is end-exclusive**, both week-aligned Mondays.
Colspan is `(ends_on - starts_on)/7` with no `+1` to forget, and a
zero-width sprint is representable only as `ends_on = starts_on`, which
a CHECK rejects — so the degenerate case is invalid rather than the
thing you get by filling in one field. Three CHECKs in total (forward
span, both endpoints `ISODOW = 1`). A `DATE` has no timezone, so the
Monday checks mean the same thing for a client in Auckland and one in
Vancouver — which is exactly why the client formats date keys from local
`Y/M/D` rather than round-tripping through `toISOString()`.

`sprints.dates TEXT` survives untouched (legacy, unwritten). `active`
survives for a different reason: on a board that draws a "now" marker
the running sprint is simply the one the marker sits inside, so the flag
is redundant with the span and the board neither reads nor writes it.
Better an untouched column than a maintained one nothing consults.

## 3. The seeder became an op script

This started as a detour and turned out to be the most valuable thing in
the sprint.

`seed.rs` contradicted the architecture it serves. The system's thesis is
that ops are truth and state is a fold — but the seeder wrote state with
direct `INSERT`s and then `TRUNCATE`d the log. Consequences we kept
tripping over while designing the scrubber: no history to scrub, nothing
to check the scrubber against by hand, and a fixture that *can't* be
consistent with a history it doesn't have.

So: **content becomes a backdated op script; tenancy stays direct.**
That's the same seam production uses (client ops for content, REST
handlers for tenancy), and it's forced anyway — there is no `user.create`
op, because users arrive via OAuth.

```
wipe()             unchanged — still truncates, including the log
seed_tenancy()     direct INSERT: users, sessions, workspaces, projects, members
Fixture::apply()   apply_payload × N, with an explicit backdated applied_at
backdate_fixups()  created_at / finished_at / active — the fields no op writes
```

Four things that had to be right:

- **One transaction, not one per op.** Production isolates ops
  deliberately ("a stale `task_id` in op #3 doesn't poison #1, #2, #4"),
  but a seeder wants all-or-nothing. `apply_payload` already took a
  `&mut Transaction`.
- **Chronological insertion**, so `seq` agrees with `applied_at` as it
  does in production. The projection orders by `seq`; a fixture where
  the two disagree would test something that can't happen. The sort is
  stable, so ops sharing a timestamp keep emission order and a create
  still precedes the tick that follows it.
- **The actor is the task's assignee**, not Maya. `task.create` stamps
  `created_by` from the acting user, so this is what preserved the
  pre-conversion fixture exactly.
- **Backdate in a post-pass, not with a virtual clock.** The tick
  handler hardcodes `finished_at = now()`; teaching production SQL about
  seeding would be backwards.

The fixture **isn't generated, it's declared** — exactly as before. The
seeder already separated fixture data (a table of task structs) from the
writing mechanism (a loop). Only the loop body changed, plus one new
field per row: `created_w`, the week it happened. Rust rather than JSON
because dates must be computed from `week_anchor()`, `id(slug)` already
exists in Rust, and the payloads get type-checked against the op enum —
so adding an op kind breaks the build instead of letting the fixture rot.

Not randomized: `web/src/playground/bootstrap.json` is committed and
regenerated by `pnpm playground:dump`, so a random fixture would churn
that diff on every dump, and `visual-check`'s screenshots would stop
being comparable run to run. `stress_seed.rs` stays direct-INSERT — it
exists to make ~8k tasks fast, and routing that through `apply_payload`
would miss its entire point.

**The acceptance test was sharp and it's what made this safe:**
`cargo run --bin dump-bootstrap` before and after, normalised through
`jq` (dropping `created_at` / `finished_at` / `cursor` and sorting by
id), had to be byte-identical. It was. A fixture rewrite that silently
changes the dev data is the failure mode here, and that catches it
outright.

**One prediction that turned out wrong:** the plan said `tasks.spent_min`
would become 0 everywhere because no op writes it, and warned that dev
dashboard numbers would move. `TaskInput.spent_min` exists and
`task.create` binds it, so `spent_min` round-trips unchanged — the
fixture total is 2210 before and after. No behaviour change, and the
sprint-29 list-vs-dashboard drift is neither fixed nor worsened.

**The payoff reaches past this feature.** Every reseed now exercises
every content op handler, so the seeder doubles as a smoke test of the
op surface — 165 ops across 13 weeks, and a broken handler fails the
reseed instead of lurking.

## 4. The plan ops: four shapes in the codebase, and the obvious one was wrong

The first draft reached for a combined `sprint.update` carrying
`track_id` + title + dates, citing `goal.update`. Reading the code found
**four** distinct op shapes already in use:

| shape | used by | why |
|---|---|---|
| whole entity | `task.create`, `tag.create`, `block.create`, `goal.create`, all via an `*Input` struct | creation needs every field at once |
| whole entity on update | `goal.update` **only** | its fields are all nullable *and* a modal submits the full form, so a patch couldn't tell "leave alone" from "clear" |
| `patch: Partial<T>` | `block.update` **only** | drag/resize changes `start_at`+`end_at` together, and `BlockPatch` happens to have **no nullable fields** — the only reason it gets away with it |
| narrow per-field setter | everything else | nullable scalars are plain `Option<T>`, so explicit-null is unambiguous |

Sprints need a nullable `track_id` ("No track" is a real, reachable
state) **and** are edited by drag rather than a form. So `goal.update`'s
shape would mean reconstructing a whole entity from a drag, and
`block.update`'s would need `Option<Option<Uuid>>` in Rust to tell
absent from null. The fourth shape — `task.set_assignee`'s plain
nullable scalar — is the clean fit and is what the codebase does almost
everywhere. **Eleven ops, no combined patch:**

```
track.create / set_title / set_color / reorder / delete
sprint.create / set_title / set_dates / set_track / delete
task.set_sprint
```

The track family is `tag.*` almost verbatim; `task.set_sprint` is
`task.set_assignee` verbatim. `sprint.set_dates` carries both columns
because a span is one value — move and resize both emit it, and the two
are never independently null.

`track.reorder` authorizes through its WHERE clause
(`... WHERE id = $1 AND project_id = $3`), exactly as `task.reorder`
does. The `project_id` predicate *is* the check: ids inside `ordered`
are never trusted, so a forged list can't touch another project's rows.
There's a test for precisely that.

**Dropped from the first draft:** `sprint.set_active` (redundant with the
span, see §2) and `task.set_track` (assign a task to a track without a
sprint — nice, not load-bearing).

### `#[serde(alias = "epic_id")]` is load-bearing

`processed_ops` is never pruned and must stay replayable forever, so
every `task.create` payload written before migration 0034 still says
`epic_id` on the wire. Without the alias, the version scrubber would
silently null the track link of every task it replays from before this
sprint. One attribute, and there's a unit test pinning it.

## 5. Removal: three different things, and conflating them loses trust

1. **Remove a task from a sprint** — `task.set_sprint(null)`. Row leaves
   the card and the task reappears in the inbox.
   Fully reversible. **This is the only removal the board's UI offers**:
   drag out, or the `×` on the checklist row.
2. **Delete the task** — the existing `task.delete`. **The board does
   not offer it.** Deletion stays in the task modal behind the confirm
   it already has, so the easy gesture on the board is the reversible
   one.
3. **Move to another project** — `move_task` already clears `sprint_id`
   and `track_id`. `moveImpact` already computed and reported both; after
   the rename it reports them by the right name. Nothing new to build.

Deleting a *track* or a *sprint* is non-destructive by construction:
both FKs are `ON DELETE SET NULL` from `0001_init.sql`. A deleted sprint
returns its tasks to the inbox; a deleted track drops its sprints into a
**"No track" row at the foot of the board**. That row is the point: SET
NULL *without* it would be data loss by invisibility, and with it the
state is self-healing — drag the orphans onto a track. Same posture as
everywhere else in Fira (ex-members' tasks stay because "it's history,
not stale data", sprint 19).

**Say this part out loud, because the plan view is the first surface
where it's visible as rewriting the past:** `time_blocks.task_id` is
`ON DELETE CASCADE`, so deleting a task takes its completed blocks with
it. A sprint that read `8/10` last month reads `8/8` after someone tidies
up two tasks, and the retro band — built from exactly those blocks —
loses the work entirely. This is pre-existing Fira behaviour (nothing
here soft-deletes a task; the month dashboard already has it), not
something this sprint introduces. But a roadmap is read as a *record*,
so it belongs in the log rather than being discovered from a number that
moved. The fix is half-paid-for: the op log retains both the
`task.create` payload and the `task.delete`, so sprint 32's projection
resurrects deleted tasks for historical counts.

## 6. The retro band — a reconstructed past, derived not materialized

A brand-new board is empty, which is the usual reason a roadmap feature
is never adopted. So the past is reconstructed: fortnight buckets over
finished work, anchored to **even ISO weeks** so every project in a
workspace shares boundaries and two people never describe the same
fortnight differently.

Per task, the splitter is three branches, best evidence first:

```
completed time blocks?  → span = [first.start_at, last.end_at)
else finished_at?       → point
else created_at?        → point     (pre-0017 rows)
```

Blocks lead for two reasons. They're the only source that yields a
*span* — a sprint needs a week range, and a six-week task that finished
last week shouldn't collapse into one fortnight. And they're immune to
the clumping `finished_at` suffers: it's stamped at the instant of the
status flip, so a Friday tidy-up puts twenty tasks in one minute. It's a
*point*, not a span. Planned blocks are excluded — intent, not record.

**Derived, never materialized.** Materializing ~26 rows a year per
project would pollute the sprint namespace, fake the provenance (rows
created today, dated in W20), and read as unverified history in the
scrubber forever. Instead it's computed at render time and drawn **muted,
dashed and read-only as its own full-width row outside every track** —
which is also the honest signal that it's a record, not a plan. That
distinction is the product's whole thesis; the two must not share a
visual slot.

### The band as first shipped was incoherent, and the bug was one clause

It bucketed every finished task. Every one — including the finished
tasks sitting in sprint cards one row above. So the same task rendered
twice on the same board: once as a planned, ticked checklist row, and
again as a reconstructed record of itself. That is precisely the
double-render the single-valued `task.sprint_id` model was chosen to
make impossible, and the band walked straight into it.

Worse, it left the band with **no rule by which anything ever left it**.
Asked what the band was for, the honest answer was "all your done work,
again, dimmer". Asked when it regenerated, the honest answer was "it
doesn't, it's derived" — true, and useless, because the question behind
it was really *what is this and what do I do with it*.

One clause fixes all of it:

```ts
t.status === 'done' && t.sprint_id === null
```

Now the band means something you can say in a sentence: **finished work
that was never planned.** Which gives it, for free:

- **A self-clearing rule.** Plan a row and it leaves. That is also the
  answer to "I can't edit them": you can't edit a record — you turn it
  into a plan. Two gestures do that, and both are just `task.set_sprint`
  underneath. Drag a row onto a card, or **Promote** the bucket, which
  creates a real sprint over the computed span and moves every member
  into it. Promote lands on "No track" rather than guessing one, and is
  withheld for a bucket clipped by the window, where the visible part
  isn't the span.
- **An answer to "what if we keep working without sprints?"** The band
  fills up. It's recomputed every render from current tasks and blocks,
  so work finished today appears in today's fortnight with nothing
  pressed and nothing regenerated.
- **A name that matches its switch.** The row is titled **Past**,
  because the toolbar toggle that shows it says Past. It had been
  "Finished work" under a button called "Past", which is two names for
  one thing.

The fix exposed a gap in the fixture, which is the useful part: **the
seeded board had zero unplanned finished tasks**, so the corrected band
was empty across the whole dev database and in the playground. That was
a true statement about the data and a silent hole in the demo. Five
Atlas tasks now finish across three recent fortnights without ever
entering a sprint — the ordinary case the band exists for, not an edge
one.

`RetroBucket` also gained `startsOn`/`endsOn` as Monday-aligned
end-exclusive date keys, so Promote hands `sprint.create` a span
verbatim instead of redoing the date arithmetic at the call site, and
the schema's three ISODOW/ordering CHECKs pass by construction.

## 7. Where the projection lives: Rust, reversing an earlier call

The first draft put the version projection in `web/src/planHistory.ts`,
citing `stats.ts`. Wrong on two counts. `stats.ts`'s own header says it's
a stand-in *for a future endpoint* — the precedent points at the server.
And decisively: **the client does not have the op log.** It has current
state plus a cursor. Scrubbing needs a server call regardless; the only
question is whether the response is raw ops or something already folded,
and shipping thousands of ops to every client that opens the board, to
recompute what the server could compute once, is the worse half of that.
It also put the highest-risk logic in the one language this repo had no
way to test.

So the split is:

```
live:   store state          ──┐
                               ├─▶ buildPlanSnapshot(PlanInput) ─▶ PlanSnapshot ─▶ PlanView
replay: GET /api/plan/at?t= ──┘    (TS — ONE implementation)
```

- **Projection** (folding the log to a point in time) is Rust, in
  `api/src/plan.rs`. Pure, DB-free, `cargo test`-able.
- **Assembly** (lane packing, badge codes, week indices, clipping) stays
  in `web/src/plan.ts`, with exactly **one** implementation serving both
  modes.

The endpoint will return *projected entities*, not a finished snapshot,
so there's no second assembly implementation in Rust and no
cross-language drift. `project_at` and its 17 tests landed **this**
sprint even though the handler is next: it's the highest-risk code in the
feature, it needs no DB, and having it green before the UI exists is what
makes 32 a UI sprint rather than a debugging sprint.

**`PlanView` renders only `PlanSnapshot`. No component reads
`s.sprints`.** Being strict about that is what makes live and replay
share one render path.

Badge codes (`A1`, `A2`, … `AA1`) are **derived, not stored**: track
letter by `sort_key` order, sprint ordinal within track by
`(starts_on, sort_key, created_at)`. Ordering by `starts_on` first means
dragging a card left renumbers it, which is what a reader expects from a
timeline, and it removes the need for a sprint-reorder gesture entirely.
Decisive for 32: a derived badge is computed *from the projected
snapshot*, so scrubbing to W38 renumbers badges to what they were. They're
numbered before the window clips anything, so scrolling a card out of
view doesn't renumber the ones still on screen.

## 8. Testing — three layers, and the first one is new

No frontend test runner was added; the UI stays script-checked, per the
repo's existing posture. But the scrubbing logic isn't UI logic any
more, and `cargo test` was already there at zero cost.

**Tier A — 17 pure projection tests, no infrastructure.** `project_at`
takes a slice and returns a struct, so the op sequences are hand-written
inline. Covers: a sprint moved twice reads its span at each point; a task
created after T is absent at T; a task deleted after T is **still present
at T with its `task.create` title**; a task created *and* deleted before
T is absent (the deferred case — it must at least not crash); membership
follows the last `set_sprint` ≤ T; a retracked card sits on its old
track at T; `track.delete` orphans children rather than vanishing them;
`applied_at` ties resolve by `seq` **in both input orders**; an unknown
op kind is skipped not fatal; a malformed payload for a *known* kind is
skipped too; a pre-0034 `epic_id` payload still resolves its track; an
op targeting an unknown id is a no-op; an empty log returns empty state.

**Tier B — 9 DB-backed tests via `#[sqlx::test]`.** It turned out to
work out of the box — the `migrate` feature is already there
transitively, so each test gets its own migrated database and there's no
fixture teardown to write. Covers what pure tests can't: each op
persists what it claims; `track.reorder` ignores a forged foreign id;
the SET NULL cascades; cross-project ids are **rejected with a readable
error** rather than silently filtered (three paths); an out-of-scope id
says "not in scope" rather than confirming the row exists; invalid spans
(inverted, zero-width, Tuesday) are rejected *before* the database sees
them and leave the row unchanged; `task.set_sprint` round-trips through
null.

This meant making `apply_payload` `pub` rather than adding a
`_for_test` shim. It's honest — it is the single apply seam, used by
`/ops`, the seeder and the tests, so there's exactly one implementation
of what an op means.

**`scripts/test-migration.sh` — 21 assertions in pure psql.** The
`epics` → `tracks` rename over **populated** data is the riskiest
non-logic item in the sprint, and `seed --drop` only ever exercises a
fresh DB. A rename that drops an FK looks exactly like a success at the
psql prompt. So: scratch DB → apply 0001..0033 → insert a project and a
task with both plan links set → apply 0034 → assert. It checks the FK
through `pg_constraint` (not just the column), the row counts, the
preserved values, the new columns' defaults, that all three CHECKs
actually fire, and that deleting a track or sprint NULLs its children
rather than cascading them away.

**`web/src/plan.selfcheck.ts` — ~60 in-page dev assertions.** The risky
assembly logic is pure, so it checks itself at runtime: imported only
behind `import.meta.env.DEV` so vite tree-shakes it out of production.
Each case is a known wrong-by-default algorithm — `isoWeekNumber` at the
year boundaries that `floor(dayOfYear/7)` gets wrong (2027-01-01 → W53,
2024-12-30 → W01), `fmtDateKey` round-tripping a Monday *as* a Monday
(the `toISOString()` Sunday bug), `weeksBetween` returning an integer
across a DST transition rather than 2.996, `fortnightStartOf` landing on
an even ISO week, `packLanes` against a table of overlap shapes
including nested and separate clusters, `planCode` through `AA1`, the
retro splitter's branch precedence, and `buildPlanSnapshot`'s
sprint's-track-wins rule and window clipping. It throws on failure,
which is what makes `visual-check` (watching `pageerror`) the gate.

**State the weakness plainly:** those assertions run only when someone
opens the app in dev or runs `pnpm visual-check`. That's a discipline
dependency, not CI. `pnpm build` runs `tsc -b`, so typecheck *is*
enforced; the assertions are not. **Anyone touching `time.ts` or
`plan.ts` must run `pnpm visual-check` before merging**, and that
sentence belongs here and in the PR template rather than in someone's
memory.

`visual-check.mjs` now shoots the board in all three theme/style combos
(reached by the `p` shortcut, since the sidebar button is gated out of
production) plus a tight `.plan-rows` crop, and **exits non-zero** if any
`pageerror` or console error fired — previously they scrolled past.

## 9. The seeded timeline

The seeder's plan narrative is hand-written, because it *is* a narrative
— the point of the scrubber is that specific things slipped on specific
weeks, and random churn demonstrates nothing. Twelve weeks for Atlas,
exercising every state the drift overlay will need to render:

| week | event | demonstrates |
|---|---|---|
| W−13/−12 | 7 tracks, 8 sprints created | the baseline board |
| W−10 | tasks joined sprints | a climbing done-count |
| W−8 | `sp_a2`'s dates pushed +2 weeks | **the headline slip** |
| W−7 | a sprint created that won't survive | — |
| W−6 | `sp_a3` moved to another track | the retrack ghost |
| W−6 | a task added to an in-flight sprint | scope creep |
| W−5 | a task created outside TASKS | sets up the next two |
| W−4 | a new sprint | "added since T" |
| W−4 | a task removed from a sprint | membership `−` row |
| W−2 | that counted task deleted outright | **the resurrection case** |
| W−2 | a sprint deleted | tasks return to the inbox |
| W−1 | `sp_a2` slips a second time | cumulative drift, not a one-off |

`pnpm playground:dump` carries all of it into the committed
`bootstrap.json`, so the backend-free playground opens on a populated
board and `visual-check` can shoot it.

Because the fixture *is* the op log, the seeded end state is by
construction exactly what the ops produce — which is what will make
sprint 32's live-vs-replay equivalence assertion meaningful against
seeded data rather than failing on a hand-built inconsistency between
state and history.

## 10. Recorded risk: op shapes are permanent once released

`processed_ops` is never pruned and must stay replayable forever, so an
op kind that reaches a real user's log is effectively permanent — if
`sprint.set_dates` turns out to be the wrong intent shape, those rows
persist and `project_at` has to keep understanding them. Components, CSS
and even the schema can be revised by a later migration; shipped ops
can't. This sprint commits eleven of them against a UX that was revised
three times while being designed. That's a real bet and it's recorded
here as one.

What makes it acceptable is that the constraint binds at *production
release*, not at merge:

- **The sidebar entry is gated behind `import.meta.env.DEV`.** While the
  door is dev-only, every op shape stays revisable at the cost of one
  `TRUNCATE processed_ops` and a reseed. The `p` shortcut and the view
  itself stay live.
- **The op set is already minimal** — eleven, after cutting
  `sprint.set_active` and `task.set_track`.
- **Unknown kinds are skipped, not fatal**, in both `apply_payload` and
  `project_at`, so a retired kind degrades rather than breaking replay.
  There are tests for both.
- **Each op maps to one store action and one handler**, so reshaping one
  is a contained three-file change rather than a cascade.

**Revisit this before the release that exposes the view to users** —
that's the last moment the shapes are free.

## 11. Also fixed

- **`loadLastView` silently discarded `'dashboard'`.** The view union was
  hand-written in four places and the fourth was a runtime whitelist that
  never got updated, so anyone whose last surface was the dashboard
  landed on the calendar. Fixed at the cause: `VIEWS` / `ViewName` in
  `types.ts`, with the type *derived from the array* and the whitelist
  validating against it. Whitelist and type can no longer drift, and
  every future view inherits it. Thirty minutes, done before anything
  else.
- **A stray `}` in `list.css`** (line 460, pre-existing) was making every
  production build emit a CSS syntax warning.
- **`idx_processed_ops_project_applied`** added now rather than later.
  `idx_processed_ops_seq_project` can't serve the scrubber's
  `project_id = $1 AND applied_at <= $2 ORDER BY seq` — its leading
  column is `seq`. Adding an index to the largest append-only table in
  the schema is cheap today and a different kind of change once it's
  large, so it lands with the migration that creates the need.

## 11b. What only showed up once it rendered

Chromium wasn't installed in the devcontainer at first, so the first
pass of this board was verified by typecheck, build and headless
assertions alone. Those all passed. Four things were still wrong, and
every one of them needed a picture or a live DOM query:

- **`position: relative` silently killed `position: sticky`.** The track
  names were supposed to stay pinned while the week axis scrolls. Adding
  `position: relative` to the same rule — to anchor the row's hover
  buttons — overrode the `sticky` above it, and the whole head column
  scrolled off. Nothing catches this but looking: it typechecks, it
  builds, and it only misbehaves once there's enough board to scroll.
  `sticky` is already a positioned ancestor, so the line was never
  needed. There's a comment on the rule now saying so.
- **The axis pad has to be sticky too.** Once the row head stuck and the
  axis's leading spacer didn't, the week labels drifted out of register
  with the columns they name — W37 sitting over W39's column. Verified
  with a live `getBoundingClientRect` comparison rather than by eye:
  labels and cells now share x at 20/124/228/332.
- **The default window opened on empty space.** `-2/+12` from today is a
  defensible plan-view default in the abstract, and in practice it meant
  the board opened on weeks where nothing had been planned yet. Now
  `-6/+16`, and it scrolls to put "now" two columns in from the left on
  first open (once per project; after that the scroll position is the
  user's).
- **The inbox predicate was wrong, and the plan was wrong about why.**
  The plan said an unplaced task that gets ticked "leaves the inbox
  (which excludes `section === 'done'`)". It doesn't: `task.tick`
  changes `status` and never `section` — `setTaskSection`'s own comment
  says Now "is also where recently-finished work lives until archived".
  So a ticked, unplaced task sat in the Unplanned rail as work still to
  be planned. The filter needs both predicates. Caught by driving the
  real gestures in a browser and watching the inbox count go the wrong
  way; there's now a self-check case for it, and the behaviour is the
  asymmetry you want — removing a *done* task from a card sends it to
  the retro band, removing an *open* one returns it to the rail.

Then a second round, from actually trying to use it:

- **Move and resize did nothing at all.** The card was an HTML5 drag
  source (for changing track) *and* a pointer-drag handle (for the week
  span). Instrumenting the event stream showed `dragstart` firing on the
  first `pointermove` and `pointermove`/`pointerup` never arriving
  again — the native drag swallows the pointer stream, every time. Two
  drag systems cannot share one element. Fixed by collapsing to **one
  pointer gesture carrying both axes**, which is what the calendar
  already does for blocks (time and day together) and is a better mental
  model anyway. HTML5 DnD now appears only where the card is the
  *target*, never the source.
- **The card title swallowed `pointerdown`.** Once the above was fixed,
  move still failed: the title button called `stopPropagation` so that
  clicking it would open the rename editor. The title fills most of the
  header, which is the only place anybody grabs a card. Replaced with
  the house pattern — let the drag start, and suppress the trailing
  click if the pointer actually moved.
- **Empty track rows had zero-height cells.** `grid-template-rows:
  repeat(N, auto)` collapses to 0 with no cards in it, so the week cells
  of an empty track were 0px tall and could not be clicked or swept —
  exactly the row where you most want to add a sprint. `minmax()` fixes
  it.
- **The window controls were nonsense.** `‹` and `›` *grew* the window
  rather than moving it, and sat next to a lone `−` meaning "drop the
  last week". Nobody reads a chevron that way. Panning and sizing are
  now separate clusters: `‹ now ›` moves the window, `− 16w +` resizes
  it.
- **`+ Sprint` was invisible, then in the wrong place.** First it was
  hidden behind row hover, so the board looked like it had no way to
  create anything; then it was a per-row button, which is not where
  anyone looks. It's now a toolbar button that *arms* the grid — click
  it, the board lights up and the cursor becomes a crosshair, then drag
  across the weeks you want. Creating a card by drawing its span is the
  gesture a timeline affords.
- **The cyan accent was wrong for this surface.** `--accent` /
  `--accent-soft` / `--accent-line` were doing the "now" marker, the
  running sprint's ring and every drop highlight. On a board whose
  entire visual language is track colour against paper, a cyan ring
  reads as a different app. All replaced with ink/rule neutrals, except
  the active card, which now rings in **its own track's colour** — which
  is what it should have been saying all along.

Also: the `visual-check` exit gate was initially wired to *console*
errors, which failed the sweep on the pre-login `/api/me` 401 the login
screen legitimately produces. It gates on `pageerror` only now — the
signal, not the noise — and that was confirmed end-to-end by mutating
an assertion and watching the sweep go red.

The lesson is cheap to state and worth stating: **typecheck, build and
pure-logic assertions can all be green while the thing is unusable.**
Most of the above is CSS, defaults, or two event systems fighting —
exactly the categories none of those gates covers. Two of them (the
`dragstart` hijack, the `position: relative` override) were only
findable by instrumenting a live page. Install the browser, drive the
gestures, and look at the thing.

## 11c. The second pass: what using it for ten minutes found

Everything in 11b came from driving gestures that didn't work.
Everything here came from someone *looking* at the result, which turns
out to catch a different class of thing entirely. Grouped by what was
actually wrong, not by the order they arrived.

### The board was showing numbers instead of saying things

- **`3/4` on every card.** "I can read and count myself" is the whole
  critique and it's right: the checklist is directly above the counter,
  with ticks on it. The counter restated it in digits and took header
  width from the title to do so. Gone. Completeness is now **dullness** —
  an all-done card dims, the same treatment a done row gets in the list
  and a completed block gets on the calendar. No new visual language for
  a fact the app already knows how to express.
- **A track-coloured ring around the "running" sprint.** Read as a
  status badge; nobody guessed it meant "today is inside this span".
  Deleted outright. A card's *position on the week axis* says when it
  runs, next to a now marker on that same axis. Ringing it as well is
  saying the same thing in a second language.
- **The now marker said it too quietly.** `inset 2px 0 0 var(--ink-3)`
  on a week label, among twenty-six identical labels. It is now the
  calendar's current-day marker copied token for token — `--accent-soft`
  fill, 2px `--accent` underscore, `--accent` text, 1px `--accent` line
  down the column. Worth being precise about why this is not a
  contradiction of "remove the blue accents": that instruction was about
  cards, where `--accent` was decorating objects whose own language is
  track colour against paper. "Now" is the one fact on this board that
  the calendar also states, and the two surfaces disagreeing about where
  it is would be indefensible.

### Controls that fought the thing they were attached to

- **Inline title editing on a card broke dragging**, and there was no
  arrangement that fixed it. The header is the move handle; the title
  fills most of the header. Either the title swallows `pointerdown` —
  and the card becomes undraggable from the only place anyone grabs it,
  which is what 11b was about — or it doesn't, and every short drag
  lands in an edit box. The `didDrag` click-threshold ref papered over
  the second case and is now deleted along with it. Rename is a **pencil
  button**. The title is plain text that inherits `cursor: grab`.
- **Two different crosses meant two different things.** The card's `×`
  destroyed a sprint with no confirmation; a checklist row's `×` merely
  cleared `sprint_id`. Now: the card gets a **trash** icon behind
  `ConfirmDelete` ("Its 5 tasks lose their sprint and return to the
  rail. No task is deleted."), and the row gets a **left arrow** toward
  the rail it's going back to. A cross means destroy everywhere else in
  this app, and destroying a task is the one thing the board
  deliberately doesn't offer.
- **Resizing selected text.** The native selection begins at
  `pointerdown`, so the grip now `preventDefault`s there — free, because
  a grip has no click. The header can't, so the board sets
  `user-select: none` for the duration of a drag instead.
- **Reordering a checklist didn't exist.** It does now, and it drives
  the list's own section-scoped `reorderTasks` rather than inventing a
  board-local order, so the two surfaces can't disagree. Clicking a row
  opens the task modal, as a task row does everywhere else.

  This surfaced a hazard worth recording. Ordering is `sort_key`, which
  is section-scoped, so honouring "put this above that" across a section
  boundary means moving the task's *section* — which is exactly what the
  list's own drag does. Across the **done** boundary that silently
  un-archives a finished task. Fixed by making finished rows sink to the
  foot of the card and take no part in ordering. That also repaired an
  older inconsistency: `task.tick` sets `status` and leaves `section`
  alone, so a ticked task still in Now was sorting to the *top* of its
  card while rendering struck through.

### Chrome that didn't survive being looked at

- **Five controls, four heights, two idioms.** 24px segmented pills next
  to 26px standalone chips. Every toolbar control is now a segment of a
  `week-nav` pill at one height off `--control-h`, and the three view
  switches became one segmented group with a filled on-state and
  `aria-pressed` — they're a set, and they're not exclusive.
- **A horizontal line that slid around during scroll.** `.plan-axis` was
  a plain block, so it took the scroll container's *visible* width
  (989px) while its grid children overflowed to the board's full width
  (1844px). Its background and bottom rule therefore stopped partway
  across and stayed pinned to the viewport. `.plan-rows` already carried
  `width: max-content; min-width: 100%` for this exact reason; the axis
  needed it too. Measured rather than guessed — the numbers above are
  from `scrollWidth` vs `getBoundingClientRect()` in the live page.
- **The rail header and the board axis ended on different lines.** Both
  close with a rule and they sit side by side, so two pixels read as a
  break in the chrome. One axis row is now `--plan-axis-row-h`, declared
  rather than left to fall out of font metrics, and the rail header is
  exactly twice that plus the axis's own 1px rule.
- **Row-head buttons sat on top of the track name**, which was elided to
  "Auth v2 (refresh + S" to make room for them. The head is 44px tall
  and holds one short string; the vertical space was free. Buttons moved
  above the title with their height reserved (so hover doesn't shunt
  anything), and the title wraps instead of eliding.
- **The crumb read "Aug 31 – Sep 6 – Feb 22 – 28"** — two *week* labels
  concatenated. `fmtWeekRange` now delegates to a general
  `fmtDateRange`, and `fmtWeekSpan` composes the board's window from it,
  keeping the trailing-day arithmetic on `addDaysLocal` where a raw
  `+ 6 * 86400000` would name the wrong date across a spring-forward.

### The rail: stop building a second one

The first version was a bare `<ul>` of titles. The instruction — make it
like the calendar's rail — was the right call for a reason worth naming:
a task waiting to be scheduled and a task waiting to be planned are the
**same object answering the same question**. So the rail now *is*
`.cal-rail` and the `.rail-*` classes, reused rather than imitated.

Two substitutions, because the calendar groups by project and filters by
project and the board is already scoped to one project:

- groups are **sections**, rendered with the list's own `.section-head`,
  always present and always counted even at zero (a section that
  vanishes when it empties makes the rail's shape jump as you plan, and
  "is there anything in Now?" is a question the rail should answer
  rather than leave to an absence);
- the filter is **tags**, and specifically the list's `ListTagFilter`,
  extracted to `TagFilter.tsx` and now imported by both. The hand-rolled
  chip panel it replaced was a worse version of a control that already
  existed twenty lines away in another file — the correction was
  "use the component from list", and the only defensible response is to
  go and share it.

Headings sit flush with the rail's left gutter and the rows indent under
them. They had been the other way round: the caret led each heading,
pushing the words inward past the left edge of the very rows they
introduced.

### Then the reuse went one step too far, and had to come back

Reusing `.rail-task` for the rows was the same instinct applied where it
didn't hold. A calendar rail row answers *how big is this and how much
is left* — it carries an estimate, an external id and a progress fill,
across two lines, in 44px. A plan board asks only **where does this
go**. So the row was 44px of mostly-irrelevant metadata sitting a few
hundred pixels from an 18px `--fs-xs` checklist row holding the same
kind of object. One screen, two designs, and the mismatch was the first
thing anyone noticed.

The rows are now board-native: one line, the title, nothing else. The
estimate and external id are gone from the render — though both are
still carried on `PlanTask`, because the filter box matches on
`external_id` and the tag chips need `tag_ids`. Searching for `ATL-602`
still works; it just doesn't cost every row a second line to say so.

The fix that mattered more than the markup was making the rhythm
explicit. `--plan-task-h` and `--plan-task-fs` are now **one task
line**, and every place a task line appears uses them: a card's
checklist, its add-task row, the Past band's rows, and the rail. Before
this they were four independent sets of paddings and font sizes that
had never been compared because they live in different components and
nothing forces them into the same frame — except the screen, which does
it constantly. `--plan-lane-h` derives from the same token, so an empty
track's sweepable band is exactly one task line plus padding instead of
a magic 30px.

The section rules went too. `.section-head`'s trailing `.rule` works in
the list because its sections are page-wide and the line reads as an
underline; in a 220px column it reads as a line *closing* the group
above it, so each section looked like a title, some subtasks, then an
end marker. Blocks are separated by whitespace instead.

Two sizing faults rode in with that token and are worth separating,
because they have the same cause:

- **`--density` is for padding, not for rows.** Its own definition says
  "padding / gaps that are allowed to breathe", and modern sets it to
  1.45 for "~30% more breathing room". Written as
  `calc(22px * var(--density))` the token breathed the *line box* too,
  so a modern task row came out at 31.9px against classic's 22px —
  a size and a half, not 30%. Both row tokens are now line box plus
  density-scaled padding, which puts modern at 24.4px: visibly roomier,
  still a task row.
- **Panel widths are not a density concern at all.** `--plan-rail-w`
  and `--plan-head-w` were `calc(220px * …)` and `calc(180px * …)`,
  giving modern a 319px rail and a 261px track column — while the week
  columns, which come from a JS constant, didn't move a pixel. The
  board's proportions came apart at exactly the width where they matter
  most. They're fixed per style now (220/180, 248/200), which is what
  `--side-w` does (220/248) and what the calendar's 320px rail does.

The axis had the same disease in a third place. Month and week labels
were `--fs-xs * --label-size` — 15.8px in modern, against 13.8px of
task text. The scaffolding was set larger than the thing standing on
it, and the two rows cost 57px of a board whose whole value is how many
weeks fit on screen. Labels are now a flat `10px * var(--fs-scale)`,
below the content they name; week numbers took the mono face and
tabular figures, being codes; the month strip is shorter than the week
row and carries the only strong rule on the axis, since grouping is the
only thing it does. The axis went 57px → 46px in modern, 44px → 42px in
classic, and stopped reading as two headings.

The axis also had vertical rules that began in mid-air: the week
columns' borders started at the month/week row junction with nothing
above them. A rule under the month strip gives them something to start
from, and a month boundary's own rule crosses it and carries on — which
is the hierarchy the strip exists to express.

The toolbar finished the same way. Unifying it on `--control-h`
(§11c) was right about the *idiom* and wrong about the number:
`calc(26px * var(--density))` is 37.7px in modern for a bar of 12.65px
labels. The calendar's own `.cal-toolbar .week-nav-btn` is a flat 22px
in both styles — same control, same bar, already shipped — so the plan
toolbar now inherits it and measures identically to the calendar's:
47px bar, 24px pill in modern. Only the flex layout is overridden,
because these segments carry an icon beside a label where the base rule
centres a single child with `inline-grid`.

A smaller one, reported as "track/sprint buttons have another font than
inbox/tasks": they don't — both are JetBrains Mono at 12.65px, measured.
What differed was the icon metric (`size 11 / strokeWidth 2` against
`12 / 1.75`) and a colour I'd given the add actions to mark them as
verbs rather than state. Two segments in one bar differing in icon
weight and ink is a real inconsistency even when the type is identical;
both are uniform now. Worth measuring before agreeing *or* disagreeing.

The topbar's playground pill was the `--label-size` factor one last
time: `calc(10px * --fs-scale * --label-size)` made "Playground" 25%
larger than the sync chip welded to its own right edge, in modern only.
Dropping the factor outright overcorrected — a sans label reads a notch
smaller than mono at the same nominal size — so it sits at 11px scaled,
which lands level with the mono chip and the avatar beside it. The
lesson is the one running through this whole pass: match these things
*optically*, against what they sit next to, not by making two numbers
equal.

Not folded into one row, and the reason is a constraint worth writing
down: **the rail's header has to close on the same line as the axis**
(§11c), and that header holds a filter box at `--control-h` — 37.7px in
modern. A single-row axis is ~23px, so folding would force either the
misalignment we'd just fixed or moving the filter somewhere else. The
height was never really coming from the row count; it was coming from
the type size, and that is where it went.

And the whitespace between rail and board was a scrollbar that could
never appear: `.rail-body` inherits `scrollbar-gutter: stable` from the
calendar, where it's deliberate — the rail reserves the gutter
unconditionally so its rows keep the head's content edge, and every row
subtracts `--scrollbar-w` to match. The plan rail's rows don't subtract
it and the rail rarely overflows, so the reservation bought nothing and
cost 15px of dead band. Measured: `clientWidth` 204 against
`offsetWidth` 219 with `scrollHeight === clientHeight`. The same
reservation was on `.plan-scroll`, which scrolls horizontally always and
vertically almost never. Both are `auto` now.

Worth recording as a method note: the rail drag looked broken in the
first test after this change, and wasn't. The board auto-scrolls to
"now", so the first card in DOM order can sit left of the viewport —
underneath the rail — and a drag aimed at its bounding box never leaves
the rail. The event trace showed `dragstart`, sixteen `dragover`s and a
`drop` whose target chain ended at `.list-tag-filter-chips`, which is
at the *top of the rail*. Instrument before fixing; the trace said
"your test aimed at the wrong place", not "the drag is broken".

### Navigation, which was wrong in a way the board made obvious

Clicking a project in the sidebar always called `setView('list', id)`.
From the list that reads as scoping; from the plan board, the calendar
or the dashboard it reads as being thrown out of the view you were in.
All four surfaces are project-scopable and each already owns a cursor
for it, so the click now routes to the current view's: `planProjectId`,
`dashboardProjectId`, `listFilter.project_id`, and on the calendar
`soloProjectFilter` — a time surface across every project scopes itself
by visibility, which is the same solo its rail already performs on
double-click.

The highlight followed. It had been list-only, with a comment
explaining that on the calendar "a single-project highlight would lie
about the visible content" — true, but the fix was to make it truthful
rather than to suppress it: it now reads whichever cursor the current
view uses, and on the calendar appears only when exactly one project is
visible, which is exactly when it isn't lying. `PlanBoard` also writes
its resolved project back to `planProjectId`, because the board falls
back to the list's scope (then the first project) when nothing has been
picked, and the store should say what the screen says.

Nav order is now Calendar · List · Plan · Dashboard. The three
task surfaces widen in sequence — one project's document, one project's
quarter — and the dashboard is the aggregate, so it belongs last.

## 12. Deferred to sprint 32

Implemented in [Sprint 32 — Plan history](32-plan-history.md). The
following records the original deferral from this sprint. Sprint 32
also renames the reconstructed Past band and its row to Unplanned;
Past now toggles a separate historical timeline with continuous scrubbing,
precise revision selection and independent zoom/pan. The week-stop design
recorded below was superseded during sprint 32.

The board ships **live only**. The reason is structural, not scheduling:
`sprint.*` and `task.set_sprint` ship *in* 31, so the placement timeline
is empty on the day it lands — "this was planned 3 weeks earlier" is
undemoable at the end of 31 no matter how much is built. The
`PlanSnapshot` seam makes the deferral free: 32 adds a second producer of
a shape that already renders, and changes no component.

What 32 owes: the `GET /api/plan/at` handler, `PlanTimeline.tsx` (week
-granular stops, ticks only on weeks with ≥1 op so the strip doubles as
a change-density sparkline, inside the horizontal scroll container so
each tick sits over its week column), the drift overlay (solid =
scrubbed, ghost = live, `→ +3w` badges), the live-vs-replay equivalence
assertion, and a `visual-check` block that scrubs and shoots. Card
counters stay removed (§11c); the checklist and all-done dimming already
show completion. Deleted-task resurrection is already implemented and
covered by the pure projection tests (§8).

Also deferred, deliberately: a genesis clamp. The scrubber's left stop is
the project's earliest op, with one honest banner ("History for this
project starts 12 Aug 2026") rather than per-field hatching. A week you
cannot reconstruct is a week you don't offer.

**Be honest about one cost of this model.** Under the tag-based
alternative, sprint membership would have had *retroactive* history,
because `task.set_tags` has been logged since sprint 21.
`tasks.sprint_id` has never been written by any op, so membership
history starts at zero. That loss is smaller than it looks — those
historical ops recorded *basic-tag* edits, not sprint placements, so
replaying them would have shown a plan nobody ever made. The retro band
is the honest way to get a populated past, and it shipped here.
