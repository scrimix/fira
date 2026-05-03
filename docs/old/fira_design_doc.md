# Fira — UI Design Doc (v12)

> A task layer for projects too complex for a kanban board.

---

## 1. What Fira is for

Fira is a tool for managing tasks across the whole arc of real work — capturing them as they appear, understanding what they actually contain, prioritizing them honestly, planning when they'll happen, distributing them across people, and tracking what really happened versus what we said would happen. Most task tools handle the first half of that arc and hand off to a calendar (which doesn't know about tasks) and a spreadsheet (which doesn't know about reality) for the rest. The handoffs are where plans drift from execution, and the drift is invisible until it's expensive.

The kinds of failures we see all the time, in our work and in everyone else's: a person gets allocated 5 hours to a project this week and actually spends 10, because the spreadsheet didn't know that the "small" auth task contained three unknowns that turned into their own tasks. Two weeks later the same person is "20% on Project X" but Project X has no critical work, so they sit underloaded while Project Y is in crunch — and nobody notices because the percentages on paper still look balanced. A task sits in "in progress" for two weeks while its estimate quietly grows from one day to fourteen, and the only person who knows is the assignee, because no view in the system shows that drift. A fragmented team lead spends one hour per week per task because they're split across too many projects, which sounds fine until you realize the time-to-completion on every one of those tasks is now measured in months. Bugs get spotted in standup, get nodded at, and never make it into any system because capturing them requires opening a different tool and filling in five fields. And underneath all of this, the project itself is complex — a real codebase with real unknowns — and the task tool was designed for a tidier world where tasks are well-defined and finish when you said they would.

Every team we know is looking for the one tool that handles all of this, and nobody has found it. Jira is the system of record but doesn't help you plan a Tuesday afternoon. Linear is clean but assumes your week looks like a sprint board. Notion is flexible but doesn't know about time. Asana, ClickUp, Monday — same shape: each one optimizes one slice of the arc and forces you to bolt on the rest. The truth is that the perfect task tool probably doesn't exist, because different teams need different shapes. Fira isn't trying to be everyone's answer. It's trying to be the answer for the way *we* work — fragmented across projects, complex codebases with lots of unknowns, time as the scarce resource that needs to be planned and tracked honestly. If your work looks like that, the rest of this doc is for you.

The central idea is that the **time block** — a discrete scheduled work session, tied to a specific task — is the unit that connects planning to reality. A block is a real slot on a real day, attached to a real task. The plan is the set of blocks you've drawn on the calendar; the reality is the set of blocks that actually got marked complete. When the two diverge, you can see exactly where, and the snapshot system makes that divergence visible across days and weeks. Capture and understanding happen in an inbox that's a sectioned document, not a board, so a 50-row task list with deep subtask trees stays readable. Prioritization is manual ordering — top of the list is most important, period. Planning is dragging tasks onto the calendar grid. Distribution falls out of the per-person calendar view: scan your own week, see your projects in different colors, see whether the time you're putting in matches the time you said you would. Tracking is the snapshot replay: weeks later, you can scrub back through any day and see what the plan looked like, with estimates as they stood at the time, against what actually happened.

The whole product is a tight loop between these steps. Same data, different views.

### 1.1 The non-feature

One thing Fira is explicitly not:

- **Not a Jira replacement.** Teams won't migrate. Fira is a layer over Jira/Notion that mirrors tasks and owns the time blocks. It writes back only two fields (status and description) because the description is where Fira's hierarchical checkbox-tree lives.

---

## 2. Primary users

Three user shapes in v1, all served by the same two screens:

**The solo IC** managing complex personal work. Wants to plan their week honestly. Drags tasks onto the calendar, sees time-left fall as blocks complete, learns over weeks that they consistently underestimate.

**The small team (3–8) doing standup.** Runs a daily 10–15 minute sync where each person covers what they finished, what they're doing today, and what's blocking them. Needs to read the room quickly, capture new tasks as they come up in conversation, and surface stalled work that's been quietly sitting for days. The inbox's assignee subsections give each person their own column to read down; the calendar's silent-blocker indicator surfaces the in-progress tasks that have stopped getting scheduled.

**The person split across multiple projects** — typically a senior IC or tech lead allocated to 3–5 projects in parallel. Their critical view is the **personal cross-project calendar**: their own week, blocks colored by project, showing at a glance whether their actual planned hours match the percentages someone wrote in a spreadsheet. This is the user the v1 design must keep in mind even when describing per-project surfaces.

The standup user and the multi-project user are the ones who couldn't function without Fira. The solo IC is a beneficiary of the same machinery.

---

## 3. The two surfaces

Fira is two screens. Everything else is a lens on these two.

### 3.1 Task Inbox — the editorial view

Per project. Looks like a Notion page or Slack canvas — a sectioned document, not a filterable list. The only navigation control is the project switcher; everything else is content. Four sections, top to bottom:

- **Now.** Current week, plus a few days on either side. These are the tasks you're actually engaging with — they have, or are about to have, time blocks scheduled.
- **Later.** Everything not on this week's plan. This is a real backlog: it can include Jira backlog issues, Notion pages not yet pulled in for this week, and locally-captured ideas that haven't graduated yet. Later is *not* "unsynced" — a Jira-backed Later task is a real Jira issue. Later just means "not committed to this week."
- **Recurring.** Tasks that repeat indefinitely — weekly deployment, end-of-sprint testing, monthly security review. These are tasks like any other (estimate, description, assignee), but they never move to Done. Each instance of the work is a fresh time block on the same task; over time the task accumulates a long history of completed blocks. Below Later, collapsed by default if it gets long. See "Recurring tasks" subsection below.
- **Done.** Collapsed by default. An archive lens.

Two kinds of tasks live in Later: **synced** (a real Jira/Notion record exists) and **local-only** (no external record yet, created in Fira as a sticky-note capture). Both look the same in the UI; the source icon at the row-end tells them apart. Local-only Later tasks have minimal required fields — title and description — and skip estimate/priority/assignee until they matter.

The Now / Later boundary is the most important interaction in the inbox. Dragging a task from Later into Now is **promotion**: the task is being committed to. The user is prompted (inline, not modal) to fill in estimate and any missing required fields. For local-only Later tasks in a Jira/Notion-backed project, promotion is *also* the moment Fira creates the external record (the Jira issue, the Notion page) and starts syncing. For already-synced Later tasks, promotion is just a section change — nothing new is created externally.

Tasks created during standup can be added to any section. The default landing is Now (since standup conversation usually concerns this week's work), but a task captured as "we should look at this eventually" goes into Later just as easily — the user picks per-task.

**Now allows local-only tasks, but flags them.** Most Now tasks in a Jira/Notion-backed project are synced. A local-only task in Now means the user committed to work that isn't recorded in the system of record — sometimes that's intentional (a quick personal task, something too small to file), but it's also a common source of "I forgot to put it in Jira" mistakes. Local-only tasks in Now show a small warning glyph (a hollow exclamation, dim color) at the row's source-icon position, with hover text like "Not synced to Jira." A one-click promotion action on the warning creates the Jira issue right there. Local-only tasks in Later don't show the warning — Later is where uncommitted ideas live, and not syncing them is the expected state.

**Reverse motion and completion:**

- **Ticking a Now task as done** sets its status to done but keeps it in the Now section, visually struck through. This is so the team can see "this got done today" during the rest of the day's standup follow-ups, and so the assignee can batch-archive at end of day or end of week. The task does not auto-move to Done.
- **Archiving a done task** moves it out of Now and into Done. There's an explicit archive action per row, plus a "archive all completed in Now" bulk action for end-of-week cleanup.
- **Un-ticking a done-but-not-archived task** clears the done status and returns it to its normal state — useful for fixing accidental ticks.
- **Un-archiving (Done → Now)** also exists for re-opening tasks that turned out not to actually be done. Goes back to Now, not Later, since reopening implies it's active again.
- **Now → Later** is allowed (deferral). The task keeps its external link if it has one; sync continues. Demotion is just a section change.
- **Later tasks cannot have time blocks.** If a user drags a Later task onto the calendar, it auto-promotes to Now. Blocks imply commitment; Later means uncommitted to this week.
- **Recurring** is a separate axis — see below. A recurring template doesn't move through Now/Later/Done; converting a regular task to recurring (or vice-versa) is the only way in or out.

#### Sorting and grouping

Manual ordering, top-to-bottom, within every section. Top is most important. The user drags rows to reorder. Order is persisted on the task as a per-section sort key — tasks remember their position in Now and their position in Later independently, so demoting a task and re-promoting it doesn't lose its old place.

There is **no automatic sorting** by priority, due date, or anything else. The order on the screen is the user's stated priority. This is the same discipline as a paper to-do list: if it's at the top, it matters most.

**Now is further split by assignee.** Each assignee gets a subsection; rows are manually ordered within each subsection. Unassigned tasks get their own subsection at the bottom. In a personal project (single member), assignee subsections collapse to a single un-headed list — no decoration when there's nothing to differentiate.

Later and Done are flat — no assignee grouping. Later is the messy parking lot, Done is an archive; subdividing them adds noise without value.

Recurring is also flat — assignee can be set per task but the section itself doesn't subdivide. Most recurring tasks are owned by one person or are team rituals.

#### Recurring tasks and instances

Some work repeats indefinitely — code review, weekly deployment, end-of-sprint testing, monthly security review. Fira models this as two related task types: a **recurring** task (the template) and an **instance** task (a single occurrence of the work).

The recurring task lives in the Recurring section forever. It carries the title, a base description (steps, links, defaults), a default estimate, and a default assignee. It does not have its own time blocks and is not tickable; it's a template, not work.

Each time the work needs to happen — a new code review, this week's deployment — the user creates an instance. The instance is a regular task in every meaningful sense: it has its own description (this deployment's specific PRs and gotchas), its own subtasks (verify migrations, smoke-test, monitor), its own time blocks, and its own checkbox. It lives in Now (or wherever the user puts it). It carries a backlink to its parent recurring task so the history is queryable. When the work is done, the instance gets ticked, stays in Now until archived, and the parent recurring task is unaffected — ready for next time.

This separation matters because recurring work isn't always identical. A code review for week 12 has its own PRs, its own reviewers, its own bounce-back. A deployment for release 2.4 has its own list of branches, its own rollback plan, its own postmortem if it goes sideways. Cramming that context into a block note on a single ever-growing recurring task loses too much. Giving each instance its own task row preserves the context where context belongs — in a description with subtasks, alongside the time blocks for that specific instance.

**Creating instances.** Each recurring task has a "create instance" action that spawns a new instance task pre-filled from the template (title suffixed with the cycle, description copied, default estimate and assignee inherited). The user can edit any of it before saving. For weekly rituals, this is a one-click action at the start of the week; for ad-hoc rituals like "deployment when we cut a release," it's manual when the moment comes.

**Becoming recurring.** Any regular task can be converted to recurring via a per-row control. When converted, the task moves to the Recurring section and becomes a template — its existing time blocks are removed (they belong to a one-off completion, not a template), and the user is prompted to confirm. Flipping it back to regular demotes it to Later.

**For Jira-backed recurring tasks**, the Jira status is mapped to a project-configured "Paused" or similar non-active state — Fira never pushes Done for a recurring task. Instances are real Jira tasks of their own, created at instance-spawn time, and follow the normal sync rules.

**Why this lives below Later.** Recurring templates aren't "this week's plan" (Now) and aren't "next week's plan" (Later) — they're ongoing commitments. Their instances *are* in Now during the week they happen. Putting templates at the bottom of the inbox keeps them out of the way of editorial planning while still being one click away when you need to spawn this cycle's instance.

#### Inbox row behavior

Each task is a checkbox row:

```
☐ Implement OAuth refresh token rotation        [3h left]  ⓘ
  ☐ Audit current refresh logic
  ☐ Add rotation endpoint
  ☐ Migrate existing tokens
  → see description for full plan
```

The indented children are *both* checkbox subtasks AND the bullets in the markdown description, kept in sync. For Jira-backed Now tasks, the description IS the contract written back to Jira. The "see description" link opens the full description in a side panel; images render there for mirrored tasks.

**Frictionless editing.** Every row is editable in place. Enter creates a sibling. Tab/Shift-Tab indents/outdents. Cmd-Enter ticks done. No save button anywhere.

**Per-row controls (appear on hover):**
- Assign person (also moves the row between assignee subsections in Now)
- Add tag
- Set estimate
- Schedule (small calendar popover — pick a slot, creates a block)
- Promote / demote (Later ↔ Now)

**No filters.** The inbox is a document, not a query. If a user wants "show me only my tasks" they switch projects, or they look at the calendar (which has the person-switcher). Tags and statuses exist on tasks for the calendar's task rail and for snapshots, but they don't filter the inbox.

#### Date-scoped reading mode

A date selector at the top of the inbox re-scopes Now to that date's lens. "What's the state as of Tuesday?" The Now section, with its assignee subsections, re-renders to show:

- Tasks with completed blocks on that date (yesterday's done)
- Tasks with planned blocks on that date (today's plan)

The assignee grouping is what makes this standup-grade: walk the columns of a teammate's name, see what they finished and what they're doing today, move on. No filter required — the document just *reads* like a standup as you scroll.

The "silent blockers" signal (in-progress tasks with no upcoming blocks) lives on the calendar, not the inbox — it's a scheduling question, not an editorial one. See §3.2.

### 3.2 Calendar — the spatial view

Weekly grid, Mon–Sun, 6am–10pm default with scroll. Time blocks render as rectangles spanning their start/end.

**The calendar always shows one person's week.** Projects don't do work, people do — every block belongs to exactly one person, and overlaying multiple people's blocks on one grid would be visual noise without information value. The two controls in the header answer the only two questions worth asking:

- **Whose calendar?** Person-switcher. Defaults to "me." Switching to a teammate shows their week.
- **Which project(s)?** Project filter. Defaults to "all" — every project the selected person belongs to, blocks colored by project. Selecting one project narrows to just that project's blocks (other-project blocks dim or disappear, configurable).

The default landing — me, all projects — is the answer to the spreadsheet allocation problem. A senior IC split across 4 projects opens the calendar and immediately sees their week colored by project: which days are Project X-heavy, which projects got zero hours, whether the percentages someone wrote in a spreadsheet match the reality of what's actually planned.

The "narrow to one project" filter is what you use when planning *for* that project — adding blocks, dragging from the rail, sequencing the project's tasks. The filter doesn't change *whose* calendar you're looking at; it changes which subset of blocks is highlighted.

**Layout, left to right:**
- Mini month calendar + week navigator (collapsible)
- The grid itself (dominant — at least 60% of width)
- Task rail on the right: shows the selected person's Now tasks (regular + instance) plus the project's recurring templates. Tasks are grouped by project (project headers, manually-ordered rows under each, mirroring each project's inbox order). Recurring templates appear in their own subsection below Now within each project group, visually distinct (a small ↻ glyph beside the title). Dragging a regular or instance task onto the calendar creates a planned block on that task. Dragging a recurring template onto the calendar **spawns a new instance** for the current cycle and creates a block on the instance — one motion, two operations, hidden from the user as a single action.

**Compare mode (v1 stretch, v2 if it's hard).** When the user wants to see overlap between two people — "when can Anna and I pair?", "is Bob actually free Thursday?" — they enable compare mode and pick a second person. The grid splits into alternating columns or side-by-side panels. This is the *only* way to see two people's blocks on one screen; there is no team or project overlay.

**Silent-blocker indicator.** In the task rail, any Now task with `status = in_progress` and no `planned` blocks in the next 3 days gets a small visual marker — a hollow dot or muted warning glyph next to its title. This is the standup's killer signal. The rule is precise: it fires on absence-of-future-planned-blocks, not on absence-of-recent-completed-blocks. A task with five completed blocks last week and none planned this week still fires.

**Cross-task dependencies** ("X must finish before Y can start") are out of scope for v1. Noted because they're standup-relevant and will come up; resist building them until v2.

**Block colors are per-project.** That's the only color dimension the calendar uses — it's what makes "all projects" view legible. Priority is communicated by the manual order in the inbox (top is most important); blocks on the calendar carry no priority signal. With one project filtered, all blocks share that project's color and rely on the title for differentiation.

**Interactions:**
- Drag a task from the rail onto the grid → creates a planned block. Default duration: 60 min, or `min(time_left, 90 min)` if estimate exists.
- Click-and-drag on empty grid → creates a block, then prompts which task it's for (or "new local task," which lands in the inbox of the currently-filtered project, or — if no project filter — the user's default project).
- Resize block by dragging edges. Move by dragging body. 15-min snap by default; hold shift for free.
- Right-click block: duplicate, mark complete, mark skipped, delete, convert to recurring.
- Tick a block complete → captures `actual_minutes`, decrements `time_left` on the task.
- Overlapping blocks split width 50/50 (or 33/33/33 for three, etc.). The visual rule is honesty, not enforcement — overlap is allowed because life is messy.

**Editing other people's blocks.** When viewing a teammate's calendar, the grid is read-only by default. A small "edit mode" toggle lets you make changes to their blocks if you have permission — useful for managers redistributing work. Defaults are conservative; permissions are per-project (anyone in the project can edit anyone else's blocks within that project, but you can't edit blocks from a project you don't belong to).

**GCal events** appear as muted, dashed-border blocks behind the user's own time blocks. They reduce visible "available" hours but don't reduce time-left on any task.

**Time blocks optionally sync to GCal one-way** (Fira → GCal) so the user's calendar reflects their plan. The GCal event has a Fira deep-link in the description. Read sync (GCal → Fira) is for visualization only — it never creates Fira tasks or blocks.

#### The cross-project view is the allocation answer

Worth restating because it's what makes Fira useful at the team level, not just the IC level:

The default calendar — your own week, blocks colored by project, summed up — replaces the Excel allocation spreadsheet. Instead of writing "20% Project X" and hoping work fits the box, you put real blocks for real tasks on real days, and the percentage is whatever the blocks add up to. This is **honest allocation**: it can't lie, because it's tied to actual planned work.

For the team-wide allocation question ("who's doing what for which project this week?"), v1 answers it by walking through teammates with the person-switcher. A dedicated team-allocation view (rows = people, columns = projects, cells = block-hours, summed across the whole team) is a strong v2 candidate but explicitly out of scope here — it's the natural next product surface once the data exists.

---

## 4. Data architecture

The most important section in this doc. Get this right and everything else falls out; get it wrong and every feature fights you.

### 4.1 Tasks

Local copies of everything. Not a thin shadow of Jira; a full task model on its own terms, capable of standing alone (for Later tasks and local projects) and capable of mirroring (for Now tasks in Jira/Notion projects).

**Why local copies, not just IDs:**
- The inbox renders dozens of tasks. You cannot make dozens of API calls per page load.
- Filter and sort across projects ("all in-progress 'auth' tasks, by priority") requires local queryable data.
- Jira and Notion are not always up. The calendar should not break when they hiccup.
- Snapshots reference task IDs and resolve them live (see §4.4) — even though we don't *snapshot* task state, we still need it locally to render at any given time.

**Schema:**

```
tasks
  id                       uuid, pk
  source                   enum: local | jira | notion
  external_id              text, nullable    -- null for local & Later
  external_workspace       text, nullable    -- jira site / notion workspace id
  external_url             text, nullable    -- deep link
  project_id               fk projects, nullable
  section                  enum: now | later | recurring | done
  title                    text
  description_md           text
  status                   enum: backlog | todo | in_progress | done | archived
  status_external          text, nullable    -- raw source status, for debugging maps
  assignee_id              fk users, nullable
  priority                 enum: p0 | p1 | p2 | p3, nullable
  estimate_minutes         int, nullable
  parent_task_id           fk tasks, nullable    -- subtask hierarchy (within a single task)
  tags                     text[]
  task_type                enum: regular | recurring | instance   default 'regular'
  recurring_parent_id      fk tasks, nullable    -- only set on instances; points at the recurring template
  source_created_at        timestamptz, nullable
  source_updated_at        timestamptz, nullable   -- source's last-edit
  fira_updated_at          timestamptz             -- our last-edit
  last_synced_at           timestamptz, nullable
  sync_state               enum: clean | pending_push | diverged | error | not_synced
  raw_payload              jsonb, nullable         -- safety net for fields we didn't map
  sort_key                 text                    -- per-section manual order; see notes
  created_at, updated_at   timestamptz
```

**Notes:**

- `section` is the Now / Later / Recurring / Done bucket. It's a property of the task, not a query.
- `task_type` distinguishes three kinds of task:
  - **`regular`** — a normal one-off task. Lives in Now / Later / Done. The default, by far the most common.
  - **`recurring`** — a template for repeating work like code review, weekly deployment, sprint testing. Lives in the Recurring section. Has a title, base description, default estimate, default assignee. Has no time blocks of its own. Instances reference it.
  - **`instance`** — a single occurrence of a recurring task. Lives wherever the user puts it (typically Now). Has its own description, its own subtasks, its own time blocks. Behaves exactly like a regular task in every way except it carries a backlink to its parent via `recurring_parent_id`.
- `recurring_parent_id` is set only on instance tasks. The parent task is always type=recurring. When an instance is created, it inherits title (typically suffixed with the cycle, e.g. "Code review (week of Mar 12)"), default estimate, default assignee, and base description from the parent. After creation, the instance is independent — edits don't propagate.
- Ticking an instance complete behaves like ticking any other task: status goes to done, the task stays in Now (visually struck through) until explicitly archived. The parent recurring task is unaffected.
- `parent_task_id` is for subtask hierarchy *within* a single task and is unrelated to `recurring_parent_id`. Both can be set: an instance task can have its own subtasks. Don't conflate the two fields.
- `sort_key` encodes the manual order within `(project_id, section, assignee_id_or_null)`. Use a fractional-index / lexicographic scheme (e.g. base62 strings like "U", "V", "Ua") so that inserting between two rows is a single update, not a renumbering. Keep one sort_key per task; when a task moves between sections, store the previous section's sort_key in a small JSONB on the task (`section_history: {now: "Vk", later: "Q3"}`) so re-promoting a task restores its prior position.
- `sync_state = not_synced` only for genuinely local tasks (`source = 'local'`). Synced tasks in any section, including Later, have a real `sync_state`. Later does not mean unsynced.
- `raw_payload` is the lifeline. When you discover six months in that you needed Jira's "fix version" field, it's already there in the JSONB and you can backfill without re-fetching.
- The subtask hierarchy lives in two places that must stay aligned: `parent_task_id` and the markdown checkboxes inside `description_md`. The inbox UI edits both atomically. For Jira-backed tasks, the description is what's pushed back — Jira sub-issues are *not* created.

### 4.2 Time blocks

```
time_blocks
  id                       uuid, pk
  task_id                  fk tasks
  user_id                  fk users
  start                    timestamptz
  end                      timestamptz
  state                    enum: planned | completed | skipped
  actual_minutes           int, nullable     -- filled when state -> completed
  gcal_event_id            text, nullable    -- if pushed to GCal
  note                     text, nullable
  created_at, updated_at   timestamptz
```

Blocks can overlap freely; the calendar UI handles it visually. Only Now tasks (and during the auto-promotion moment, formerly-Later tasks) can have blocks.

### 4.3 Projects

```
projects
  id                       uuid, pk
  title                    text
  icon                     text                -- emoji or icon ref
  source                   enum: local | jira | notion
  source_config            jsonb               -- workspace id, board/db id, column maps
  members                  fk users[]
```

**Project setup flow** (Notion as the messy case):

1. User picks "Notion" as the source.
2. OAuth into Notion. Fira gets a workspace token. (Distinct from the Google login OAuth — see §4.8.)
3. User picks a Notion *database* (not a single page — Fira works against collections).
4. Column-mapping UI: which column is title, status, assignee, priority, tags. For status, map each Notion status value to one of Fira's canonical statuses.
5. Initial sync pulls all pages → creates Fira tasks. Notion has no sprint concept, so all tasks land in `section = later`. The user promotes individually as the week's plan emerges.
6. Webhook + poll thereafter.

For Jira this is simpler in the sense that the source has structure: pick a board or a JQL query. Status mapping is still required. **Initial-sync placement reflects sprint membership:** issues in the active sprint → Now; everything else (backlog, future sprints) → Later. This matches how teams already think about Jira and means a fresh Fira project for a Jira-backed team feels immediately correct without any manual sorting.

### 4.4 Snapshots — block-only, lookup-live, daily

The simplest possible model:

```
snapshots
  id              uuid pk
  user_id         fk users
  date            date              -- the snapshotted day
  taken_at        timestamptz
  blocks          jsonb             -- see structure below
```

Where `blocks` has the shape:

```json
{
  "time_blocks": [
    {"task_id": "...", "start": "...", "end": "...", "state": "planned"},
    ...
  ],
  "task_estimates": {
    "task_id_1": 60,
    "task_id_2": 180
  }
}
```

One row per user per day. Frozen at midnight local time. A year per user is ~365 rows × small JSONB blob each — trivial.

**What's preserved:**

- The day's time blocks themselves (their own data: task_id, start, end, state).
- The estimate of every task referenced by those blocks, *as it stood at snapshot time*. Stored as a map from task_id to estimate-in-minutes — one entry per task, not per block, so the same estimate isn't repeated when a task has multiple blocks that day.

**What's not preserved:** task title, status, assignee, priority, tags, description. None of it. Everything else is resolved live.

**Replay rules:**

- `task_id` is resolved live against the current `tasks` table.
- If the task still exists, render its current title.
- If the task has been deleted, render the block as **"(task not found)"**.
- If the title changed since the snapshot, you see the new title — that's accepted, snapshots capture the plan, not the metadata.
- The estimate, however, is shown as it *was* — that's the whole point of snapshotting it. "On Tuesday I thought this was 3h; today I think it's 6h" is exactly the kind of self-knowledge the replay should surface.

This makes the snapshot trivially small, schema-stable (you can change the Task model and snapshots keep working), and honest about what it preserves.

**Replay UI:** a timeline scrubber across the top of the calendar. The user drags through days and the calendar grid morphs to show that day's plan. It feels like flipping through a paper planner. Estimates show next to their tasks during replay (typically in the task rail, not on the blocks themselves), drawing attention to estimate changes over time without crowding the calendar grid.

### 4.5 Planning accuracy metric

Falls out of the snapshot model. For week W:

```
accuracy(W) = (sum of completed-block hours during week W)
              ÷ (sum of planned-block hours from the snapshot taken at start of week W)
```

The "start of week W" snapshot is the daily snapshot dated to that week's Monday — captured at midnight, so it reflects the plan as it stood before the week began. Daily snapshots between Monday and Sunday let you also compute mid-week drift if you want it later.

- Score of 1.0 = executed the plan exactly.
- Below 1.0 = over-planned (didn't get to everything).
- Above 1.0 = under-planned (did extra unplanned work).

Honest, simple, weekly cadence in the surfaced metric — the right cadence to actually change behavior. No task estimates needed, no churn metrics, no per-task drift.

### 4.6 Sync semantics

**What Fira reads:** title, description, status, assignee, tags, priority, estimate, parent/subtask refs. Plus raw_payload for everything else.

**What Fira writes back, ever:**
1. **Status.** When ticked done in Fira, push to source's configured "done" state.
2. **Description.** Debounced 5s after edit, push to source.

That's it. Nothing else.

**Sync mechanisms, in order of preference:**
- **Webhooks** where available (Jira Cloud, partial in Notion). Webhook → enqueue per-task sync.
- **Polling** for active projects (any user opened the inbox in the last 24h). Every 2–5 min, ask source for "issues updated since T."
- **Manual refresh** as the visible escape hatch.

**Conflict rule.** At push time, if `source_updated_at > last_synced_at`, abort the push and flip the task's `sync_state` to `diverged`. The UI shows a badge; the user picks which side wins. No silent overwrites — that's the rule that prevents the worst class of bug.

**Pushes are idempotent.** Use the source's "set field" semantics, not "patch" — a retry of the same push is safe.

### 4.7 What syncs and what doesn't

Sync is a property of the **source**, not the **section**. A Jira-backed task syncs whether it's in Now or Later. The only thing the section affects is whether time blocks are allowed.

| | Synced task (source = jira/notion) | Local task (source = local) |
|---|---|---|
| stored locally as full record | yes | yes |
| sync from source | yes | n/a |
| sync to source | yes (status + description only) | n/a |
| can have blocks | only when in Now | only when in Now |
| eligible for snapshot | when it has blocks | when it has blocks |

Two cases worth calling out:

- **Local-only Later task in a Jira-backed project.** Captured as a sticky-note idea, no Jira issue exists yet. Promotion to Now is also the moment Fira creates the Jira issue.
- **Synced Later task.** A real Jira backlog issue. Promotion to Now is just a section change — no external creation, sync continues as it already was.

### 4.8 Authentication

**Login: Google sign-in only in v1.** OAuth scopes are the minimal set: `openid email profile`. No password auth, no email magic link, no other providers. The reasoning is pragmatic — every target user already has a Google account (it's how they use Notion, GCal, and most Jira-on-Atlassian setups), and Google's account recovery is better than anything Fira would build.

**Personal instances are first-class.** A user signs in with a personal Gmail address and gets their own Fira workspace. They can connect their personal Notion, personal Jira, personal GCal — same product, same code path. There is no enforced organization or workspace boundary at the user level. A "team" is just a project with multiple members; if a project has one member, it's a personal project. This is important for the founder's own dogfooding case and means the user model cannot assume an org ID.

**User schema:**

```
users
  id                       uuid pk
  google_sub               text unique     -- Google's stable user id
  email                    text
  name                     text
  avatar_url               text
  created_at, updated_at   timestamptz
```

No `org_id`. Membership is per-project (`projects.members`).

**Integration OAuth is separate.** "Sign in with Google" and "Connect Google Calendar" are two distinct OAuth flows, even when it's the same Google account. They request different scopes (`calendar.events` for Calendar) and produce different tokens that are stored separately. Conflating them is a classic mistake — corporate Google admins often allow login but block Calendar API access for non-allowlisted apps, and Fira needs to gracefully handle "logged in but Calendar not connected."

**Integration tokens** (per user, per service) live in their own table:

```
integration_tokens
  id                       uuid pk
  user_id                  fk users
  service                  enum: google_calendar | jira | notion
  account_identifier       text       -- email for google, site for jira, workspace for notion
  access_token             text encrypted
  refresh_token            text encrypted, nullable
  expires_at               timestamptz, nullable
  scopes                   text[]
  created_at, updated_at   timestamptz
```

A user can have multiple tokens for the same service — e.g. personal Google account for login and Calendar, plus a work Google account for a separate Calendar. The project's `source_config` references which `integration_tokens.id` to use for sync.

**Project members all need their own integration tokens.** When a Jira project has three members, each user OAuths into Jira separately for sync to work as them. This matters because Jira API calls are made *as a user* — comments, status changes, etc. are attributed correctly. There is no service-account model in v1.

---

## 5. Standup

A daily standup is a short team sync — typically 10–15 minutes — where each person covers what they finished yesterday, what they're doing today, and what's blocking them. The hard parts in practice are: keeping it short, making sure nothing falls through the cracks, and surfacing work that's been quietly stalled for days. Fira supports this directly through the inbox and calendar, with a few small affordances that make the meeting flow without anyone needing to dig.

Open the inbox and set the date scope to today. Now's assignee subsections become the standup's natural reading order — go down each person's column and you see their completed blocks from yesterday and their planned blocks for today, in the order *they* prioritized. The conversation tracks the document. New tasks that come up during the meeting — bugs spotted, scope discoveries, things someone agreed to take on — get captured inline as they're mentioned, in the right person's section, and they're real tasks the moment they're typed. No "I'll add that to Jira after."

The calendar handles the parts the inbox can't. When someone says "I'm working on X today," the person-switcher pulls up their calendar so the team can see whether X actually has time on it or whether the day is full of meetings. The task rail's silent-blocker indicator surfaces in-progress tasks that haven't had a planned block for three days — the tasks people have stopped scheduling but haven't admitted are stuck. Those are the ones standup is supposed to catch and usually doesn't.

For pairing or scheduling questions that come up — "when can we sit down on this together?" — the calendar's compare mode shows two people's weeks side by side. This is the one piece specifically motivated by standup; if implementation is painful, it's the first thing to defer.

---

## 6. Visual design intent

For the design agent that picks this up: Fira should feel like a *tool*, not a SaaS dashboard. Closer to a code editor or a CAD program than to Asana. The calendar grid is the hero — it should feel precise, dense, and editable. The inbox should feel like a text document, not a Jira board.

**Suggested directional cues** (the design agent should commit to one and run):

- **Editorial / refined.** Mono/sans pairing (e.g. JetBrains Mono + a quiet humanist sans like Söhne or IBM Plex Sans). Restrained palette: paper white, ink, one strong accent for "now" (vermillion or a saturated cyan). Hairline borders. Generous gutters in the inbox; tight, gridded calendar.
- **Utilitarian / industrial.** A power tool that doesn't pretend to be friendly. Single sans (e.g. Söhne, Inter Tight, Geist). Dark default. Subtle grid dots. Dense, no decorative space.

Avoid: pastel gradients, soft shadows everywhere, "friendly" rounded rectangles, generic system fonts, purple-on-white. This is a tool for people who care about their time.

**Density expectations:**
- Calendar: at least 14 visible hours, 7-day week comfortable to read. Blocks are coloured rectangles with truncated title and a thin progress bar showing planned vs completed time on the parent task.
- Inbox: row height ~32px. No avatars unless on team filter. No emoji unless user-added.
- Inbox sections: Now is open by default and visually dominant. Later is collapsed-but-prominent below it. Done is collapsed and quiet.

**Motion:** sparing. Block drag should feel rigid (15-min snap). Subtask reorder should ease. No page-load reveals; this is software people open 30 times a day.

**Visual treatment of mirrored vs local tasks:** tiny source icon at row-end, no other difference. The whole point is they feel native to Fira.

**Block colors:** per-project. Priority is sequence in the inbox, not a visual signal on the block.

---

## 7. Out of scope for v1

Stated up front so the design agent doesn't speculate:

- Mobile (calendar grid wants real estate)
- Real-time collaboration on the inbox (single-editor with refresh is fine)
- Image upload on local tasks (mirrored tasks render images from source)
- Write-back beyond status and description
- Standalone recurring blocks not tied to any task — recurring work is modeled via recurring tasks + instances, not via the block layer
- Notifications, reminders, email digests
- Permissions beyond project membership
- Custom Jira fields (raw_payload preserves them; UI comes later)
- Cross-task dependencies (X-blocks-Y)
- Team-allocation matrix view (rows = people, columns = projects, cells = block-hours). Strong v2 candidate; the data exists in v1, the dedicated screen does not.
- Per-task drift / estimate-change history

---

## 8. Build order

0. Google sign-in. Single-user, personal-instance shape. The auth surface is small and gating; ship it first so every later slice has a real user to attach data to.
1. Local tasks + inbox (Now/Later/Done) + calendar drag-to-schedule, single-project. No external sync, no team. Prove the time-block model on its own merits.
2. **Multi-project support for a single user**: a user can create more than one project. The calendar shows blocks across all of their projects by default, colored by project, with a project filter to narrow when planning. This is what proves the cross-project allocation answer — even before any team or sync is wired up, the founder dogfooding their own week across 3–4 personal projects should already feel valuable. Without this step, the product is just a fancier todo list.
3. Daily snapshot capture (time_blocks + task_estimates). No replay UI yet — just capture. Start collecting data immediately so the metric has history when you turn it on.
4. Jira sync: read first (initial sync respects sprint membership → Now/Later split), then write status + description. Local-only-Later → Now promotion creates Jira issues.
5. Notion sync (database picker + column mapping; initial sync places everything in Later).
6. GCal read (events as background) + GCal write (blocks as events). Reuse the Google login token if scopes were granted; otherwise prompt for the additional Calendar scope.
7. Snapshot replay UI (daily timeline scrubber) + planning-accuracy metric.
8. Multi-user projects + per-user integration tokens. This is when "team" becomes real; before this, every project is single-member. Person-switcher on calendar appears here.
9. Standup polish: date scope on inbox; silent-blocker indicator in the calendar rail; assignee subsections in Now. Small individually; together they unlock the standup workflow.
10. Two-user calendar compare mode, if it's not painful.

Steps 0–3 are the irreducible core. The two things to prove early: (a) time blocks feel right as a unit (steps 0–1), (b) cross-project allocation falls out naturally for one person (step 2). If those don't land, no amount of sync or team support will save the product.
