// Month aggregation + goal scoring for the dashboard.
//
// Everything here derives from data the client already holds: bootstrap
// ships every block in the active workspace's project scope with no date
// filter, so a whole month is computable without a round trip.
//
// The shapes below are deliberately wire-friendly — plain arrays and
// numbers, no Maps or Dates on the boundary — because they are the shape
// `GET /api/stats/month` will return when the aggregation moves to a SQL
// `GROUP BY`. When that lands, the components shouldn't have to change:
// only the thing producing `MonthStats` does.
//
// Two rules run through all of it:
//
//   1. Blocks are filtered to the caller *first*. `list_blocks_in_scope`
//      has no user predicate, so in a team workspace `blocks` contains
//      everyone's — aggregating without the filter would report the
//      team's hours as yours. The dashboard is personal-stats-only, so
//      `activePersonId` is deliberately ignored: it's always `meId`.
//   2. `completed` and `planned` never mix. Planned is intent; it counts
//      toward "today and the rest of the month" and never toward a
//      historical total.

import type { Goal, LinkedTask, Project, Tag, Task, TimeBlock, UUID, WorkTask } from './types';
import { blockMinutes, localMidnight, monthRangeFor, weekStartOf } from './time';

/// Fill color for blocks whose task carries no tags. A real token rather
/// than a hex so it tracks the theme — these bars sit alongside
/// tag-colored ones and shouldn't fight them for attention.
export const UNTAGGED_COLOR = 'var(--ink-4)';

export interface Bucket {
  /// Stable identity for React keys and click targets. A project id, a
  /// lowercased tag title, a workspace id, or `'untagged'`.
  key: string;
  label: string;
  color: string;
  done_min: number;
  planned_min: number;
}

export interface DayBucket {
  /// Local midnight — the canonical day key.
  ms: number;
  done_min: number;
  planned_min: number;
  /// Project with the most completed minutes that day, for the hover
  /// popover. Null on a day with no completed work.
  top_project: { label: string; color: string } | null;
}

export interface MonthStats {
  /// `[start, end)` local midnights.
  start: number;
  end: number;
  done_min: number;
  planned_min: number;
  /// Days with at least one completed block. The denominator people
  /// actually care about — "12 of 31" reads better than an average
  /// diluted by weekends.
  active_days: number;
  /// Completed minutes / active days. Zero when there are no active
  /// days, rather than NaN.
  avg_active_min: number;
  /// One entry per day of the month, in order.
  by_day: DayBucket[];
  by_project: Bucket[];
  by_tag: Bucket[];
  /// Previous month's completed minutes, for the "vs last month" tile.
  /// Null when that month falls outside what the client has loaded, so
  /// the tile can mute itself instead of claiming a false −100%.
  prev_done_min: number | null;
}

export interface StatsInput {
  meId: UUID | null;
  blocks: TimeBlock[];
  tasks: Task[];
  projects: Project[];
  tags: Tag[];
  monthOffset: number;
  /// Dashboard scope. Null = workspace overview; set = every number on
  /// the page re-scopes to that project.
  projectId?: UUID | null;
}

/// A block joined to what it was spent on. Built once per aggregation
/// pass; every bucket below reads from it rather than re-walking the
/// task list.
interface Resolved {
  ms: number;
  minutes: number;
  done: boolean;
  task: Task;
  project: Project | undefined;
}

function resolve(input: StatsInput, from: number, to: number): Resolved[] {
  const taskById = new Map(input.tasks.map((t) => [t.id, t]));
  const projectById = new Map(input.projects.map((p) => [p.id, p]));
  const out: Resolved[] = [];
  for (const b of input.blocks) {
    // Rule 1: caller's blocks only.
    if (b.user_id !== input.meId) continue;
    const startMs = Date.parse(b.start_at);
    if (startMs < from || startMs >= to) continue;
    const task = taskById.get(b.task_id);
    // A block whose task isn't in scope can't be attributed to a project
    // or tag, so it would silently distort every breakdown. Shouldn't
    // happen — bootstrap ships both from the same project scope — but
    // dropping it is the honest failure mode.
    if (!task) continue;
    if (input.projectId && task.project_id !== input.projectId) continue;
    out.push({
      ms: localMidnight(startMs),
      minutes: blockMinutes(b),
      done: b.state === 'completed',
      task,
      project: projectById.get(task.project_id),
    });
  }
  return out;
}

export function monthStats(input: StatsInput): MonthStats {
  const { start, end } = monthRangeFor(input.monthOffset);
  const rows = resolve(input, start, end);

  let done_min = 0;
  let planned_min = 0;

  // --- per day ---
  const days = new Map<number, { done: number; planned: number; byProject: Map<string, number> }>();
  for (let ms = start; ms < end; ) {
    days.set(ms, { done: 0, planned: 0, byProject: new Map() });
    const d = new Date(ms);
    ms = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).getTime();
  }

  for (const r of rows) {
    const day = days.get(r.ms);
    if (r.done) {
      done_min += r.minutes;
      if (day) {
        day.done += r.minutes;
        const key = r.project?.id ?? 'unknown';
        day.byProject.set(key, (day.byProject.get(key) ?? 0) + r.minutes);
      }
    } else {
      planned_min += r.minutes;
      if (day) day.planned += r.minutes;
    }
  }

  const projectById = new Map(input.projects.map((p) => [p.id, p]));
  const by_day: DayBucket[] = [...days.entries()].map(([ms, d]) => {
    let topId: string | null = null;
    let topMin = 0;
    for (const [id, min] of d.byProject) {
      if (min > topMin) { topMin = min; topId = id; }
    }
    const p = topId ? projectById.get(topId) : undefined;
    return {
      ms,
      done_min: d.done,
      planned_min: d.planned,
      top_project: p ? { label: p.title, color: p.color } : null,
    };
  });

  const active_days = by_day.filter((d) => d.done_min > 0).length;

  // --- by project ---
  const projAcc = new Map<string, Bucket>();
  for (const r of rows) {
    const p = r.project;
    if (!p) continue;
    let b = projAcc.get(p.id);
    if (!b) {
      b = { key: p.id, label: p.title, color: p.color, done_min: 0, planned_min: 0 };
      projAcc.set(p.id, b);
    }
    if (r.done) b.done_min += r.minutes; else b.planned_min += r.minutes;
  }

  // --- by tag ---
  //
  // Tags are project-scoped (`tags.project_id`), so the same `meeting`
  // tag is a *distinct row* in every project that uses it. Grouping by
  // tag_id would therefore split one conceptual tag into several bars at
  // workspace level. Group by lowercased title instead, and settle color
  // disagreements between projects by weight: the project contributing
  // the most minutes to a bucket picks its color, which keeps the choice
  // stable across renders instead of depending on iteration order.
  const tagById = new Map(input.tags.map((t) => [t.id, t]));
  const tagAcc = new Map<string, Bucket & { colorVotes: Map<string, number> }>();
  const tagBucket = (key: string, label: string) => {
    let b = tagAcc.get(key);
    if (!b) {
      b = { key, label, color: UNTAGGED_COLOR, done_min: 0, planned_min: 0, colorVotes: new Map() };
      tagAcc.set(key, b);
    }
    return b;
  };
  for (const r of rows) {
    const tagRows = r.task.tag_ids.map((id) => tagById.get(id)).filter((t): t is Tag => t != null);
    if (tagRows.length === 0) {
      const b = tagBucket('untagged', 'Untagged');
      if (r.done) b.done_min += r.minutes; else b.planned_min += r.minutes;
      continue;
    }
    // A block on a multi-tagged task counts in full toward each of its
    // tags. The bars therefore sum to more than the month's total, which
    // is the honest reading of "how much time touched #auth" — splitting
    // the minutes N ways would understate every tag.
    for (const tag of tagRows) {
      const key = tag.title.toLowerCase();
      const b = tagBucket(key, tag.title);
      if (r.done) b.done_min += r.minutes; else b.planned_min += r.minutes;
      b.colorVotes.set(tag.color, (b.colorVotes.get(tag.color) ?? 0) + r.minutes);
    }
  }
  const by_tag: Bucket[] = [...tagAcc.values()].map((b) => {
    let color = b.color;
    let best = 0;
    for (const [c, min] of b.colorVotes) {
      if (min > best) { best = min; color = c; }
    }
    return { key: b.key, label: b.label, color, done_min: b.done_min, planned_min: b.planned_min };
  });

  // --- vs last month ---
  //
  // Only meaningful if the previous month is inside the window the
  // client actually holds. Bootstrap is unbounded in time, so in
  // practice it is — but a client that has only ever seen a partial
  // sync would otherwise render a confident "−40h" that's really "we
  // don't have those blocks". Detect that by checking whether *any*
  // block predates the previous month's start.
  const prev = monthRangeFor(input.monthOffset - 1);
  const prevRows = resolve(input, prev.start, prev.end);
  const hasOlderData = input.blocks.some(
    (b) => b.user_id === input.meId && Date.parse(b.start_at) < prev.start,
  );
  const prev_done_min = prevRows.length > 0 || hasOlderData
    ? prevRows.reduce((s, r) => s + (r.done ? r.minutes : 0), 0)
    : null;

  return {
    start,
    end,
    done_min,
    planned_min,
    active_days,
    avg_active_min: active_days > 0 ? done_min / active_days : 0,
    by_day,
    by_project: [...projAcc.values()].sort(byHoursDesc),
    by_tag: by_tag.sort(byHoursDesc),
    prev_done_min,
  };
}

function byHoursDesc(a: Bucket, b: Bucket): number {
  return (b.done_min + b.planned_min) - (a.done_min + a.planned_min);
}

/// Tasks ranked by completed minutes within the current scope.
///
/// Named for what it measures, not for merit: hours spent is a *cost*
/// signal. The point of this list is to surface a project that's really
/// one runaway task, which is a problem to notice, not a leaderboard.
///
/// Omit `limit` to get every task with completed time, sorted. The
/// caller slices — that way it knows how many it is hiding and can say
/// so, instead of truncating silently.
export function tasksByHours(input: StatsInput, limit?: number): { task: Task; done_min: number }[] {
  const { start, end } = monthRangeFor(input.monthOffset);
  const acc = new Map<string, { task: Task; done_min: number }>();
  for (const r of resolve(input, start, end)) {
    if (!r.done) continue;
    const e = acc.get(r.task.id) ?? { task: r.task, done_min: 0 };
    e.done_min += r.minutes;
    acc.set(r.task.id, e);
  }
  const sorted = [...acc.values()].sort((a, b) => b.done_min - a.done_min);
  return limit == null ? sorted : sorted.slice(0, limit);
}

// --- Other workspaces ---

/// Hours from workspaces *other* than the active one, bucketed per
/// workspace. Hours only, no project breakdown — that's the point of an
/// aggregate bar, and the overlay payload doesn't carry project identity
/// anyway.
///
/// Exactly one of the two overlays is ever populated: the server returns
/// the personal side when you're in a team workspace and the work side
/// when you're in your personal one. So this is never "Personal *and*
/// Work" — it's the other side of whichever split you're on.
///
/// `tasks` supplies the workspace attribution, because a `TimeBlock`
/// carries none. Only `/work/calendar` sends `WorkTask` (with
/// `workspace_id`/`workspace_title`); the personal overlay sends plain
/// `LinkedTask`, and there's only one personal workspace, so it collapses
/// to a single labelled bucket.
export function otherWorkspaceBuckets(args: {
  meId: UUID | null;
  monthOffset: number;
  blocks: TimeBlock[];
  tasks: (WorkTask | LinkedTask)[];
  /// Label for tasks with no workspace attribution — i.e. the personal
  /// overlay's single bucket.
  fallbackLabel: string;
}): Bucket[] {
  const { start, end } = monthRangeFor(args.monthOffset);
  const taskById = new Map(args.tasks.map((t) => [t.id, t]));
  const acc = new Map<string, Bucket>();
  for (const b of args.blocks) {
    if (b.user_id !== args.meId) continue;
    const startMs = Date.parse(b.start_at);
    if (startMs < start || startMs >= end) continue;
    const t = taskById.get(b.task_id);
    const ws = t && 'workspace_id' in t
      ? { key: t.workspace_id, label: t.workspace_title }
      : { key: 'other', label: args.fallbackLabel };
    let bucket = acc.get(ws.key);
    if (!bucket) {
      // No per-project color to borrow — these bars are deliberately
      // neutral so they read as "elsewhere" rather than competing with
      // the active workspace's project palette.
      bucket = { key: ws.key, label: ws.label, color: UNTAGGED_COLOR, done_min: 0, planned_min: 0 };
      acc.set(ws.key, bucket);
    }
    const min = blockMinutes(b);
    if (b.state === 'completed') bucket.done_min += min; else bucket.planned_min += min;
  }
  return [...acc.values()].sort(byHoursDesc);
}

// --- Goals ---

export interface GoalPeriod {
  /// Local midnight of the day, or of the week's Monday.
  ms: number;
  total_min: number;
  met: boolean;
  /// 0..1 progress toward the target, for the cell fill. For a floor
  /// this is how close you got; for a cap it's how much of the allowance
  /// you've used. A frequency goal (no target) is binary.
  fill: number;
  /// Cap only: the allowance was blown. Renders as its own state rather
  /// than reading as "very complete".
  over: boolean;
  /// This period hasn't happened yet — the grid dims it and the streak
  /// walk stops before it.
  future: boolean;
}

/// Score a goal across a month, one entry per day (or per week for a
/// weekly cadence).
///
/// Only **completed** blocks count. A goal is a claim about what you
/// did, so a day full of planned blocks is not met until the work is.
///
/// Scoring is recomputed from blocks every time, never stored — which is
/// what makes a goal definitional: retune the target and the whole grid
/// re-scores. The flip side, worth knowing: periods *before* a goal
/// existed are scored too. For a floor that's honest (they show as
/// misses). For a cap it's flattering — every untracked day in the past
/// trivially passes, because zero minutes is under any allowance.
export function scoreGoal(
  goal: Goal,
  input: StatsInput,
  today: number,
): GoalPeriod[] {
  const { start, end } = monthRangeFor(input.monthOffset);
  // Ignore the dashboard's project scope here: a goal carries its own,
  // and re-scoping it to whatever bar the user last clicked would
  // silently change what the goal means.
  const rows = resolve({ ...input, projectId: null }, start, end)
    .filter((r) => r.done && matchesGoal(goal, r.task));

  const weekly = goal.cadence === 'weekly';
  const keyOf = (ms: number) => (weekly ? weekStartOf(ms) : ms);

  const totals = new Map<number, number>();
  for (const r of rows) {
    const k = keyOf(r.ms);
    totals.set(k, (totals.get(k) ?? 0) + r.minutes);
  }

  // Walk the month by period so empty ones still get a cell — a miss has
  // to be visible, and for a cap an empty period is a *pass*.
  const periods: number[] = [];
  const seen = new Set<number>();
  for (let ms = start; ms < end; ) {
    const k = keyOf(ms);
    if (!seen.has(k)) { seen.add(k); periods.push(k); }
    const d = new Date(ms);
    ms = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).getTime();
  }

  const currentKey = keyOf(today);
  return periods.map((ms) => {
    const total_min = totals.get(ms) ?? 0;
    const target = goal.target_min;
    const future = ms > currentKey;
    if (target == null) {
      // Frequency goal — "any block counts". Floors only; the schema
      // rejects a cap without a target.
      const met = total_min > 0;
      return { ms, total_min, met, fill: met ? 1 : 0, over: false, future };
    }
    const ratio = Math.min(total_min / target, 1);
    if (goal.direction === 'at_most') {
      return {
        ms,
        total_min,
        met: total_min <= target,
        fill: ratio,
        over: total_min > target,
        future,
      };
    }
    return { ms, total_min, met: total_min >= target, fill: ratio, over: false, future };
  });
}

/// Does a block's task fall inside a goal's scope? The three refs are
/// AND-combined; all null means every block in the workspace counts.
///
/// Note `tag_id` already implies a project, since tags are
/// project-scoped — so a goal carrying both is mildly redundant rather
/// than contradictory.
function matchesGoal(goal: Goal, task: Task): boolean {
  if (goal.project_id && task.project_id !== goal.project_id) return false;
  if (goal.tag_id && !task.tag_ids.includes(goal.tag_id)) return false;
  if (goal.task_id && task.id !== goal.task_id) return false;
  return true;
}

/// Consecutive met periods ending at the current one.
///
/// Today not being met yet doesn't break the streak — the day isn't over.
/// The walk starts at the current period, skips it if it's unmet, then
/// counts backwards while periods are met. Future periods are never
/// counted: for a cap they'd all be trivially "met" and would inflate
/// the streak to the end of the month.
export function goalStreak(periods: GoalPeriod[], today: number, cadence: string): number {
  const currentKey = cadence === 'weekly' ? weekStartOf(today) : localMidnight(today);
  let i = periods.findIndex((p) => p.ms === currentKey);
  // Current period outside this month's grid (viewing an old month):
  // a streak relative to "now" is meaningless there, so report none.
  if (i < 0) return 0;
  if (!periods[i].met) i -= 1;
  let streak = 0;
  for (; i >= 0 && periods[i].met; i -= 1) streak += 1;
  return streak;
}

/// "18 / 31 days met" — counts only periods that have actually happened,
/// so the denominator doesn't include the rest of the month.
export function goalMetCount(periods: GoalPeriod[]): { met: number; total: number } {
  const elapsed = periods.filter((p) => !p.future);
  return { met: elapsed.filter((p) => p.met).length, total: elapsed.length };
}
