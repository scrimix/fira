// Plan-board assembly. Pure: plain arrays in, plain data out, no React
// and no store — the same posture as stats.ts.
//
// This is the seam the version scrubber (sprint 32) plugs into. Live
// mode feeds current store state in; replay mode feeds the projected
// entities `GET /api/plan/at` returns. One assembly implementation
// serves both, so what you see scrubbed to W38 is rendered by exactly
// the code that renders today.
//
// The rule that makes that work: PlanView renders only PlanSnapshot. No
// component reads `s.sprints` directly.

import type { Section, Status, TimeBlock, UUID } from './types';
import {
  fmtDateKey, fortnightStartOf, isoWeekLabel, localMidnight, parseDateKey,
  weekStartOf, weeksBetween,
} from './time';

/// The subset of a track the board reads. Narrower than `Track` so the
/// Rust projection can satisfy it without inventing a `created_at` it
/// would have to guess at.
export interface PlanTrackInput {
  id: UUID;
  project_id: UUID;
  title: string;
  color: string;
  sort_key: string;
}

export interface PlanSprintInput {
  id: UUID;
  project_id: UUID;
  track_id: UUID | null;
  title: string;
  starts_on: string | null;
  ends_on: string | null;
  sort_key: string;
}

export interface PlanTaskInput {
  id: UUID;
  project_id: UUID;
  track_id: UUID | null;
  sprint_id: UUID | null;
  title: string;
  section: Section;
  status: Status;
  sort_key: string;
  /// Replay derives these from recorded creation/completion ops. Legacy
  /// incoming moves can lack dates; live mode supplies the full task.
  finished_at?: string | null;
  created_at?: string | null;
  /// Rail-only, and only for *filtering* — the rail renders titles and
  /// nothing else. Optional, so the projection never has to invent them.
  external_id?: string | null;
  tag_ids?: UUID[];
}

export interface PlanInput {
  projectId: UUID;
  tracks: PlanTrackInput[];
  sprints: PlanSprintInput[];
  tasks: PlanTaskInput[];
  /// Only used by the retro band, and only completed ones.
  blocks: TimeBlock[];
  /// Local-midnight Monday of the leftmost column.
  weekStartMs: number;
  weekCount: number;
}

export interface PlanTask {
  id: UUID;
  title: string;
  done: boolean;
  section: Section;
  status: Status;
  /// Carried through so the rail can filter by text and by tag. Not
  /// rendered: a rail row is its title. Empty/null when the producer
  /// doesn't have them.
  externalId: string | null;
  tagIds: UUID[];
}

export interface PlanSprint {
  id: UUID;
  /// Derived A1/A2 badge, never stored — so scrubbing renumbers it to
  /// what it was. See `planCode`.
  code: string;
  title: string;
  color: string;
  /// Indices into `weeks`, end-exclusive. Clamped to the window.
  startWeek: number;
  endWeek: number;
  lane: number;
  lanes: number;
  /// True when the card actually starts/ends outside the window, so the
  /// edge can be drawn torn rather than square.
  clipStart: boolean;
  clipEnd: boolean;
  /// Every member task is ticked. The board's only completeness signal:
  /// a done card is dulled, exactly as a done row is in the list and a
  /// completed block is on the calendar. There is deliberately no
  /// separate progress treatment and no `3/4` readout — the checklist
  /// already says which rows are ticked, and a card sitting on the week
  /// axis already says when it runs.
  allDone: boolean;
  tasks: PlanTask[];
  doneCount: number;
  totalCount: number;
}

export interface PlanTrackRow {
  /// null on the synthetic "No track" row.
  id: UUID | null;
  title: string;
  color: string;
  sprints: PlanSprint[];
  lanes: number;
}

export interface RetroBucket {
  /// Local-midnight Monday the fortnight starts on.
  startMs: number;
  /// The same span as `YYYY-MM-DD`, end-exclusive, both Mondays — the
  /// shape `sprint.create` wants, so "promote" needs no date math of
  /// its own.
  startsOn: string;
  endsOn: string;
  label: string;
  startWeek: number;
  endWeek: number;
  clipStart: boolean;
  clipEnd: boolean;
  tasks: PlanTask[];
  doneCount: number;
  totalCount: number;
}

export interface PlanSnapshot {
  /// Local-midnight Mondays, ascending.
  weeks: number[];
  /// Index into `weeks` of the column containing "now", or -1.
  nowWeek: number;
  tracks: PlanTrackRow[];
  retro: RetroBucket[];
  inbox: PlanTask[];
}

/// Colour for the synthetic "No track" row and for cards on it.
const ORPHAN_COLOR = 'var(--ink-4)';

/// A task's track: its sprint's track if it has a sprint, else its own.
/// Applied at render time rather than mirrored into a column, so it can
/// never drift.
export function trackOf(
  task: PlanTaskInput,
  sprintById: Map<UUID, PlanSprintInput>,
): UUID | null {
  if (task.sprint_id) return sprintById.get(task.sprint_id)?.track_id ?? null;
  return task.track_id;
}

/// `A1`, `A9`, `Z1`, `AA1` — the track's letter plus the sprint's
/// ordinal within it.
///
/// Derived, not stored, and ordered by `starts_on` first, which is what
/// makes dragging a card left renumber it the way a reader of a timeline
/// expects. It also removes any need for a sprint-reorder gesture.
export function planCode(trackIdx: number, sprintIdx: number): string {
  let n = trackIdx;
  let letters = '';
  do {
    letters = String.fromCharCode(65 + (n % 26)) + letters;
    n = Math.floor(n / 26) - 1;
  } while (n >= 0);
  return `${letters}${sprintIdx + 1}`;
}

/// Assign overlapping spans to lanes so non-overlapping cards each get
/// the full row height and only actual collisions stack.
///
/// Lifted from `placeBlocks`'s cluster/flush logic (the calendar's
/// overlap layout) with the time axis swapped for the week axis. Not a
/// shared helper: the calendar buckets by day first and refactoring it
/// onto this is a separate change.
export function packLanes(
  items: { start: number; end: number }[],
): { lane: number; lanes: number }[] {
  const order = items
    .map((it, i) => ({ ...it, i }))
    .sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start) || a.i - b.i);
  const out: { lane: number; lanes: number }[] = new Array(items.length);

  let cluster: typeof order = [];
  let clusterEnd = -Infinity;
  const flush = () => {
    if (!cluster.length) return;
    const laneEnds: number[] = [];
    const assigned: { i: number; lane: number }[] = [];
    for (const it of cluster) {
      let lane = laneEnds.findIndex((end) => end <= it.start);
      if (lane === -1) {
        laneEnds.push(it.end);
        lane = laneEnds.length - 1;
      } else {
        laneEnds[lane] = it.end;
      }
      assigned.push({ i: it.i, lane });
    }
    for (const { i, lane } of assigned) out[i] = { lane, lanes: laneEnds.length };
    cluster = [];
    clusterEnd = -Infinity;
  };
  for (const it of order) {
    if (cluster.length === 0 || it.start < clusterEnd) {
      cluster.push(it);
      clusterEnd = Math.max(clusterEnd, it.end);
    } else {
      flush();
      cluster.push(it);
      clusterEnd = it.end;
    }
  }
  flush();
  return out;
}

function toPlanTask(t: PlanTaskInput): PlanTask {
  return {
    id: t.id,
    title: t.title,
    done: t.status === 'done',
    section: t.section,
    status: t.status,
    externalId: t.external_id ?? null,
    tagIds: t.tag_ids ?? [],
  };
}

/// Section order the list shows, so the inbox and the list feel like one
/// product rather than two orderings of the same rows.
const SECTION_RANK: Record<Section, number> = {
  now: 0, later: 1, recurring: 2, someday: 3, done: 4,
};

function bySectionThenSort(a: PlanTaskInput, b: PlanTaskInput): number {
  return SECTION_RANK[a.section] - SECTION_RANK[b.section]
    || (a.sort_key < b.sort_key ? -1 : a.sort_key > b.sort_key ? 1 : 0);
}

// A card's checklist is ordered by `bySectionThenSort` — the list's
// order, unchanged.
//
// It briefly sank finished rows to the foot of the card, on the
// reasoning that `task.tick` sets `status` and leaves `section` alone,
// so a ticked task still in Now leads its own card while rendering
// struck through. True, but the list does exactly the same thing and
// does it on purpose: recently-finished work stays where it is until
// somebody archives it. Sinking meant **ticking a box reordered the
// card under your cursor**, which no other surface in the app does, and
// the inconsistency cost more than the tidiness bought.

export function buildPlanSnapshot(input: PlanInput): PlanSnapshot {
  const { projectId, weekCount } = input;
  const weekStart = weekStartOf(input.weekStartMs);
  const weeks: number[] = [];
  for (let i = 0; i < weekCount; i++) {
    const d = new Date(weekStart);
    weeks.push(new Date(d.getFullYear(), d.getMonth(), d.getDate() + i * 7).getTime());
  }
  const windowEnd = weeks.length
    ? weeksBetween(weekStart, weeks[weeks.length - 1]) + 1
    : 0;

  const tracks = input.tracks
    .filter((t) => t.project_id === projectId)
    .slice()
    .sort((a, b) => (a.sort_key < b.sort_key ? -1 : a.sort_key > b.sort_key ? 1
      : a.title.localeCompare(b.title)));
  const sprints = input.sprints.filter((s) => s.project_id === projectId);
  const sprintById = new Map(sprints.map((s) => [s.id, s]));
  const tasks = input.tasks.filter((t) => t.project_id === projectId);

  const tasksBySprint = new Map<UUID, PlanTaskInput[]>();
  for (const t of tasks) {
    if (!t.sprint_id) continue;
    const arr = tasksBySprint.get(t.sprint_id) ?? [];
    arr.push(t);
    tasksBySprint.set(t.sprint_id, arr);
  }

  // Badge ordinals are per track and ordered by span, so they have to be
  // numbered before the window clips anything — a card scrolled out of
  // view must not renumber the ones still on screen.
  const trackIdxById = new Map<UUID, number>(tracks.map((t, i) => [t.id, i]));
  const ordinalBySprint = new Map<UUID, number>();
  const byTrack = new Map<UUID | null, PlanSprintInput[]>();
  for (const s of sprints) {
    const key = s.track_id && trackIdxById.has(s.track_id) ? s.track_id : null;
    const arr = byTrack.get(key) ?? [];
    arr.push(s);
    byTrack.set(key, arr);
  }
  for (const [, arr] of byTrack) {
    arr.sort((a, b) =>
      (a.starts_on ?? '9999').localeCompare(b.starts_on ?? '9999')
      || a.sort_key.localeCompare(b.sort_key)
      || a.id.localeCompare(b.id));
    arr.forEach((s, i) => ordinalBySprint.set(s.id, i));
  }

  const nowWeekStart = weekStartOf(localMidnight(Date.now()));

  const buildRow = (
    id: UUID | null,
    title: string,
    color: string,
    trackIdx: number,
  ): PlanTrackRow | null => {
    const spanned = (byTrack.get(id) ?? []).filter((s) => s.starts_on && s.ends_on);
    // Window-relative, end-exclusive. Cards entirely outside drop out.
    const placed = spanned
      .map((s) => {
        const rawStart = weeksBetween(weekStart, parseDateKey(s.starts_on!));
        const rawEnd = weeksBetween(weekStart, parseDateKey(s.ends_on!));
        return { s, rawStart, rawEnd };
      })
      .filter(({ rawStart, rawEnd }) => rawEnd > 0 && rawStart < windowEnd);
    if (placed.length === 0 && id !== null) {
      return { id, title, color, sprints: [], lanes: 0 };
    }
    if (placed.length === 0) return null;

    const lanesOf = packLanes(placed.map(({ rawStart, rawEnd }) => ({
      start: rawStart, end: rawEnd,
    })));
    const laneCount = lanesOf.reduce((m, l) => Math.max(m, l.lanes), 0);

    const out: PlanSprint[] = placed.map(({ s, rawStart, rawEnd }, i) => {
      const members = (tasksBySprint.get(s.id) ?? []).slice().sort(bySectionThenSort);
      return {
        id: s.id,
        code: planCode(trackIdx, ordinalBySprint.get(s.id) ?? 0),
        title: s.title,
        color,
        startWeek: Math.max(0, rawStart),
        endWeek: Math.min(windowEnd, rawEnd),
        lane: lanesOf[i].lane,
        lanes: laneCount,
        clipStart: rawStart < 0,
        clipEnd: rawEnd > windowEnd,
        allDone: members.length > 0 && members.every((t) => t.status === 'done'),
        tasks: members.map(toPlanTask),
        doneCount: members.filter((t) => t.status === 'done').length,
        totalCount: members.length,
      };
    });
    out.sort((a, b) => a.lane - b.lane || a.startWeek - b.startWeek);
    return { id, title, color, sprints: out, lanes: laneCount };
  };

  const rows: PlanTrackRow[] = [];
  tracks.forEach((t, i) => {
    const row = buildRow(t.id, t.title, t.color, i);
    if (row) rows.push(row);
  });
  // The orphan row exists only when there is something in it. SET NULL
  // without it would be data loss by invisibility; with it, the state is
  // self-healing — drag the cards onto a track.
  const orphan = buildRow(null, 'No track', ORPHAN_COLOR, tracks.length);
  if (orphan && orphan.sprints.length > 0) rows.push(orphan);

  // Unplaced *open* work. Both predicates are needed: `task.tick`
  // changes `status` and never `section` (the list deliberately keeps
  // recently-finished work in Now until it's archived), so filtering on
  // section alone leaves ticked tasks sitting in the rail as work still
  // to be planned. Their home is the retro band.
  const inbox = tasks
    .filter((t) => t.sprint_id === null && t.section !== 'done' && t.status !== 'done')
    .sort(bySectionThenSort)
    .map(toPlanTask);

  return {
    weeks,
    nowWeek: weeks.findIndex((ms) => ms === nowWeekStart),
    tracks: rows,
    retro: buildRetroBuckets(input),
    inbox,
  };
}

/// The reconstructed past: fortnight buckets over finished work that was
/// never planned into a sprint, so a brand-new board isn't empty on the
/// day it opens.
///
/// There is no regeneration step and nothing to refresh — it is computed
/// from current tasks and blocks on every render, so work finished today
/// shows up in today's fortnight by itself, whether or not anyone is
/// using sprints.
///
/// Derived, never materialized. Materializing ~26 rows a year per
/// project would pollute the sprint namespace and fake the provenance —
/// rows created today, dated in W20. Rendered muted and read-only in its
/// own full-width band outside every track, because a record is not a
/// plan and the two must not share a visual slot.
export function buildRetroBuckets(input: PlanInput): RetroBucket[] {
  const { projectId, weekCount } = input;
  const weekStart = weekStartOf(input.weekStartMs);
  const windowEnd = weekCount;
  // `sprint_id === null` is the load-bearing half of this predicate. The
  // band reconstructs the work that was finished *without being
  // planned*; a finished task that does sit in a sprint is already
  // rendered in its card, and counting it here too put the same task on
  // the board twice — the exact double-render the single-valued
  // `task.sprint_id` model exists to make impossible.
  //
  // It also gives the band a self-clearing rule: plan a bucket's work
  // (promote it, or drag a row into a real sprint) and it leaves.
  const tasks = input.tasks.filter((t) =>
    t.project_id === projectId && t.status === 'done' && t.sprint_id === null);
  if (tasks.length === 0) return [];

  const taskIds = new Set(tasks.map((t) => t.id));
  // Completed blocks only: a planned block is intent, not record.
  const spans = new Map<UUID, { from: number; to: number }>();
  for (const b of input.blocks) {
    if (b.state !== 'completed' || !taskIds.has(b.task_id)) continue;
    const from = Date.parse(b.start_at);
    const to = Date.parse(b.end_at);
    const cur = spans.get(b.task_id);
    spans.set(b.task_id, cur
      ? { from: Math.min(cur.from, from), to: Math.max(cur.to, to) }
      : { from, to });
  }

  const buckets = new Map<number, PlanTaskInput[]>();
  for (const t of tasks) {
    // Best evidence first. Blocks lead because they're the only source
    // that yields a *span* — a six-week task finishing last week should
    // not collapse into one fortnight — and because they're immune to
    // the clumping `finished_at` suffers when someone tidies up a
    // backlog on a Friday and stamps twenty tasks the same minute.
    const span = spans.get(t.id);
    const point = span ? null : retroPointOf(t);
    if (!span && point === null) continue;
    const from = fortnightStartOf(span ? span.from : point!);
    const to = fortnightStartOf(span ? span.to : point!);
    for (let ms = from; ms <= to; ms = addFortnight(ms)) {
      const arr = buckets.get(ms) ?? [];
      arr.push(t);
      buckets.set(ms, arr);
    }
  }

  const out: RetroBucket[] = [];
  for (const [startMs, members] of [...buckets].sort((a, b) => a[0] - b[0])) {
    const rawStart = weeksBetween(weekStart, startMs);
    const rawEnd = rawStart + 2;
    if (rawEnd <= 0 || rawStart >= windowEnd) continue;
    const sorted = members.slice().sort(bySectionThenSort);
    out.push({
      startMs,
      startsOn: fmtDateKey(startMs),
      endsOn: fmtDateKey(addFortnight(startMs)),
      label: `${isoWeekLabel(startMs)}–${isoWeekLabel(addFortnight(startMs) - 86400000)}`,
      startWeek: Math.max(0, rawStart),
      endWeek: Math.min(windowEnd, rawEnd),
      clipStart: rawStart < 0,
      clipEnd: rawEnd > windowEnd,
      tasks: sorted.map(toPlanTask),
      doneCount: sorted.length,
      totalCount: sorted.length,
    });
  }
  return out;
}

function addFortnight(ms: number): number {
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + 14).getTime();
}

/// The splitter's point branches: `finished_at` (the status flip), then
/// `created_at` for rows predating migration 0017, which deliberately
/// left it NULL and named `created_at` as the fallback.
function retroPointOf(t: PlanTaskInput): number | null {
  if (t.finished_at) return Date.parse(t.finished_at);
  if (t.created_at) return Date.parse(t.created_at);
  return null;
}
