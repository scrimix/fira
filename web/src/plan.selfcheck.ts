// Dev-only assertions for the plan board's pure logic.
//
// There is no frontend test runner here, and the risky logic is pure —
// plain data in, plain data out — so it checks itself at runtime
// instead. Imported only behind `import.meta.env.DEV`, so vite
// tree-shakes the whole file out of production.
//
// Kept out of `plan.ts` and `time.ts` so those stay clean.
//
// WEAKNESS, stated plainly: these run only when someone opens the app in
// dev or runs `pnpm visual-check` (which fails the sweep on a page
// error). That's a discipline dependency, not CI. Anyone touching
// `time.ts` or `plan.ts` must run `pnpm visual-check` before merging.

import {
  buildPlanSnapshot, buildRetroBuckets, packLanes, planCode, sprintInformation,
  type PlanInput, type PlanSprintInput, type PlanTaskInput,
} from './plan';
import {
  fmtDateKey, fortnightStartOf, isoWeekNumber, parseDateKey, weeksBetween,
} from './time';
import type { TimeBlock } from './types';
import { clampHistoryWindow, historyTicks } from './components/PlanTimeline';

let failures = 0;

function eq(label: string, got: unknown, want: unknown): void {
  const a = JSON.stringify(got);
  const b = JSON.stringify(want);
  if (a !== b) {
    failures += 1;
    console.error(`[plan.selfcheck] ${label}\n  got:  ${a}\n  want: ${b}`);
  }
}

const day = (s: string) => parseDateKey(s);

function checkTime(): void {
  // The year-boundary set `floor(dayOfYear / 7)` gets wrong.
  eq('isoWeekNumber 2026-01-01', isoWeekNumber(day('2026-01-01')), 1);
  eq('isoWeekNumber 2027-01-01', isoWeekNumber(day('2027-01-01')), 53);
  eq('isoWeekNumber 2024-12-30', isoWeekNumber(day('2024-12-30')), 1);
  eq('isoWeekNumber 2026-12-31', isoWeekNumber(day('2026-12-31')), 53);
  eq('isoWeekNumber mid-year', isoWeekNumber(day('2026-09-14')), 38);

  // A local midnight must round-trip to the same calendar day, and a
  // Monday must stay a Monday — `toISOString().slice(0,10)` yields the
  // previous Sunday for anyone east of UTC.
  for (const key of ['2026-10-05', '2026-01-01', '2026-12-31', '2026-03-30']) {
    eq(`fmtDateKey round-trips ${key}`, fmtDateKey(parseDateKey(key)), key);
    if (key === '2026-10-05' || key === '2026-03-30') {
      eq(`${key} is a Monday after round-trip`, new Date(parseDateKey(key)).getDay(), 1);
    }
  }

  // Spans crossing a DST transition are 2.9583 weeks of elapsed ms; the
  // board needs an integer.
  eq('weeksBetween across spring DST', weeksBetween(day('2026-03-23'), day('2026-04-13')), 3);
  eq('weeksBetween across autumn DST', weeksBetween(day('2026-10-19'), day('2026-11-09')), 3);
  eq('weeksBetween is signed', weeksBetween(day('2026-10-19'), day('2026-10-05')), -2);
  eq('weeksBetween mid-week anchors to Monday',
    weeksBetween(day('2026-10-07'), day('2026-10-15')), 1);

  // Even-ISO-week anchoring, so every project in a workspace agrees on
  // where a fortnight begins.
  const fn = fortnightStartOf(day('2026-09-16'));
  eq('fortnightStartOf lands on an even ISO week', isoWeekNumber(fn) % 2, 0);
  eq('fortnightStartOf lands on a Monday', new Date(fn).getDay(), 1);
  eq('two dates in one fortnight agree',
    fortnightStartOf(day('2026-09-14')), fortnightStartOf(day('2026-09-26')));
  eq('the next fortnight does not',
    fortnightStartOf(day('2026-09-28')) !== fortnightStartOf(day('2026-09-14')), true);
}

function checkPackLanes(): void {
  const lanes = (items: [number, number][]) =>
    packLanes(items.map(([start, end]) => ({ start, end })));

  eq('disjoint spans share lane 0',
    lanes([[0, 2], [2, 4]]), [{ lane: 0, lanes: 1 }, { lane: 0, lanes: 1 }]);
  eq('overlapping spans stack',
    lanes([[0, 3], [1, 4]]), [{ lane: 0, lanes: 2 }, { lane: 1, lanes: 2 }]);
  eq('three-deep overlap',
    lanes([[0, 4], [1, 5], [2, 6]]),
    [{ lane: 0, lanes: 3 }, { lane: 1, lanes: 3 }, { lane: 2, lanes: 3 }]);
  // A nested span goes beside its container, not inside it.
  eq('nested span', lanes([[0, 6], [2, 3]]), [{ lane: 0, lanes: 2 }, { lane: 1, lanes: 2 }]);
  // Two clusters must not inflate each other's lane count: the whole
  // point of clustering is that a collision over there doesn't halve the
  // card height over here.
  eq('separate clusters keep their own lane counts',
    lanes([[0, 2], [0, 2], [5, 7]]),
    [{ lane: 0, lanes: 2 }, { lane: 1, lanes: 2 }, { lane: 0, lanes: 1 }]);
  eq('empty', lanes([]), []);
}

function checkPlanCode(): void {
  eq('planCode A1', planCode(0, 0), 'A1');
  eq('planCode A9', planCode(0, 8), 'A9');
  eq('planCode A10', planCode(0, 9), 'A10');
  eq('planCode Z1', planCode(25, 0), 'Z1');
  eq('planCode AA1', planCode(26, 0), 'AA1');
  eq('planCode AB2', planCode(27, 1), 'AB2');
}

// --- fixtures ---------------------------------------------------------

const PROJ = 'p1';
const MON = '2026-10-05';

function task(over: Partial<PlanTaskInput> & { id: string }): PlanTaskInput {
  return {
    project_id: PROJ, track_id: null, sprint_id: null, title: over.id,
    section: 'later', status: 'todo', sort_key: 'M', ...over,
  };
}

function sprint(over: Partial<PlanSprintInput> & { id: string }): PlanSprintInput {
  return {
    project_id: PROJ, track_id: null, title: over.id,
    starts_on: null, ends_on: null, sort_key: 'M', ...over,
  };
}

function block(taskId: string, from: string, to: string, state = 'completed'): TimeBlock {
  return {
    id: `b-${taskId}-${from}`, task_id: taskId, user_id: 'u1',
    start_at: new Date(parseDateKey(from)).toISOString(),
    end_at: new Date(parseDateKey(to)).toISOString(),
    state: state as TimeBlock['state'],
    jira_worklog_id: null, jira_sync_error: null,
  };
}

function input(over: Partial<PlanInput>): PlanInput {
  return {
    projectId: PROJ, tracks: [], sprints: [], tasks: [], blocks: [],
    weekStartMs: parseDateKey(MON), weekCount: 8, ...over,
  };
}

function checkSnapshot(): void {
  const tracks = [
    { id: 'tr1', project_id: PROJ, title: 'Arch', color: '#0F766E', sort_key: 'M000' },
    { id: 'tr2', project_id: PROJ, title: 'Ops', color: '#B45309', sort_key: 'M001' },
  ];

  // A task with BOTH a sprint and its own track_id resolves to the
  // sprint's track. That precedence is the whole reason the chain is
  // single-valued, so it gets its own assertion.
  const s1 = sprint({ id: 's1', track_id: 'tr2', starts_on: MON, ends_on: '2026-10-19' });
  const snap = buildPlanSnapshot(input({
    tracks,
    sprints: [s1],
    tasks: [task({ id: 't1', track_id: 'tr1', sprint_id: 's1' })],
  }));
  const ops = snap.tracks.find((r) => r.id === 'tr2')!;
  eq('the card is on its sprint\'s track, not the task\'s', ops.sprints.length, 1);
  eq('the card carries the task', ops.sprints[0].tasks.map((t) => t.id), ['t1']);
  eq('the other track is empty',
    snap.tracks.find((r) => r.id === 'tr1')!.sprints.length, 0);

  // End-exclusive span: Mon 5 Oct -> Mon 19 Oct is two columns, not three.
  eq('a two-week span is two columns',
    [ops.sprints[0].startWeek, ops.sprints[0].endWeek], [0, 2]);

  // Window clipping.
  const clipped = buildPlanSnapshot(input({
    tracks,
    weekCount: 4,
    sprints: [sprint({
      id: 's2', track_id: 'tr1', starts_on: '2026-09-21', ends_on: '2026-11-16',
    })],
  }));
  const card = clipped.tracks.find((r) => r.id === 'tr1')!.sprints[0];
  eq('clipStart set when the span starts before the window', card.clipStart, true);
  eq('clipEnd set when the span ends after it', card.clipEnd, true);
  eq('clipped card is clamped to the window', [card.startWeek, card.endWeek], [0, 4]);

  // A sprint entirely outside the window drops out rather than being
  // clamped to a zero-width sliver.
  eq('a span before the window is not rendered',
    buildPlanSnapshot(input({
      tracks,
      sprints: [sprint({ id: 's3', track_id: 'tr1', starts_on: '2026-08-03', ends_on: '2026-08-17' })],
    })).tracks.find((r) => r.id === 'tr1')!.sprints.length,
    0);

  // Orphans get a synthetic row, and only when there are any.
  eq('no orphan row when nothing is orphaned',
    snap.tracks.some((r) => r.id === null), false);
  const orphaned = buildPlanSnapshot(input({
    tracks,
    sprints: [sprint({ id: 's4', track_id: null, starts_on: MON, ends_on: '2026-10-19' })],
  }));
  eq('an orphan row appears when a sprint has no track',
    orphaned.tracks.filter((r) => r.id === null).length, 1);
  // A track_id pointing at a track in another project is as orphaned as
  // a null one — it can't render in a row that isn't there.
  eq('an unresolvable track_id orphans too',
    buildPlanSnapshot(input({
      tracks,
      sprints: [sprint({ id: 's5', track_id: 'gone', starts_on: MON, ends_on: '2026-10-19' })],
    })).tracks.filter((r) => r.id === null).length,
    1);

  // Counters are status-based, never time math.
  const counted = buildPlanSnapshot(input({
    tracks,
    sprints: [sprint({ id: 's6', track_id: 'tr1', starts_on: MON, ends_on: '2026-10-19' })],
    tasks: [
      task({ id: 'd1', sprint_id: 's6', status: 'done', section: 'done' }),
      task({ id: 'd2', sprint_id: 's6', status: 'done', section: 'done' }),
      task({ id: 'o1', sprint_id: 's6' }),
    ],
  })).tracks.find((r) => r.id === 'tr1')!.sprints[0];
  eq('counter is done/total', [counted.doneCount, counted.totalCount], [2, 3]);
  eq('done tasks stay in the card', counted.tasks.length, 3);

  // Badge codes: per track, ordered by span, so dragging a card left
  // renumbers it. Numbered before clipping, so scrolling doesn't.
  const coded = buildPlanSnapshot(input({
    tracks,
    sprints: [
      sprint({ id: 'late', track_id: 'tr1', starts_on: '2026-10-19', ends_on: '2026-11-02' }),
      sprint({ id: 'early', track_id: 'tr1', starts_on: MON, ends_on: '2026-10-19' }),
      sprint({ id: 'other', track_id: 'tr2', starts_on: MON, ends_on: '2026-10-19' }),
    ],
  }));
  const byId = new Map(
    coded.tracks.flatMap((r) => r.sprints).map((s) => [s.id, s.code]),
  );
  eq('earliest card on the first track is A1', byId.get('early'), 'A1');
  eq('the next one along is A2', byId.get('late'), 'A2');
  eq('the second track restarts at B1', byId.get('other'), 'B1');

  // The inbox: unplaced, not done, ordered as the list orders.
  const inbox = buildPlanSnapshot(input({
    tracks,
    sprints: [sprint({ id: 's7', track_id: 'tr1', starts_on: MON, ends_on: '2026-10-19' })],
    tasks: [
      task({ id: 'later', section: 'later', sort_key: 'M001' }),
      task({ id: 'now', section: 'now', sort_key: 'M002' }),
      task({ id: 'placed', sprint_id: 's7' }),
      task({ id: 'archived', status: 'done', section: 'done' }),
      // Ticked but not archived. `task.tick` sets status and leaves
      // section alone, so a section-only filter would leave this in
      // the rail as work still to be planned.
      task({ id: 'ticked', status: 'done', section: 'now' }),
    ],
  })).inbox;
  eq('inbox excludes placed, archived and merely-ticked tasks',
    inbox.map((t) => t.id), ['now', 'later']);

  // Only this project's rows.
  eq('another project\'s sprint is ignored',
    buildPlanSnapshot(input({
      tracks,
      sprints: [{ ...sprint({ id: 's8', track_id: 'tr1', starts_on: MON, ends_on: '2026-10-19' }), project_id: 'p2' }],
    })).tracks.find((r) => r.id === 'tr1')!.sprints.length,
    0);

  // An unspanned sprint is representable and simply doesn't render.
  eq('a sprint with no span does not render',
    buildPlanSnapshot(input({
      tracks, sprints: [sprint({ id: 's9', track_id: 'tr1' })],
    })).tracks.find((r) => r.id === 'tr1')!.sprints.length,
    0);
}

function checkRetro(): void {
  const base = { tracks: [], sprints: [], weekCount: 12, weekStartMs: parseDateKey('2026-08-31') };

  // Splitter precedence. A task with BOTH blocks and finished_at must use
  // the block *span*: blocks are the only source that yields a range, and
  // they're immune to the clumping finished_at suffers when someone
  // archives twenty tasks in one minute.
  const spanning = buildRetroBuckets(input({
    ...base,
    tasks: [task({
      id: 'spanned', status: 'done', section: 'done',
      finished_at: new Date(parseDateKey('2026-10-05')).toISOString(),
      created_at: new Date(parseDateKey('2026-01-01')).toISOString(),
    })],
    blocks: [
      block('spanned', '2026-09-07', '2026-09-08'),
      block('spanned', '2026-09-28', '2026-09-29'),
    ],
  }));
  eq('a block span covers every fortnight it touches', spanning.length >= 2, true);
  eq('the span starts at the first block\'s fortnight',
    spanning[0].startMs, fortnightStartOf(parseDateKey('2026-09-07')));

  // finished_at when there are no completed blocks.
  const flipped = buildRetroBuckets(input({
    ...base,
    tasks: [task({
      id: 'flipped', status: 'done', section: 'done',
      finished_at: new Date(parseDateKey('2026-09-21')).toISOString(),
      created_at: new Date(parseDateKey('2026-01-01')).toISOString(),
    })],
    // A *planned* block is intent, not record, so it must not count.
    blocks: [block('flipped', '2026-09-07', '2026-09-08', 'planned')],
  }));
  eq('a blocks-free task lands on its finished_at point', flipped.length, 1);
  eq('and in that fortnight',
    flipped[0].startMs, fortnightStartOf(parseDateKey('2026-09-21')));

  // created_at for rows predating migration 0017, which left
  // finished_at NULL and named created_at as the fallback.
  const legacy = buildRetroBuckets(input({
    ...base,
    tasks: [task({
      id: 'legacy', status: 'done', section: 'done',
      finished_at: null,
      created_at: new Date(parseDateKey('2026-09-21')).toISOString(),
    })],
  }));
  eq('a pre-0017 task falls back to created_at', legacy.length, 1);
  eq('and in that fortnight',
    legacy[0].startMs, fortnightStartOf(parseDateKey('2026-09-21')));

  // Open tasks are not a record of finished work.
  eq('an open task is not in the band',
    buildRetroBuckets(input({
      ...base,
      tasks: [task({ id: 'open' })],
      blocks: [block('open', '2026-09-07', '2026-09-08')],
    })).length,
    0);

  // Finished work that IS in a sprint belongs to its card, not the band.
  // Counting it in both put the same task on the board twice.
  eq('a placed done task is not in the band',
    buildRetroBuckets(input({
      ...base,
      sprints: [sprint({ id: 'sp', starts_on: '2026-09-07', ends_on: '2026-09-21' })],
      tasks: [task({
        id: 'placed-done', sprint_id: 'sp', status: 'done', section: 'done',
        finished_at: new Date(parseDateKey('2026-09-21')).toISOString(),
      })],
    })).length,
    0);

  // The promote span: Monday to Monday, end-exclusive, so sprint.create
  // can take it verbatim and the schema's ISODOW CHECKs pass.
  const promotable = buildRetroBuckets(input({
    ...base,
    tasks: [task({
      id: 'p1', status: 'done', section: 'done',
      finished_at: new Date(parseDateKey('2026-09-21')).toISOString(),
    })],
  }))[0];
  eq('the bucket span starts on its fortnight Monday',
    promotable.startsOn, fmtDateKey(fortnightStartOf(parseDateKey('2026-09-21'))));
  // weeksBetween, not raw ms: a fortnight that straddles a DST change
  // is not 14 x 86400000 ms long.
  eq('and ends a fortnight later, exclusive',
    weeksBetween(parseDateKey(promotable.startsOn), parseDateKey(promotable.endsOn)), 2);

  // No evidence at all: skipped rather than bucketed at the epoch.
  eq('a task with no timestamps is skipped',
    buildRetroBuckets(input({
      ...base,
      tasks: [task({ id: 'bare', status: 'done', section: 'done' })],
    })).length,
    0);
}

function checkHistory(): void {
  const months = historyTicks(day('2026-01-15'), day('2026-06-15'));
  eq('history month ticks use calendar boundaries', months.every(({ at }) => new Date(at).getDate() === 1), true);
  const years = historyTicks(day('2020-01-01'), day('2030-01-01'));
  eq('history long ranges use year labels', years.every(({ label }) => /^\d{4}$/.test(label)), true);
  eq('history year ticks are not empty', years.length > 0, true);
  eq('history zoom clamps left boundary', clampHistoryWindow(-5000, 2000, 0, 10000), { start: 0, end: 2000 });
  eq('history zoom clamps right boundary', clampHistoryWindow(9500, 2000, 0, 10000), { start: 8000, end: 10000 });
  eq('history zoom fits full range', clampHistoryWindow(0, 20000, 0, 10000), { start: 0, end: 10000 });
}

function checkSprintInformation(): void {
  // Two weeks across the spring DST transition still have 80h of capacity.
  const span = sprint({ id: 'metrics', starts_on: '2026-03-23', ends_on: '2026-04-06' });
  const members = [task({ id: 'a', estimate_min: 600 }), task({ id: 'b', estimate_min: 3000 }), task({ id: 'c' })];
  const info = sprintInformation(span, members, [
    block('a', '2026-03-24', '2026-03-25'),
    block('b', '2026-03-22', '2026-03-24', 'planned'),
    block('a', '2026-04-05', '2026-04-07'),
    block('c', '2026-03-22', '2026-04-07'),
    block('a', '2026-03-23', '2026-04-06'),
    block('unrelated', '2026-03-22', '2026-03-24'),
    block('a', '2026-04-08', '2026-04-07'),
  ])!;
  eq('sprint capacity ignores DST hour changes', info.capacityMinutes, 80 * 60);
  eq('sprint load sums member estimates', info.estimatedMinutes, 60 * 60);
  eq('sprint tracks missing estimates', info.missingEstimates, 1);
  eq('sprint excludes in-range, unrelated and invalid blocks', info.outsideBlocks, 3);
  eq('sprint outside distinct tasks', info.outsideTasks, 3);
  eq('sprint counts only logged portions outside', info.loggedOutsideMinutes, 72 * 60);
  eq('sprint separates planned outside portions', info.plannedOutsideMinutes, 24 * 60);
  eq('sprint lists tasks and exact before/after portions, splitting a spanning block',
    info.outsidePortions.map(({ taskId, taskTitle, side, state, from, to }) => ({ taskId, taskTitle, side, state, from, to })), [
      { taskId: 'b', taskTitle: members[1].title, side: 'before', state: 'planned', from: day('2026-03-22'), to: day('2026-03-23') },
      { taskId: 'c', taskTitle: members[2].title, side: 'before', state: 'completed', from: day('2026-03-22'), to: day('2026-03-23') },
      { taskId: 'a', taskTitle: members[0].title, side: 'after', state: 'completed', from: day('2026-04-06'), to: day('2026-04-07') },
      { taskId: 'c', taskTitle: members[2].title, side: 'after', state: 'completed', from: day('2026-04-06'), to: day('2026-04-07') },
    ]);
  const clipped = buildPlanSnapshot(input({
    sprints: [span], tasks: members.map((t) => ({ ...t, sprint_id: span.id })),
    weekStartMs: day('2026-03-30'), weekCount: 1,
  }));
  eq('viewport clipping does not reduce sprint capacity', clipped.tracks[0].sprints[0].information?.capacityMinutes, 80 * 60);
  const historical = buildPlanSnapshot(input({ sprints: [span], tasks: members,
    timeDataAvailable: false, weekStartMs: day('2026-03-23') }));
  eq('history does not fabricate missing time data', historical.tracks[0].sprints[0].information, null);
}

export function runPlanSelfCheck(): void {
  checkTime();
  checkPackLanes();
  checkPlanCode();
  checkSnapshot();
  checkRetro();
  checkHistory();
  checkSprintInformation();
  if (failures > 0) {
    // Thrown, not logged: visual-check.mjs watches `pageerror` and fails
    // the sweep on one, which is the only automation that sees this.
    throw new Error(`[plan.selfcheck] ${failures} assertion(s) failed`);
  }
  console.info('[plan.selfcheck] ok');
}
