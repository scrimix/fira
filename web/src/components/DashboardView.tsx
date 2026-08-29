// The month dashboard: where did my hours go, and am I keeping my
// commitments.
//
// Personal stats only. `activePersonId` is deliberately ignored — this
// surface is always about *your* blocks, so the aggregator filters to
// `meId` and there is no person picker.
//
// Everything is derived client-side from data bootstrap already ships.
// When `/api/stats/month` lands, only the `monthStats` call changes; the
// rendering below reads the same shape either way.
//
// Form choices, in the order the data's job decided them:
//   - "how much did I do this month" is one headline number → a hero
//     figure, not a chart.
//   - the supporting numbers are a KPI row, not more charts.
//   - hours per day over a month is magnitude on a grid → a calendar
//     heatmap on a single sequential hue, with a scale legend.
//   - project / tag / workspace splits are magnitude comparisons →
//     horizontal bars. Not a pie: the reader's job is "is Atlas bigger
//     than Helix", which is a length comparison, and the tag list runs
//     long and sums past 100%.
//
// One cut per level, no picker: the workspace splits by project, and
// tags are only shown inside a project. See the Bars call below.

import { useMemo, useState } from 'react';
import { ChevronLeft, Plus } from 'lucide-react';
import { useFira } from '../store';
import { useIsMobile } from '../hooks';
import {
  DAY_LABELS,
  fmtMin,
  fmtMonth,
  localMidnight,
  monthRangeFor,
  todayMidnight,
  weekStartOf,
  weekdayGridFor,
} from '../time';
import type { MonthCell } from '../time';
import {
  goalMetCount,
  goalStreak,
  monthStats,
  otherWorkspaceBuckets,
  scoreGoal,
  tasksByHours,
} from '../stats';
import type { Bucket, StatsInput } from '../stats';
import type { Goal, UUID } from '../types';
import { MonthGrid, ScaleLegend, WeekStrip } from './MonthGrid';
import type { GridCell, HoverPayload } from './MonthGrid';
import { ProjectIcon } from './ProjectIcon';

/// Hours-per-day buckets for the heatmap ramp. Quantized rather than
/// continuous so the grid reads as a small number of distinguishable
/// steps — a smooth gradient over 31 cells is pretty and unreadable, and
/// a legend can't label it.
const HOUR_STEPS = [
  { fill: 0.22, label: '<2h' },
  { fill: 0.45, label: '2-4h' },
  { fill: 0.72, label: '4-6h' },
  { fill: 1, label: '6h+' },
];
function hoursFill(min: number): number {
  if (min <= 0) return 0;
  const h = min / 60;
  if (h < 2) return HOUR_STEPS[0].fill;
  if (h < 4) return HOUR_STEPS[1].fill;
  if (h < 6) return HOUR_STEPS[2].fill;
  return HOUR_STEPS[3].fill;
}

const MONTH_SHORT = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const fmtDay = (ms: number) => {
  const d = new Date(ms);
  return `${DAY_LABELS[(d.getDay() + 6) % 7][0]}${DAY_LABELS[(d.getDay() + 6) % 7].slice(1).toLowerCase()} ${d.getDate()} ${MONTH_SHORT[d.getMonth()]}`;
};

export function DashboardView() {
  const meId = useFira((s) => s.meId);
  const blocks = useFira((s) => s.blocks);
  const tasks = useFira((s) => s.tasks);
  const projects = useFira((s) => s.projects);
  const tags = useFira((s) => s.tags);
  const goals = useFira((s) => s.goals);
  const monthOffset = useFira((s) => s.monthOffset);
  const setMonthOffset = useFira((s) => s.setMonthOffset);
  const dashboardProjectId = useFira((s) => s.dashboardProjectId);
  const setDashboardProject = useFira((s) => s.setDashboardProject);
  const setView = useFira((s) => s.setView);
  const setWeekOffset = useFira((s) => s.setWeekOffset);
  const setDayOffset = useFira((s) => s.setDayOffset);
  const openGoalModal = useFira((s) => s.openGoalModal);

  // Other-workspace overlay. Exactly one of these is ever populated: the
  // server returns the personal side when you're in a team workspace and
  // the work side when you're in your personal one.
  const personalBlocks = useFira((s) => s.personalBlocks);
  const personalTasks = useFira((s) => s.personalTasks);
  const workBlocks = useFira((s) => s.workBlocks);
  const workTasks = useFira((s) => s.workTasks);

  const isMobile = useIsMobile();
  const [tip, setTip] = useState<HoverPayload | null>(null);

  const scopedProject = projects.find((p) => p.id === dashboardProjectId) ?? null;

  const input: StatsInput = useMemo(() => ({
    meId, blocks, tasks, projects, tags, monthOffset, projectId: dashboardProjectId,
  }), [meId, blocks, tasks, projects, tags, monthOffset, dashboardProjectId]);

  const stats = useMemo(() => monthStats(input), [input]);
  const cells = useMemo(() => weekdayGridFor(monthOffset), [monthOffset]);
  const byDay = useMemo(() => new Map(stats.by_day.map((d) => [d.ms, d])), [stats]);

  const others = useMemo(() => {
    const inPersonal = personalBlocks.length === 0 && workBlocks.length > 0;
    return otherWorkspaceBuckets({
      meId,
      monthOffset,
      blocks: inPersonal ? workBlocks : personalBlocks,
      tasks: inPersonal ? workTasks : personalTasks,
      fallbackLabel: 'Personal',
    });
  }, [meId, monthOffset, personalBlocks, personalTasks, workBlocks, workTasks]);

  const today = todayMidnight();
  const { start, end } = monthRangeFor(monthOffset);
  const todayInMonth = today >= start && today < end;
  const prevMonthName = fmtMonth(monthOffset - 1).split(' ')[0];

  // Clicking a day jumps to the calendar at that date. Desktop steps the
  // week cursor, mobile the day cursor — each layout owns its own, so
  // setting the wrong one silently lands on the wrong screen.
  const jumpToDay = (ms: number) => {
    if (isMobile) {
      setDayOffset(Math.round((ms - today) / 86400000));
    } else {
      setWeekOffset(Math.round((weekStartOf(ms) - weekStartOf(today)) / (7 * 86400000)));
    }
    setView('calendar');
  };

  const heatCell = (c: MonthCell): GridCell => {
    const d = byDay.get(c.ms);
    if (!d) return { fill: 0, tip: `${fmtDay(c.ms)} — outside ${fmtMonth(monthOffset).split(' ')[0]}` };
    // Planned time is hatched, never solid, and only from today forward —
    // a past day's leftover plan is not a claim about what happened.
    const pending = d.done_min === 0 && d.planned_min > 0 && c.ms >= today;
    const parts = [
      `${fmtMin(d.done_min)} done`,
      d.planned_min > 0 ? `${fmtMin(d.planned_min)} planned` : null,
      d.top_project ? `mostly ${d.top_project.label}` : null,
    ].filter(Boolean);
    return {
      fill: pending ? hoursFill(d.planned_min) : hoursFill(d.done_min),
      pending,
      tip: `${fmtDay(c.ms)} — ${parts.join(' · ')}`,
    };
  };

  return (
    <div className="dash" onMouseLeave={() => setTip(null)}>
      <div className="cal-toolbar dash-toolbar">
        <span className="week-nav">
          <button className="week-nav-btn" onClick={() => setMonthOffset(monthOffset - 1)} title="Previous month">‹</button>
          <button
            className="week-nav-btn week-nav-today"
            data-active={monthOffset === 0}
            onClick={() => setMonthOffset(0)}
          >
            Today
          </button>
          <button className="week-nav-btn" onClick={() => setMonthOffset(monthOffset + 1)} title="Next month">›</button>
        </span>
        {scopedProject && (
          <>
            {/* Sits to the *right* of the month stepper, and carries a
              * word. An icon-only chevron immediately left of the
              * stepper's own `‹` was two adjacent chevrons meaning
              * different things. */}
            <button
              className="dash-back"
              onClick={() => setDashboardProject(null)}
              title="Back to all projects"
            >
              <ChevronLeft size={13} strokeWidth={2} />
              All projects
            </button>
            <span className="dash-scope">
              <ProjectIcon name={scopedProject.icon} color={scopedProject.color} size={13} />
              {scopedProject.title}
            </span>
          </>
        )}
      </div>

      <div className="dash-scroll">
        <div className="dash-col">
          {/* The month's headline is one number, so it gets the hero
            * treatment rather than being one tile among six equals. */}
          <header className="dash-hero">
            <div className="dash-hero-fig">{fmtMin(stats.done_min)}</div>
            <div className="dash-hero-sub">
              completed in {fmtMonth(monthOffset)}
              {scopedProject && <> on <strong>{scopedProject.title}</strong></>}
              {stats.prev_done_min != null && (
                <span
                  className="dash-delta"
                  data-dir={stats.done_min >= stats.prev_done_min ? 'up' : 'down'}
                >
                  {fmtDelta(stats.done_min - stats.prev_done_min)} vs {prevMonthName}
                </span>
              )}
            </div>
          </header>

          <div className="dash-kpis">
            <Kpi label="Planned ahead" value={fmtMin(stats.planned_min)} />
            <Kpi label="Active days" value={`${stats.active_days}`} sub={`of ${stats.by_day.length}`} />
            <Kpi label="Avg / active day" value={fmtMin(Math.round(stats.avg_active_min))} />
          </div>

          <div className="dash-grid">
            <section className="dash-panel">
              <div className="dash-h-row">
                <h3 className="dash-h">Hours per day</h3>
              </div>
              {/* The cells encode magnitude in color and the numbers in
                * them are *dates*, so the key is not optional — without
                * it a reader has no way to know what a shade is worth. */}
              <MonthGrid
                cells={cells}
                cellFor={heatCell}
                today={todayInMonth ? today : undefined}
                onPick={jumpToDay}
                onHover={setTip}
                onLeave={() => setTip(null)}
              />
              <ScaleLegend steps={HOUR_STEPS} />
              <p className="dash-note">
                Each square is a day of {fmtMonth(monthOffset).split(' ')[0]}; the small
                number is the date. Darker means more hours completed. Hatched is
                planned but not done yet. Click a day to open it in the calendar.
              </p>
            </section>

            <section className="dash-panel">
              <div className="dash-h-row">
                <h3 className="dash-h">
                  {scopedProject ? `Tags in ${scopedProject.title}` : 'Where the time went'}
                </h3>
                {/* The way out sits with the scoped content, not only up
                  * in the toolbar — this heading is where a reader is
                  * looking when they decide they're done with it. */}
                {scopedProject && (
                  <button
                    className="dash-back dash-back-inline"
                    onClick={() => setDashboardProject(null)}
                    title="Back to all projects"
                  >
                    <ChevronLeft size={13} strokeWidth={2} />
                    All projects
                  </button>
                )}
              </div>

              {/* One cut per level, no picker. The workspace splits by
                * project; tags only make sense *inside* one, because
                * they're project-scoped rows — a workspace-wide tag list
                * has to merge same-named tags from different projects,
                * which silently fuses things that were never the same
                * tag. Drilling into a project sidesteps that entirely. */}
              <Bars
                buckets={scopedProject ? stats.by_tag : stats.by_project}
                total={stats.done_min + stats.planned_min}
                onPick={scopedProject ? undefined : (key) => setDashboardProject(key as UUID)}
                showPct={!scopedProject}
              />

              {scopedProject ? (
                <p className="dash-note">
                  A block counts toward every tag on its task, so these can add up to
                  more than the project's total — that's why there are no percentages
                  here.
                </p>
              ) : (
                <p className="dash-note">
                  Click a project for its hours, its tags and where they went.
                </p>
              )}

              {scopedProject && <TasksByHours input={input} />}

              {!scopedProject && others.length > 0 && (
                <>
                  <h3 className="dash-h dash-h-sub">Other workspaces</h3>
                  <Bars buckets={others} total={0} showPct={false} />
                </>
              )}
            </section>
          </div>

          <section className="dash-section">
            <div className="dash-h-row">
              <h3 className="dash-h">Goals</h3>
              <button className="dash-chip dash-chip-add" onClick={() => openGoalModal(null)}>
                <Plus size={12} strokeWidth={2} /> Add goal
              </button>
            </div>
            {goals.length === 0 ? (
              <p className="dash-empty">
                No goals yet. A goal is a filter over your blocks with a daily or
                weekly target — "1h of deep work a day", or "at most 30m of meetings".
              </p>
            ) : (
              <div className="goal-grid">
                {goals.map((g) => (
                  <GoalCard
                    key={g.id}
                    goal={g}
                    input={input}
                    cells={cells}
                    today={today}
                    todayInMonth={todayInMonth}
                    onEdit={() => openGoalModal(g.id)}
                    onPick={jumpToDay}
                    onHover={setTip}
                    onLeave={() => setTip(null)}
                  />
                ))}
              </div>
            )}
          </section>
        </div>
      </div>

      {tip && (
        <div className="dash-tip" style={{ left: tip.x, top: tip.y }} role="status">
          {tip.text}
        </div>
      )}
    </div>
  );
}

function fmtDelta(min: number): string {
  return `${min >= 0 ? '+' : '−'}${fmtMin(Math.abs(min))}`;
}

function Kpi({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="dash-kpi">
      <div className="dash-kpi-v">{value}{sub && <span> {sub}</span>}</div>
      <div className="dash-kpi-l">{label}</div>
    </div>
  );
}

function Bars({
  buckets,
  total,
  onPick,
  showPct = true,
}: {
  buckets: Bucket[];
  total: number;
  onPick?: (key: string) => void;
  /// Off for the tag cut. A block on a task with three tags counts in
  /// full toward all three — the honest reading of "how much time
  /// touched #auth" — so tag buckets sum to more than the month. A
  /// "% of total" label next to them invites a sum that means nothing.
  showPct?: boolean;
}) {
  // Scale against the biggest bar, not the month total: with five
  // projects every bar would otherwise sit under 30% wide and the
  // comparison — the actual point — gets harder to read.
  const max = Math.max(...buckets.map((b) => b.done_min + b.planned_min), 1);
  if (buckets.length === 0) return <p className="dash-empty">Nothing tracked this month.</p>;
  return (
    <div className="dash-bars">
      {buckets.map((b) => {
        const sum = b.done_min + b.planned_min;
        const pct = total > 0 ? Math.round((sum / total) * 100) : 0;
        return (
          <div
            key={b.key}
            className="dash-bar-row"
            data-clickable={onPick ? 'true' : undefined}
            onClick={onPick ? () => onPick(b.key) : undefined}
          >
            <div className="dash-bar-label">{b.label}</div>
            <div className="dash-bar-track">
              <div
                className="dash-bar-done"
                style={{ width: `${(b.done_min / max) * 100}%`, background: b.color }}
              />
              {b.planned_min > 0 && (
                <div
                  className="dash-bar-planned"
                  style={{ width: `${(b.planned_min / max) * 100}%`, background: b.color }}
                />
              )}
            </div>
            <div className="dash-bar-val">
              {fmtMin(sum)}{showPct && <span> · {pct}%</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/// Where the project's hours actually went, biggest first. Capped
/// rather than scrolled — a scroll area inside a panel hides its own
/// contents — but the cap is stated, so a project whose seventh task
/// also matters isn't quietly truncated away.
///
/// Deliberately not called "top tasks": hours are a cost, and the row
/// at the head of this list is as often a problem as an achievement.
const TASK_ROWS = 6;

function TasksByHours({ input }: { input: StatsInput }) {
  const all = useMemo(() => tasksByHours(input), [input]);
  const shown = all.slice(0, TASK_ROWS);
  const hidden = all.length - shown.length;
  if (all.length === 0) return null;
  return (
    <>
      <h3 className="dash-h dash-h-sub">Hours by task</h3>
      <ul className="dash-tasks">
        {shown.map(({ task, done_min }) => (
          <li key={task.id}>
            <span className="dash-task-title">{task.title}</span>
            <span className="dash-task-min">{fmtMin(done_min)}</span>
          </li>
        ))}
      </ul>
      {hidden > 0 && (
        <p className="dash-note">
          + {hidden} more task{hidden === 1 ? '' : 's'} with time this month.
        </p>
      )}
    </>
  );
}

function GoalCard({
  goal, input, cells, today, todayInMonth, onEdit, onPick, onHover, onLeave,
}: {
  goal: Goal;
  input: StatsInput;
  cells: MonthCell[];
  today: number;
  todayInMonth: boolean;
  onEdit: () => void;
  onPick: (ms: number) => void;
  onHover: (p: HoverPayload) => void;
  onLeave: () => void;
}) {
  const periods = useMemo(() => scoreGoal(goal, input, today), [goal, input, today]);
  const byPeriod = useMemo(() => new Map(periods.map((p) => [p.ms, p])), [periods]);
  const { met, total } = goalMetCount(periods);
  const streak = goalStreak(periods, today, goal.cadence);
  const weekly = goal.cadence === 'weekly';
  const cap = goal.direction === 'at_most';

  const cellFor = (ms: number): GridCell => {
    const p = byPeriod.get(ms);
    if (!p) return { fill: 0 };
    const state = p.future ? 'upcoming' : p.over ? 'over the cap' : p.met ? 'met' : 'short';
    return {
      fill: p.fill,
      pending: p.future,
      over: p.over,
      tip: `${weekly ? 'Week of ' : ''}${fmtDay(p.ms)} — ${fmtMin(p.total_min)}`
        + (goal.target_min ? ` of ${fmtMin(goal.target_min)}` : '')
        + ` · ${state}`,
    };
  };

  const targetLabel = goal.target_min == null
    ? 'any block counts'
    : `${cap ? 'at most' : 'at least'} ${fmtMin(goal.target_min)} ${goal.cadence}`;

  return (
    <div className="goal-card" data-cap={cap ? 'true' : undefined}>
      <div className="goal-head">
        <button className="goal-name" onClick={onEdit} title="Edit goal">{goal.name}</button>
        <span className="goal-count">
          <strong>{met}</strong> / {total} {weekly ? 'weeks' : 'days'}
        </span>
      </div>
      <div className="goal-sub">
        {targetLabel}
        {streak > 0 && (
          <span className="goal-streak">
            {streak} {weekly ? 'week' : 'day'}{streak === 1 ? '' : 's'} running
          </span>
        )}
      </div>
      {weekly ? (
        <WeekStrip
          weeks={periods.map((p) => p.ms)}
          cellFor={cellFor}
          currentWeek={todayInMonth ? weekStartOf(today) : undefined}
          onHover={onHover}
          onLeave={onLeave}
        />
      ) : (
        <MonthGrid
          cells={cells}
          cellFor={(c) => cellFor(localMidnight(c.ms))}
          today={todayInMonth ? today : undefined}
          onPick={onPick}
          onHover={onHover}
          onLeave={onLeave}
          compact
        />
      )}
    </div>
  );
}
