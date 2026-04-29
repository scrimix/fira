import { useEffect, useMemo, useRef } from 'react';
import { useFira } from '../store';
import {
  HOURS, DAY_LABELS, TODAY_DAY_INDEX, NOW_TIME_MIN,
  blockToGrid, fmtClockShort, fmtMin, taskCompletedMin, taskPlannedMin, taskTimeLeft,
} from '../time';
import type { Project, Task, TimeBlock, GcalEvent, UUID } from '../types';

const HOUR_H = 56;

interface PlacedBlock {
  block: TimeBlock;
  task: Task;
  project: Project;
  day: number;
  start_min: number;
  dur_min: number;
  lane: number;
  lanes: number;
}

function placeBlocks(blocks: TimeBlock[], tasks: Task[], projects: Project[]): PlacedBlock[] {
  const taskById = new Map(tasks.map((t) => [t.id, t]));
  const projById = new Map(projects.map((p) => [p.id, p]));

  // Group by day so overlap layout stays per-column.
  const byDay = new Map<number, Array<{
    block: TimeBlock; task: Task; project: Project;
    day: number; start_min: number; dur_min: number;
  }>>();

  for (const b of blocks) {
    const t = taskById.get(b.task_id);
    if (!t) continue;
    const p = projById.get(t.project_id);
    if (!p) continue;
    const { day, start_min, dur_min } = blockToGrid(b.start_at, b.end_at);
    if (day < 0 || day > 6) continue;
    const arr = byDay.get(day) ?? [];
    arr.push({ block: b, task: t, project: p, day, start_min, dur_min });
    byDay.set(day, arr);
  }

  const placed: PlacedBlock[] = [];
  for (const [, items] of byDay) {
    items.sort((a, b) => a.start_min - b.start_min || b.dur_min - a.dur_min);
    const lanes: Array<{ end: number }> = [];
    const assigned: Array<{ idx: number; lane: number }> = [];
    items.forEach((it, idx) => {
      let lane = lanes.findIndex((l) => l.end <= it.start_min);
      if (lane === -1) {
        lanes.push({ end: it.start_min + it.dur_min });
        lane = lanes.length - 1;
      } else {
        lanes[lane].end = it.start_min + it.dur_min;
      }
      assigned.push({ idx, lane });
    });
    const totalLanes = lanes.length;
    assigned.forEach(({ idx, lane }) => {
      placed.push({ ...items[idx], lane, lanes: totalLanes });
    });
  }
  return placed;
}

export function CalendarView() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const gcal = useFira((s) => s.gcal);
  const projects = useFira((s) => s.projects);
  const projectFilter = useFira((s) => s.projectFilter);
  const selectedPersonId = useFira((s) => s.selectedPersonId);
  const toggleProjectFilter = useFira((s) => s.toggleProjectFilter);
  const openTask = useFira((s) => s.openTask);
  const updateBlock = useFira((s) => s.updateBlock);
  const gridRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (gridRef.current) gridRef.current.scrollTop = 7 * HOUR_H - 12;
  }, []);

  const myBlocks = useMemo(
    () => blocks.filter((b) => b.user_id === selectedPersonId),
    [blocks, selectedPersonId],
  );
  const visibleBlocks = useMemo(() => {
    return myBlocks.filter((b) => {
      const t = tasks.find((x) => x.id === b.task_id);
      if (!t) return false;
      return projectFilter[t.project_id] !== false;
    });
  }, [myBlocks, tasks, projectFilter]);
  const placed = useMemo(
    () => placeBlocks(visibleBlocks, tasks, projects),
    [visibleBlocks, tasks, projects],
  );

  const totalMin = myBlocks.reduce((s, b) => s + dur(b), 0);
  const completedMin = myBlocks.filter((b) => b.state === 'completed').reduce((s, b) => s + dur(b), 0);
  const plannedMin = myBlocks.filter((b) => b.state === 'planned').reduce((s, b) => s + dur(b), 0);

  const allocByProject = projects.map((p) => {
    const mins = myBlocks
      .filter((b) => tasks.find((t) => t.id === b.task_id)?.project_id === p.id)
      .reduce((s, b) => s + dur(b), 0);
    return { project: p, mins, pct: totalMin ? (mins / totalMin) * 100 : 0 };
  });

  const myGcal = gcal.filter((g) => g.user_id === selectedPersonId);

  const tickBlock = (b: TimeBlock) => {
    updateBlock(b.id, { state: b.state === 'completed' ? 'planned' : 'completed' });
  };

  return (
    <div className="calendar">
      <div className="cal-left">
        <div className="group">
          <h4>Projects</h4>
          <div className="proj-filter">
            {projects.map((p) => {
              const dimmed = projectFilter[p.id] === false;
              const alloc = allocByProject.find((a) => a.project.id === p.id);
              return (
                <div key={p.id} className="proj-filter-row" data-dimmed={dimmed}
                     onClick={() => toggleProjectFilter(p.id)}>
                  <div className="proj-swatch"
                       style={{ background: dimmed ? 'var(--paper-3)' : p.color, border: `1px solid ${p.color}` }} />
                  <span className="label">{p.title}</span>
                  <span className="count">{fmtMin(alloc?.mins ?? 0)}</span>
                </div>
              );
            })}
          </div>
          <div className="alloc-bar">
            {allocByProject.map((a) => a.mins > 0 && (
              <div key={a.project.id} className="alloc-seg"
                   style={{ width: `${a.pct}%`, background: a.project.color }} />
            ))}
          </div>
        </div>
        <div className="group">
          <h4>This week</h4>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink-2)', lineHeight: 1.7 }}>
            <div><span style={{ color: 'var(--ink-4)' }}>done    </span><span style={{ color: 'var(--done)' }}>{fmtMin(completedMin)}</span></div>
            <div><span style={{ color: 'var(--ink-4)' }}>planned </span><span style={{ color: 'var(--accent)' }}>{fmtMin(plannedMin)}</span></div>
            <div><span style={{ color: 'var(--ink-4)' }}>total   </span><span style={{ color: 'var(--ink)' }}>{fmtMin(totalMin)}</span></div>
          </div>
        </div>
      </div>

      <div className="cal-main">
        <div className="cal-toolbar">
          <span className="week-label">Apr 27 – May 3, 2026</span>
          <div className="totals">
            <span><strong>{fmtMin(completedMin)}</strong> done</span>
            <span><strong>{fmtMin(plannedMin)}</strong> planned</span>
            <span><strong>{fmtMin(totalMin)}</strong> total</span>
          </div>
        </div>
        <div className="cal-grid-wrap" ref={gridRef} style={{ ['--hour-h' as string]: `${HOUR_H}px` }}>
          <div className="cal-grid" style={{ height: 24 * HOUR_H + 44 }}>
            <div className="cal-headcorner" />
            {DAY_LABELS.map((lbl, i) => (
              <div key={i} className="cal-dayhead"
                   data-today={i === TODAY_DAY_INDEX}
                   data-weekend={i >= 5}>
                <span className="dow">{lbl}</span>
                <span className="dnum">{27 + i > 30 ? 27 + i - 30 : 27 + i}</span>
              </div>
            ))}

            <div className="cal-gutter" style={{ gridColumn: 1, gridRow: 2, height: 24 * HOUR_H }}>
              {HOURS.map((h) => (
                <div key={h} className="cal-gutter-hour"
                     data-label={h === 0 ? '' : fmtClockShort(h * 60)} />
              ))}
            </div>

            {DAY_LABELS.map((_, dayIdx) => {
              const dayPlaced = placed.filter((p) => p.day === dayIdx);
              const dayGcal = myGcal.filter((g) => blockToGrid(g.start_at, g.end_at).day === dayIdx);
              const isToday = dayIdx === TODAY_DAY_INDEX;
              const isWeekend = dayIdx >= 5;
              return (
                <div key={dayIdx} className="cal-daycol"
                     data-today={isToday} data-weekend={isWeekend}
                     style={{ gridColumn: dayIdx + 2, gridRow: 2, height: 24 * HOUR_H, position: 'relative' }}>
                  {HOURS.flatMap((h) => [
                    <div key={`hl-${h}`} className="cal-hourline" style={{ top: h * HOUR_H }} />,
                    <div key={`hh-${h}`} className="cal-halfhourline" style={{ top: h * HOUR_H + HOUR_H / 2 }} />,
                  ])}
                  {dayGcal.map((g) => {
                    const { start_min, dur_min } = blockToGrid(g.start_at, g.end_at);
                    return (
                      <div key={g.id} className="gcal-evt" style={{
                        top: (start_min / 60) * HOUR_H,
                        height: (dur_min / 60) * HOUR_H,
                      }}>
                        {g.title} · {fmtClockShort(start_min)}
                      </div>
                    );
                  })}
                  {isToday && (
                    <div className="cal-nowline" style={{ top: (NOW_TIME_MIN / 60) * HOUR_H }} />
                  )}
                  {dayPlaced.map(({ block: b, task: t, project: p, start_min, dur_min, lane, lanes }) => (
                    <div key={b.id} className="tblock"
                         data-state={b.state}
                         style={{
                           top: (start_min / 60) * HOUR_H,
                           height: (dur_min / 60) * HOUR_H - 2,
                           ['--proj-color' as string]: p.color,
                           left: `calc(${(lane / lanes) * 100}% + 1px)`,
                           width: `calc(${100 / lanes}% - 2px)`,
                         }}
                         onClick={() => openTask(t.id)}
                         onDoubleClick={(e) => { e.stopPropagation(); tickBlock(b); }}
                         title={`${t.title} · ${fmtMin(dur_min)} · double-click to ${b.state === 'completed' ? 'unmark' : 'mark complete'}`}>
                      <div className="tb-title">{t.title}</div>
                      <div className="tb-meta">
                        <span>{fmtClockShort(start_min)}</span>
                        <span className="dot" />
                        <span>{fmtMin(dur_min)}</span>
                        {t.external_id && (<><span className="dot" /><span style={{ opacity: 0.7 }}>{t.external_id}</span></>)}
                      </div>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      </div>
      <CalRail />
    </div>
  );
}

function dur(b: TimeBlock): number {
  return Math.round((Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000);
}

function CalRail() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const projects = useFira((s) => s.projects);
  const selectedPersonId = useFira((s) => s.selectedPersonId);
  const openTask = useFira((s) => s.openTask);

  const groups: Array<{ project: Project; tasks: Task[] }> = projects.map((p) => ({
    project: p,
    tasks: tasks.filter((t) =>
      t.project_id === p.id &&
      t.assignee_id === selectedPersonId &&
      t.section !== 'done',
    ),
  })).filter((g) => g.tasks.length > 0);

  return (
    <div className="cal-rail">
      <div className="rail-head">
        <h3>Schedulable</h3>
      </div>
      <div className="rail-body">
        {groups.map((g) => (
          <div key={g.project.id} className="rail-group">
            <div className="rail-group-head">
              <div className="swatch" style={{ background: g.project.color }} />
              <span className="pname">{g.project.title}</span>
              <span className="pcount">{g.tasks.length}</span>
            </div>
            {g.tasks.map((t) => {
              const left = taskTimeLeft(t, blocks);
              const completed = taskCompletedMin(t, blocks);
              const blocker = isBlocker(t, blocks);
              return (
                <div key={t.id} className="rail-task"
                     data-status={t.status}
                     data-blocker={blocker}
                     onClick={() => openTask(t.id)}
                     title={blocker ? 'Silent blocker — no upcoming planned blocks' : ''}>
                  <div className="rail-task-body">
                    <div className="rail-task-title">{t.title}</div>
                    <div className="rail-task-meta">
                      {t.external_id && <span style={{ color: 'var(--ink-4)' }}>{t.external_id}</span>}
                      <span className="left">{left != null ? `${fmtMin(left)} left` : 'no est'}</span>
                    </div>
                    {t.estimate_min && (
                      <div style={{ height: 2, background: 'var(--paper-3)', marginTop: 4 }}>
                        <div style={{
                          height: '100%',
                          width: `${Math.min(100, (completed / t.estimate_min) * 100)}%`,
                          background: g.project.color,
                        }} />
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

function isBlocker(task: Task, blocks: TimeBlock[]): boolean {
  if (task.section !== 'now' || task.status !== 'in_progress') return false;
  const todayMs = Date.parse('2026-04-29T07:00:00Z');
  return !blocks.some((b) =>
    b.task_id === task.id && b.state === 'planned' && Date.parse(b.start_at) >= todayMs
  );
}
