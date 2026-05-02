import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Check, Copy, Trash2, X } from 'lucide-react';
import { useFira } from '../store';
import { ProjectIcon } from './ProjectIcon';
import {
  HOURS, DAY_LABELS, todayDayIndex, nowTimeMin, weekStartMs,
  blockToGrid, gridToBlock, fmtClockShort, fmtMin, taskCompletedMin, taskPlannedMin, taskTimeLeft,
  weekStartFor, dayOfMonthFor,
} from '../time';
import type { Project, Task, TimeBlock, GcalEvent, UUID } from '../types';

const HOUR_H = 56;
const SNAP_MIN = 15;
const RESIZE_EDGE_PX = 6;
const CLICK_THRESHOLD_PX = 4;

interface DragState {
  blockId: UUID;
  taskId: UUID;
  mode: 'move' | 'resize-top' | 'resize-bottom';
  startX: number;
  startY: number;
  origStartMin: number;
  origDurMin: number;
  origDay: number;
  curStartMin: number;
  curDurMin: number;
  curDay: number;
  moved: boolean;
  pointerId: number;
}

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

function placeBlocks(blocks: TimeBlock[], tasks: Task[], projects: Project[], weekStartMs: number): PlacedBlock[] {
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
    const { day, start_min, dur_min } = blockToGrid(b.start_at, b.end_at, weekStartMs);
    if (day < 0 || day > 6) continue;
    const arr = byDay.get(day) ?? [];
    arr.push({ block: b, task: t, project: p, day, start_min, dur_min });
    byDay.set(day, arr);
  }

  const placed: PlacedBlock[] = [];
  for (const [, items] of byDay) {
    items.sort((a, b) => a.start_min - b.start_min || b.dur_min - a.dur_min);
    // Cluster items into connected overlap groups so non-overlapping items
    // each get full width and only actually-overlapping ones split.
    let cluster: typeof items = [];
    let clusterEnd = -Infinity;
    const flush = () => {
      if (!cluster.length) return;
      const lanes: number[] = [];
      const assigned: Array<{ it: typeof items[number]; lane: number }> = [];
      for (const it of cluster) {
        let lane = lanes.findIndex((end) => end <= it.start_min);
        if (lane === -1) {
          lanes.push(it.start_min + it.dur_min);
          lane = lanes.length - 1;
        } else {
          lanes[lane] = it.start_min + it.dur_min;
        }
        assigned.push({ it, lane });
      }
      const total = lanes.length;
      for (const { it, lane } of assigned) {
        placed.push({ ...it, lane, lanes: total });
      }
      cluster = [];
      clusterEnd = -Infinity;
    };
    for (const it of items) {
      if (cluster.length === 0 || it.start_min < clusterEnd) {
        cluster.push(it);
        clusterEnd = Math.max(clusterEnd, it.start_min + it.dur_min);
      } else {
        flush();
        cluster.push(it);
        clusterEnd = it.start_min + it.dur_min;
      }
    }
    flush();
  }
  return placed;
}

export function CalendarView() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const gcal = useFira((s) => s.gcal);
  const projects = useFira((s) => s.projects);
  const linkedBlocks = useFira((s) => s.linkedBlocks);
  const linkedTasks = useFira((s) => s.linkedTasks);
  const linkedGcal = useFira((s) => s.linkedGcal);
  const showLinked = useFira((s) => s.showLinked);
  const setShowLinked = useFira((s) => s.setShowLinked);
  const acceptedLink = useFira((s) =>
    s.links.find((l) => l.status === 'accepted') ?? null,
  );
  const personalBlocks = useFira((s) => s.personalBlocks);
  const personalTasks = useFira((s) => s.personalTasks);
  const showPersonal = useFira((s) => s.showPersonal);
  const setShowPersonal = useFira((s) => s.setShowPersonal);
  const inTeamWorkspace = useFira((s) => {
    const ws = s.workspaces.find((w) => w.id === s.activeWorkspaceId);
    return ws ? !ws.is_personal : false;
  });
  const projectFilter = useFira((s) => s.projectFilter);
  const selectedPersonIds = useFira((s) => s.selectedPersonIds);
  const activePersonId = useFira((s) => s.activePersonId);
  const toggleProjectFilter = useFira((s) => s.toggleProjectFilter);
  const openTask = useFira((s) => s.openTask);
  const updateBlock = useFira((s) => s.updateBlock);
  const deleteBlock = useFira((s) => s.deleteBlock);
  const upsertBlock = useFira((s) => s.upsertBlock);
  const duplicateBlock = useFira((s) => s.duplicateBlock);
  const openCreate = useFira((s) => s.openCreate);
  const users = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const addPerson = useFira((s) => s.addPerson);
  const removePerson = useFira((s) => s.removePerson);
  const setActivePerson = useFira((s) => s.setActivePerson);
  const weekOffset = useFira((s) => s.weekOffset);
  const setWeekOffset = useFira((s) => s.setWeekOffset);
  const weekStart = weekStartFor(weekOffset);
  const isCurrentWeek = weekOffset === 0;
  const todayIndex = todayDayIndex();
  const nowMin = nowTimeMin();
  const gridRef = useRef<HTMLDivElement>(null);
  const innerGridRef = useRef<HTMLDivElement>(null);
  const [drag, setDrag] = useState<DragState | null>(null);
  const dragRef = useRef<DragState | null>(null);
  dragRef.current = drag;
  const [dropPreview, setDropPreview] = useState<{
    day: number; start_min: number; dur_min: number;
  } | null>(null);
  const [draggedTaskId, setDraggedTaskId] = useState<UUID | null>(null);
  const [lastBlockId, setLastBlockId] = useState<UUID | null>(null);
  // Drag-to-create flow: pointer-down on an empty day column anchors at a
  // time, drag extends the range, pointer-up (only if the user actually
  // moved) opens the task draft modal with the time range pre-filled. A
  // bare click does nothing — same convention as Google Calendar.
  const [createDrag, setCreateDrag] = useState<{
    day: number;
    anchorMin: number;
    curMin: number;
    pointerId: number;
    rectTop: number;
    rectHeight: number;
  } | null>(null);
  const createDragRef = useRef<typeof createDrag>(null);
  createDragRef.current = createDrag;

  useEffect(() => {
    if (gridRef.current) gridRef.current.scrollTop = 7 * HOUR_H - 12;
  }, []);

  const colGeometry = () => {
    const g = innerGridRef.current;
    if (!g) return null;
    const rect = g.getBoundingClientRect();
    const gutter = 56;
    return { left: rect.left + gutter, top: rect.top + 44, width: (rect.width - gutter) / 7 };
  };

  const onBlockPointerDown = (e: React.PointerEvent, b: TimeBlock, taskId: UUID) => {
    if (e.button !== 0) return;
    if ((e.target as HTMLElement).closest('.tb-action')) return;
    // Capture grid coordinates against the *visible* week so the drop's
    // gridToBlock(weekStart) round-trips to the same absolute time.
    const { day, start_min, dur_min } = blockToGrid(b.start_at, b.end_at, weekStart);
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const offsetY = e.clientY - rect.top;
    const offsetFromBottom = rect.bottom - e.clientY;
    let mode: DragState['mode'] = 'move';
    if (offsetFromBottom <= RESIZE_EDGE_PX) mode = 'resize-bottom';
    else if (offsetY <= RESIZE_EDGE_PX) mode = 'resize-top';
    e.preventDefault();
    setDrag({
      blockId: b.id, mode,
      startX: e.clientX, startY: e.clientY,
      origStartMin: start_min, origDurMin: dur_min, origDay: day,
      curStartMin: start_min, curDurMin: dur_min, curDay: day,
      moved: false,
      pointerId: e.pointerId,
      taskId,
    });
  };

  // Document-level pointer listeners while a drag is active. Using window
  // events avoids losing the drag if the block element re-renders into a
  // different day column (which unmounts the source and would lose pointer
  // capture).
  useEffect(() => {
    if (!drag) return;
    const snap = (m: number) => Math.round(m / SNAP_MIN) * SNAP_MIN;

    const onMove = (e: PointerEvent) => {
      const d = dragRef.current;
      if (!d || e.pointerId !== d.pointerId) return;
      const dy = e.clientY - d.startY;
      const dx = e.clientX - d.startX;
      const moved = d.moved || Math.hypot(dx, dy) >= CLICK_THRESHOLD_PX;
      const dMin = Math.round((dy / HOUR_H) * 60);

      let curStartMin = d.origStartMin;
      let curDurMin = d.origDurMin;
      let curDay = d.origDay;

      if (d.mode === 'move') {
        curStartMin = Math.max(0, Math.min(24 * 60 - d.origDurMin, snap(d.origStartMin + dMin)));
        const geom = colGeometry();
        if (geom && geom.width > 0) {
          const dayShift = Math.round((e.clientX - d.startX) / geom.width);
          curDay = Math.max(0, Math.min(6, d.origDay + dayShift));
        }
      } else if (d.mode === 'resize-bottom') {
        curDurMin = Math.max(SNAP_MIN, Math.min(24 * 60 - d.origStartMin, snap(d.origDurMin + dMin)));
      } else {
        const end = d.origStartMin + d.origDurMin;
        const clamped = Math.max(0, Math.min(end - SNAP_MIN, snap(d.origStartMin + dMin)));
        curStartMin = clamped;
        curDurMin = end - clamped;
      }

      if (
        curStartMin !== d.curStartMin || curDurMin !== d.curDurMin ||
        curDay !== d.curDay || moved !== d.moved
      ) {
        setDrag({ ...d, curStartMin, curDurMin, curDay, moved });
      }
    };

    const onUp = (e: PointerEvent) => {
      const d = dragRef.current;
      if (!d || e.pointerId !== d.pointerId) return;
      if (d.moved) {
        if (
          d.curStartMin !== d.origStartMin ||
          d.curDurMin !== d.origDurMin ||
          d.curDay !== d.origDay
        ) {
          const { start_at, end_at } = gridToBlock(d.curDay, d.curStartMin, d.curDurMin, weekStart);
          updateBlock(d.blockId, { start_at, end_at });
        }
      } else {
        openTask(d.taskId);
      }
      setDrag(null);
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
    };
  }, [drag?.blockId, drag?.pointerId, openTask, updateBlock]);

  // Window-level move/up for the drag-to-create flow. Mirrors the existing
  // block-drag effect: events go through window so a re-render of the source
  // day column doesn't lose pointer capture.
  useEffect(() => {
    if (!createDrag) return;
    const snap = (m: number) => Math.round(m / SNAP_MIN) * SNAP_MIN;

    const onMove = (e: PointerEvent) => {
      const d = createDragRef.current;
      if (!d || e.pointerId !== d.pointerId) return;
      const y = Math.max(0, Math.min(d.rectHeight, e.clientY - d.rectTop));
      const curMin = Math.max(0, Math.min(24 * 60, snap((y / HOUR_H) * 60)));
      if (curMin !== d.curMin) setCreateDrag({ ...d, curMin });
    };

    const onUp = (e: PointerEvent) => {
      const d = createDragRef.current;
      if (!d || e.pointerId !== d.pointerId) return;
      setCreateDrag(null);
      // No movement → bare click → do nothing.
      if (d.curMin === d.anchorMin) return;
      const startMin = Math.min(d.anchorMin, d.curMin);
      const endMin = Math.max(d.anchorMin, d.curMin);
      const durMin = Math.max(SNAP_MIN, endMin - startMin);
      const userId = activePersonId ?? meId;
      if (!userId) return;
      const { start_at, end_at } = gridToBlock(d.day, startMin, durMin, weekStart);
      // Open the draft modal seeded with the dragged time range.
      // Submit creates the task + block; cancel discards both.
      openCreate({ block: { start_at, end_at, user_id: userId } });
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
    };
  }, [createDrag?.pointerId, activePersonId, meId, weekStart, openCreate]);

  const onDayColPointerDown = (e: React.PointerEvent, day: number) => {
    if (e.button !== 0) return;
    // Only initiate drag-to-create when the press is on the day column
    // background — clicking on an existing block or gcal event must not
    // start a new draft.
    const t = e.target as HTMLElement;
    if (t.closest('.tblock') || t.closest('.gcal-evt')) return;
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const y = e.clientY - rect.top;
    const snap = (m: number) => Math.round(m / SNAP_MIN) * SNAP_MIN;
    const min = Math.max(0, Math.min(24 * 60, snap((y / HOUR_H) * 60)));
    e.preventDefault();
    setCreateDrag({
      day,
      anchorMin: min,
      curMin: min,
      pointerId: e.pointerId,
      rectTop: rect.top,
      rectHeight: rect.height,
    });
  };

  const myBlocks = useMemo(
    () => blocks.filter((b) => b.user_id === activePersonId),
    [blocks, activePersonId],
  );
  const visibleBlocks = useMemo(() => {
    return myBlocks.filter((b) => {
      const t = tasks.find((x) => x.id === b.task_id);
      if (!t) return false;
      return projectFilter[t.project_id] !== false;
    });
  }, [myBlocks, tasks, projectFilter]);
  const placed = useMemo(
    () => placeBlocks(visibleBlocks, tasks, projects, weekStart),
    [visibleBlocks, tasks, projects, weekStart],
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

  const myGcal = gcal.filter((g) => g.user_id === activePersonId);
  // Partner overlay only shows on my own calendar tab — switching to a
  // teammate's view drops it. Joined to linkedTasks so we can render the
  // title + project color without polluting global `tasks`.
  const overlayActive = showLinked && acceptedLink && activePersonId === meId;
  const linkedTaskById = useMemo(
    () => new Map(linkedTasks.map((t) => [t.id, t])),
    [linkedTasks],
  );
  const visibleLinkedBlocks = overlayActive ? linkedBlocks : [];
  const visibleLinkedGcal = overlayActive ? linkedGcal : [];

  // Personal-workspace overlay — same posture as linked: only on my own
  // tab, only in a team workspace, only when the user opted in.
  const personalOverlayActive = showPersonal && inTeamWorkspace && activePersonId === meId;
  const personalTaskById = useMemo(
    () => new Map(personalTasks.map((t) => [t.id, t])),
    [personalTasks],
  );
  const visiblePersonalBlocks = personalOverlayActive ? personalBlocks : [];

  const tickBlock = (b: TimeBlock) => {
    updateBlock(b.id, { state: b.state === 'completed' ? 'planned' : 'completed' });
  };

  const snap = (m: number) => Math.round(m / SNAP_MIN) * SNAP_MIN;
  const dayDropStartMin = (e: React.DragEvent) => {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const y = e.clientY - rect.top;
    return Math.max(0, Math.min(24 * 60 - SNAP_MIN, snap((y / HOUR_H) * 60)));
  };
  // Default to 1h regardless of time-left. The previous "use what's left,
  // clamped to [SNAP_MIN, 120]" behavior produced ugly thin slivers for
  // tasks already overtime (left ≤ 0 → SNAP_MIN). 1h is the right unit-of-
  // intent for "I'm dropping a task on the calendar"; resize handles cover
  // the cases where the user wants something different.
  const taskDurFor = (_taskId: UUID | null): number => 60;
  const onDayDragOver = (e: React.DragEvent, day: number) => {
    if (!e.dataTransfer.types.includes('application/x-fira-task')) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    const dur = taskDurFor(draggedTaskId);
    const start_min = dayDropStartMin(e);
    setDropPreview({ day, start_min, dur_min: Math.min(dur, 24 * 60 - start_min) });
  };
  const onDayDrop = (e: React.DragEvent, day: number) => {
    if (!e.dataTransfer.types.includes('application/x-fira-task')) return;
    e.preventDefault();
    const taskId = e.dataTransfer.getData('application/x-fira-task') || draggedTaskId;
    setDropPreview(null);
    setDraggedTaskId(null);
    if (!taskId) return;
    const t = tasks.find((x) => x.id === taskId);
    if (!t) return;
    // Block belongs to whoever's calendar it lands on, not the task assignee.
    // Multiple people can plan time on the same task; the assignee field
    // indicates ownership of the work item, not whose calendar holds the
    // scheduled time. Falls back to me only if no person is active.
    const userId = activePersonId ?? meId;
    if (!userId) return;
    const dur = taskDurFor(taskId);
    const start_min = dayDropStartMin(e);
    const dur_min = Math.min(dur, 24 * 60 - start_min);
    const { start_at, end_at } = gridToBlock(day, start_min, dur_min, weekStart);
    upsertBlock({
      id: crypto.randomUUID(),
      task_id: t.id,
      user_id: userId,
      start_at,
      end_at,
      state: 'planned',
    });
  };

  return (
    <div className="calendar">
      <div className="cal-main">
        <div className="cal-toolbar">
          <div className="week-nav">
            <button className="week-nav-btn" onClick={() => setWeekOffset(weekOffset - 1)}
                    title="Previous week">‹</button>
            <button className="week-nav-btn week-nav-today"
                    onClick={() => setWeekOffset(0)}
                    data-active={isCurrentWeek}
                    title="Jump to current week">Today</button>
            <button className="week-nav-btn" onClick={() => setWeekOffset(weekOffset + 1)}
                    title="Next week">›</button>
          </div>
          <UserPicker
            users={users}
            meId={meId}
            selectedPersonIds={selectedPersonIds}
            activePersonId={activePersonId}
            onAdd={addPerson}
            onRemove={removePerson}
            onSetActive={setActivePerson}
          />
          {acceptedLink && activePersonId === meId && (
            <button
              className="link-toggle"
              data-active={showLinked || undefined}
              onClick={() => setShowLinked(!showLinked)}
              title={showLinked ? 'Hide linked calendar' : 'Show linked calendar (read-only)'}
            >
              {showLinked ? 'Hide linked' : 'Show linked'}
            </button>
          )}
          {inTeamWorkspace && activePersonId === meId && (
            <button
              className="link-toggle"
              data-active={showPersonal || undefined}
              onClick={() => setShowPersonal(!showPersonal)}
              title={showPersonal
                ? 'Hide personal-workspace blocks'
                : 'Show personal-workspace blocks (read-only)'}
            >
              {showPersonal ? 'Hide personal' : 'Show personal'}
            </button>
          )}
          <div className="totals">
            <span className="totals-done"><strong>{fmtMin(completedMin)}</strong> done</span>
            <span className="totals-planned"><strong>{fmtMin(plannedMin)}</strong> planned</span>
            <span className="totals-total"><strong>{fmtMin(totalMin)}</strong> total</span>
          </div>
        </div>
        <div className="cal-grid-wrap" ref={gridRef} style={{ ['--hour-h' as string]: `${HOUR_H}px` }}
             data-dragging={drag?.moved ? 'true' : undefined}>
          <div className="cal-grid" ref={innerGridRef} style={{ height: 24 * HOUR_H + 44 }}>
            <div className="cal-headcorner" />
            {DAY_LABELS.map((lbl, i) => (
              <div key={i} className="cal-dayhead"
                   data-today={isCurrentWeek && i === todayIndex}
                   data-weekend={i >= 5}>
                <span className="dow">{lbl}</span>
                <span className="dnum">{dayOfMonthFor(weekStart, i)}</span>
              </div>
            ))}

            <div className="cal-gutter" style={{ gridColumn: 1, gridRow: 2, height: 24 * HOUR_H }}>
              {HOURS.map((h) => (
                <div key={h} className="cal-gutter-hour"
                     data-label={h === 0 ? '' : fmtClockShort(h * 60)} />
              ))}
            </div>

            {DAY_LABELS.map((_, dayIdx) => {
              const dayPlaced = placed.filter((p) => {
                if (drag?.blockId === p.block.id) return drag.curDay === dayIdx;
                return p.day === dayIdx;
              });
              const dayGcal = myGcal.filter((g) => blockToGrid(g.start_at, g.end_at, weekStart).day === dayIdx);
              const dayLinkedBlocks = visibleLinkedBlocks
                .map((b) => {
                  const grid = blockToGrid(b.start_at, b.end_at, weekStart);
                  return grid.day === dayIdx ? { block: b, ...grid } : null;
                })
                .filter((x): x is NonNullable<typeof x> => x !== null);
              const dayLinkedGcal = visibleLinkedGcal.filter(
                (g) => blockToGrid(g.start_at, g.end_at, weekStart).day === dayIdx,
              );
              const dayPersonalBlocks = visiblePersonalBlocks
                .map((b) => {
                  const grid = blockToGrid(b.start_at, b.end_at, weekStart);
                  return grid.day === dayIdx ? { block: b, ...grid } : null;
                })
                .filter((x): x is NonNullable<typeof x> => x !== null);
              const isToday = isCurrentWeek && dayIdx === todayIndex;
              const isWeekend = dayIdx >= 5;
              const showPreview = dropPreview?.day === dayIdx;
              return (
                <div key={dayIdx} className="cal-daycol"
                     data-today={isToday} data-weekend={isWeekend}
                     data-drop-target={showPreview ? 'true' : undefined}
                     style={{ gridColumn: dayIdx + 2, gridRow: 2, height: 24 * HOUR_H, position: 'relative' }}
                     onPointerDown={(e) => onDayColPointerDown(e, dayIdx)}
                     onDragOver={(e) => onDayDragOver(e, dayIdx)}
                     onDragLeave={(e) => {
                       const next = e.relatedTarget as Node | null;
                       if (!next || !(e.currentTarget as Node).contains(next)) setDropPreview(null);
                     }}
                     onDrop={(e) => onDayDrop(e, dayIdx)}>
                  {HOURS.flatMap((h) => [
                    <div key={`hl-${h}`} className="cal-hourline" style={{ top: h * HOUR_H }} />,
                    <div key={`hh-${h}`} className="cal-halfhourline" style={{ top: h * HOUR_H + HOUR_H / 2 }} />,
                  ])}
                  {showPreview && dropPreview && (
                    <div className="tblock-preview" style={{
                      top: (dropPreview.start_min / 60) * HOUR_H,
                      height: (dropPreview.dur_min / 60) * HOUR_H - 2,
                    }} />
                  )}
                  {createDrag && createDrag.day === dayIdx && createDrag.curMin !== createDrag.anchorMin && (
                    <div className="tblock-preview" style={{
                      top: (Math.min(createDrag.anchorMin, createDrag.curMin) / 60) * HOUR_H,
                      height: (Math.abs(createDrag.curMin - createDrag.anchorMin) / 60) * HOUR_H - 2,
                    }} />
                  )}
                  {dayGcal.map((g) => {
                    const { start_min, dur_min } = blockToGrid(g.start_at, g.end_at, weekStart);
                    return (
                      <div key={g.id} className="gcal-evt" style={{
                        top: (start_min / 60) * HOUR_H,
                        height: (dur_min / 60) * HOUR_H,
                      }}>
                        {g.title} · {fmtClockShort(start_min)}
                      </div>
                    );
                  })}
                  {dayLinkedGcal.map((g) => {
                    const { start_min, dur_min } = blockToGrid(g.start_at, g.end_at, weekStart);
                    return (
                      <div key={`l-g-${g.id}`} className="gcal-evt gcal-evt-linked" style={{
                        top: (start_min / 60) * HOUR_H,
                        height: (dur_min / 60) * HOUR_H,
                      }}>
                        {g.title} · {fmtClockShort(start_min)}
                      </div>
                    );
                  })}
                  {dayLinkedBlocks.map(({ block: b, start_min, dur_min }) => {
                    const lt = linkedTaskById.get(b.task_id);
                    return (
                      <div key={`l-b-${b.id}`} className="tblock tblock-linked"
                           data-state={b.state}
                           data-task-done={lt?.status === 'done' ? 'true' : undefined}
                           data-short={dur_min < 60 ? 'true' : undefined}
                           style={{
                             top: (start_min / 60) * HOUR_H,
                             height: (dur_min / 60) * HOUR_H - 2,
                             ['--proj-color' as string]: lt?.project_color ?? 'var(--ink-3)',
                           }}
                           title={`${lt?.title ?? 'Linked task'} · ${fmtMin(dur_min)} (linked, read-only)`}>
                        <div className="tb-title">{lt?.title ?? 'Linked task'}</div>
                        <div className="tb-meta">
                          <span>{fmtClockShort(start_min)}</span>
                          <span className="dot" />
                          <span>{fmtMin(dur_min)}</span>
                        </div>
                      </div>
                    );
                  })}
                  {dayPersonalBlocks.map(({ block: b, start_min, dur_min }) => {
                    const pt = personalTaskById.get(b.task_id);
                    return (
                      <div key={`p-b-${b.id}`} className="tblock tblock-personal"
                           data-state={b.state}
                           data-task-done={pt?.status === 'done' ? 'true' : undefined}
                           data-short={dur_min < 60 ? 'true' : undefined}
                           style={{
                             top: (start_min / 60) * HOUR_H,
                             height: (dur_min / 60) * HOUR_H - 2,
                             ['--proj-color' as string]: pt?.project_color ?? 'var(--ink-3)',
                           }}
                           title={`${pt?.title ?? 'Personal task'} · ${fmtMin(dur_min)} (personal, read-only)`}>
                        <div className="tb-title">{pt?.title ?? 'Personal task'}</div>
                        <div className="tb-meta">
                          <span>{fmtClockShort(start_min)}</span>
                          <span className="dot" />
                          <span>{fmtMin(dur_min)}</span>
                        </div>
                      </div>
                    );
                  })}
                  {isToday && (
                    <div className="cal-nowline" style={{ top: (nowMin / 60) * HOUR_H }} />
                  )}
                  {dayPlaced.map(({ block: b, task: t, project: p, start_min, dur_min, lane, lanes }) => {
                    const isDragging = drag?.blockId === b.id;
                    const sMin = isDragging ? drag.curStartMin : start_min;
                    const dMin = isDragging ? drag.curDurMin : dur_min;
                    const fullWidth = isDragging && drag.moved;
                    return (
                      <div key={b.id} className="tblock"
                           data-state={b.state}
                           data-task-done={t.status === 'done' ? 'true' : undefined}
                           data-dragging={isDragging && drag.moved ? 'true' : undefined}
                           data-short={dMin < 60 ? 'true' : undefined}
                           data-active={lastBlockId === b.id ? 'true' : undefined}
                           style={{
                             top: (sMin / 60) * HOUR_H,
                             height: (dMin / 60) * HOUR_H - 2,
                             ['--proj-color' as string]: p.color,
                             left: fullWidth ? '1px' : `calc(${(lane / lanes) * 100}% + 1px)`,
                             width: fullWidth ? 'calc(100% - 2px)' : `calc(${100 / lanes}% - 2px)`,
                           }}
                           onPointerDown={(e) => { setLastBlockId(b.id); onBlockPointerDown(e, b, t.id); }}
                           title={t.status === 'done' && b.state === 'planned'
                             ? `${t.title} · ${fmtMin(dMin)}\n\n⚠ Task is marked done, but this block is still planned. Delete the block or reopen the task.`
                             : `${t.title} · ${fmtMin(dMin)}`}>
                        <div className="tb-title">{t.title}</div>
                        <div className="tb-meta">
                          <span>{fmtClockShort(sMin)}</span>
                          <span className="dot" />
                          <span>{fmtMin(dMin)}</span>
                        </div>
                        {t.external_id && (
                          <div className="tb-extid">{t.external_id}</div>
                        )}
                        <div className="tb-actions">
                          <button className="tb-action tb-tick"
                                  data-checked={b.state === 'completed'}
                                  onPointerDown={(e) => e.stopPropagation()}
                                  onClick={(e) => { e.stopPropagation(); tickBlock(b); }}
                                  title={b.state === 'completed' ? 'Mark planned' : 'Mark complete'}>
                            <Check size={11} strokeWidth={2.25} />
                          </button>
                          <button className="tb-action tb-dup"
                                  onPointerDown={(e) => e.stopPropagation()}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const newId = duplicateBlock(b.id);
                                    if (newId) setLastBlockId(newId);
                                  }}
                                  title="Duplicate (Ctrl+D)">
                            <Copy size={11} strokeWidth={1.75} />
                          </button>
                          <button className="tb-action tb-close"
                                  onPointerDown={(e) => e.stopPropagation()}
                                  onClick={(e) => { e.stopPropagation(); deleteBlock(b.id); }}
                                  title="Delete block">
                            <Trash2 size={11} strokeWidth={1.75} />
                          </button>
                        </div>
                        <div className="tb-resize tb-resize-top" />
                        <div className="tb-resize tb-resize-bottom" />
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </div>
      <CalRail
        onDragTask={setDraggedTaskId}
        allocByProject={allocByProject}
      />
    </div>
  );
}

function dur(b: TimeBlock): number {
  return Math.round((Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000);
}

function UserPicker({ users, meId, selectedPersonIds, activePersonId, onAdd, onRemove, onSetActive }: {
  users: { id: UUID; name: string; initials: string; email: string }[];
  meId: UUID | null;
  selectedPersonIds: UUID[];
  activePersonId: UUID | null;
  onAdd: (id: UUID) => void;
  onRemove: (id: UUID) => void;
  onSetActive: (id: UUID) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  // Anchor the popover against whichever viewport edge gives it more room.
  // Without this, a small picker (only "Me" pinned) sits near the left edge
  // and the right-anchored popover would extend past x = 0.
  const [popAlign, setPopAlign] = useState<'left' | 'right'>('right');
  const wrapRef = useRef<HTMLDivElement>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const selectedSet = new Set(selectedPersonIds);
  const orderedSelected = selectedPersonIds
    .map((id) => users.find((u) => u.id === id))
    .filter((u): u is typeof users[number] => !!u);

  const q = query.trim().toLowerCase();
  // Skip people already in the stack — adding them again is a no-op, and
  // hiding them keeps the list short for orgs with many people.
  const filtered = users.filter((u) => {
    if (selectedSet.has(u.id)) return false;
    if (q && !(u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q))) return false;
    return true;
  });

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setOpen(false); }
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  // Pick the side with more breathing room *after* the popover paints, so we
  // can read its real width and avoid clipping. Falls back to right-anchor
  // when both sides fit.
  useLayoutEffect(() => {
    if (!open) return;
    const wrap = wrapRef.current;
    const pop = popRef.current;
    if (!wrap || !pop) return;
    const wrapRect = wrap.getBoundingClientRect();
    const popWidth = pop.getBoundingClientRect().width;
    const margin = 8;
    const fitsRightAnchor = wrapRect.right - popWidth >= margin;
    const fitsLeftAnchor = wrapRect.left + popWidth <= window.innerWidth - margin;
    setPopAlign(fitsRightAnchor ? 'right' : fitsLeftAnchor ? 'left' : 'right');
  }, [open, selectedPersonIds.length]);

  useEffect(() => { setActiveIdx(0); }, [query]);

  const pickFromSearch = (id: UUID) => {
    onAdd(id); // adds to stack and sets active
    setOpen(false);
  };

  return (
    <div className="user-picker" ref={wrapRef}>
      {orderedSelected.map((u) => {
        const isActive = u.id === activePersonId;
        const isMe = u.id === meId;
        const isOnlyAndMe = orderedSelected.length === 1 && isMe;
        return (
          <span key={u.id} className="user-pill tab-pill"
                data-active={isActive}
                data-me={isMe}
                onClick={() => onSetActive(u.id)}
                title={isActive ? u.name : `Switch to ${u.name}`}>
            <span className="avatar" data-me={isMe}>{u.initials}</span>
            <span className="user-name">{isMe ? 'Me' : u.name.split(' ')[0]}</span>
            {!isOnlyAndMe && (
              <button className="user-pill-x"
                      onClick={(e) => { e.stopPropagation(); onRemove(u.id); }}
                      title={`Remove ${u.name}`}
                      aria-label={`Remove ${u.name}`}>
                <X size={11} strokeWidth={1.75} />
              </button>
            )}
          </span>
        );
      })}
      <button className="user-pill add-pill"
              onClick={() => setOpen((v) => !v)}
              title="Add person to switchable tabs">
        <span className="user-name">+ Add</span>
      </button>
      {open && (
        <div className="user-popover" ref={popRef} data-align={popAlign}>
          <input
            ref={inputRef}
            className="user-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search people…"
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveIdx((i) => Math.min(filtered.length - 1, i + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIdx((i) => Math.max(0, i - 1));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                const u = filtered[activeIdx];
                if (u) pickFromSearch(u.id);
              }
            }}
          />
          <div className="user-list">
            {filtered.length === 0 ? (
              <div className="user-empty">No matches.</div>
            ) : filtered.map((u, i) => (
              <button key={u.id} className="user-row"
                      data-active={i === activeIdx}
                      onMouseEnter={() => setActiveIdx(i)}
                      onClick={() => pickFromSearch(u.id)}>
                <span className="avatar" data-me={u.id === meId}>{u.initials}</span>
                <span className="user-row-name">
                  {u.name}{u.id === meId && <span className="user-row-you"> (you)</span>}
                </span>
                <span className="user-row-email">{u.email}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CalRail({ onDragTask, allocByProject }: {
  onDragTask: (id: UUID | null) => void;
  allocByProject: Array<{ project: Project; mins: number; pct: number }>;
}) {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const projects = useFira((s) => s.projects);
  const projectFilter = useFira((s) => s.projectFilter);
  const toggleProjectFilter = useFira((s) => s.toggleProjectFilter);
  const activePersonId = useFira((s) => s.activePersonId);
  const openTask = useFira((s) => s.openTask);
  const openCreate = useFira((s) => s.openCreate);

  // "My tasks only" (default) vs "All in project". Showing all is what
  // makes logging time on a task someone else owns possible — drag any
  // task onto your calendar and the block becomes yours regardless of the
  // assignee. The button label names the action you'd take by clicking
  // (verb-style), not the current filter state.
  const [showAll, setShowAll] = useState(false);
  const [titleQuery, setTitleQuery] = useState('');
  const q = titleQuery.trim().toLowerCase();

  const groups: Array<{ project: Project; tasks: Task[] }> = projects
    .filter((p) => projectFilter[p.id] !== false)
    .map((p) => ({
      project: p,
      // Match the inbox order so the rail reads the same way: section
      // first (Now before Later), then sort_key within each section. The
      // inbox is the source of truth users curate against; the rail
      // diverging from it makes drag-to-calendar feel unpredictable.
      tasks: tasks
        .filter((t) =>
          t.project_id === p.id &&
          (showAll || t.assignee_id === activePersonId) &&
          (showAll ? (t.section === 'now' || t.section === 'later') : t.section === 'now') &&
          (!q
            || t.title.toLowerCase().includes(q)
            || (t.external_id?.toLowerCase().includes(q) ?? false)),
        )
        .sort((a, b) => {
          if (a.section !== b.section) return a.section === 'now' ? -1 : 1;
          return a.sort_key.localeCompare(b.sort_key);
        }),
    }))
    .filter((g) => g.tasks.length > 0);

  return (
    <div className="cal-rail">
      <div className="rail-head">
        <button className="rail-new-btn" onClick={() => openCreate()} title="New task">
          <span className="rail-new-plus">+</span>
          <span>New task</span>
        </button>
        <input
          className="rail-search"
          value={titleQuery}
          onChange={(e) => setTitleQuery(e.target.value)}
          placeholder="Filter…"
          spellCheck={false}
          onKeyDown={(e) => { if (e.key === 'Escape') setTitleQuery(''); }}
        />
        <button className="rail-scope-btn"
                onClick={() => setShowAll((v) => !v)}
                data-active={showAll}
                title={showAll
                  ? 'Showing every task in the project — click to filter back to your own'
                  : 'Show every task in the project (so you can log time on tasks you don’t own)'}>
          {showAll ? 'My' : 'All'}
        </button>
      </div>
      <div className="rail-projects">
        <div className="rail-projects-head">Projects</div>
        {projects.map((p) => {
          const dimmed = projectFilter[p.id] === false;
          const alloc = allocByProject.find((a) => a.project.id === p.id);
          return (
            <div key={p.id} className="rail-proj-row" data-dimmed={dimmed}
                 onClick={() => toggleProjectFilter(p.id)}
                 title={dimmed ? `Show ${p.title} on calendar` : `Hide ${p.title} from calendar`}>
              <ProjectIcon
                name={p.icon}
                color={dimmed ? 'var(--ink-4)' : p.color}
                size={12}
                strokeWidth={1.75}
                className="rail-proj-icon"
              />
              <span className="rail-proj-name">{p.title}</span>
              <span className="rail-proj-count">{fmtMin(alloc?.mins ?? 0)}</span>
            </div>
          );
        })}
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
              const planned = taskPlannedMin(t, blocks);
              const blocker = isBlocker(t, blocks);
              const est = t.estimate_min;
              const total = est != null ? Math.max(est, completed + planned) : 0;
              const compPct = total ? (completed / total) * 100 : 0;
              const planPct = total ? (planned / total) * 100 : 0;
              const estPct = est != null && total ? (est / total) * 100 : 100;
              const overPct = Math.max(0, compPct + planPct - estPct);
              const overSpent = est != null && completed > est;
              const leftLabel = left == null ? 'no est'
                : left < 0 ? `${fmtMin(-left)} over`
                : left === 0 && overSpent ? `+${fmtMin(completed - (est ?? 0))} spent`
                : `${fmtMin(left)} left`;
              const others = t.assignee_id !== activePersonId;
              return (
                <div key={t.id} className="rail-task"
                     data-status={t.status}
                     data-blocker={blocker}
                     data-others={others || undefined}
                     draggable
                     onDragStart={(e) => {
                       e.dataTransfer.effectAllowed = 'copy';
                       e.dataTransfer.setData('application/x-fira-task', t.id);
                       e.dataTransfer.setData('text/plain', t.title);
                       onDragTask(t.id);
                     }}
                     onDragEnd={() => onDragTask(null)}
                     onClick={() => openTask(t.id)}
                     title={blocker ? 'Silent blocker — no upcoming planned blocks' : 'Drag onto the calendar to schedule'}>
                  <div className="rail-task-body">
                    <div className="rail-task-title">{t.title}</div>
                    <div className="rail-task-meta">
                      {t.external_id && <span style={{ color: 'var(--ink-4)' }}>{t.external_id}</span>}
                      <span className="left" data-over={left != null && left < 0 ? 'true' : undefined}>
                        {leftLabel}
                      </span>
                    </div>
                    {est != null && (
                      <div className="rail-fill" style={{ marginTop: 4 }}>
                        <div className="rail-fill-spent"
                             style={{ width: `${compPct}%`, background: g.project.color }} />
                        <div className="rail-fill-planned"
                             style={{
                               width: `${planPct}%`,
                               background: `color-mix(in oklab, ${g.project.color} 35%, var(--paper-3))`,
                             }} />
                        {overPct > 0 && (
                          <div className="rail-fill-over" style={{ width: `${overPct}%` }} />
                        )}
                        {est != null && total > est && (
                          <div className="rail-fill-est-line" style={{ left: `${estPct}%` }} />
                        )}
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
  const ws = new Date(weekStartMs());
  const todayMs = new Date(
    ws.getFullYear(), ws.getMonth(), ws.getDate() + todayDayIndex(),
  ).getTime();
  return !blocks.some((b) =>
    b.task_id === task.id && b.state === 'planned' && Date.parse(b.start_at) >= todayMs
  );
}
