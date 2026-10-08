import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Archive, ChevronDown, ChevronLeft, ChevronRight, History, ListChecks, Minus,
  ChevronUp, PanelLeft, Plus, Trash2,
} from 'lucide-react';
import { useFira } from '../store';
import { api } from '../api';
import type { PlanHistory } from '../planHistory';
import { PlanTimeline } from './PlanTimeline';
import { useIsMobile } from '../hooks';
import {
  buildPlanSnapshot, type PlanSnapshot, type PlanTask, type PlanTrackRow,
  type RetroBucket,
} from '../plan';
import {
  fmtDateKey, isoWeekLabel, monthSpansFor, parseDateKey,
  weekStartFor, weekStartOf,
} from '../time';
import type { Section, Tag, UUID } from '../types';
import { PlanSprintCard, PLAN_TASK_MIME } from './PlanSprintCard';
import { ConfirmDelete } from './ConfirmDelete';
import { ListTagFilter } from './TagFilter';

const WEEK_W = { s: 72, m: 104, l: 150 } as const;
const CLICK_THRESHOLD_PX = 4;
const RESIZE_EDGE_PX = 6;

/// Live drag of a card. One gesture carries **both** axes — week span
/// (x) and track row (y) — exactly as the calendar's block drag carries
/// time and day together.
///
/// Pointer events, not HTML5 DnD, and that is not a preference: the card
/// is also a drop target for tasks, and making it a native drag source
/// too meant `dragstart` fired on the first move and the pointer stream
/// died, so neither the move nor the resize ever ran.
/// A week range being swept out in "place a sprint" mode. `from`/`to`
/// are inclusive column indices in either order; the span is normalised
/// on commit.
interface PlaceRange {
  trackId: UUID | null;
  from: number;
  to: number;
}

interface SpanDrag {
  sprintId: UUID;
  mode: 'move' | 'resize-start' | 'resize-end';
  pointerId: number;
  startX: number;
  origStart: number;
  origEnd: number;
  curStart: number;
  curEnd: number;
  /// `null` is the "No track" row. `undefined` never occurs.
  origTrackId: UUID | null;
  curTrackId: UUID | null;
  moved: boolean;
}

export function PlanView() {
  const isMobile = useIsMobile();
  const projects = useFira((s) => s.projects);
  const planProjectId = useFira((s) => s.planProjectId);
  const listProjectId = useFira((s) => s.listFilter.project_id);
  const setView = useFira((s) => s.setView);

  // Fall back to whatever the list is scoped to, so switching surfaces
  // keeps the subject rather than asking again.
  const projectId = planProjectId
    ?? (listProjectId && projects.some((p) => p.id === listProjectId) ? listProjectId : null)
    ?? projects[0]?.id
    ?? null;

  if (isMobile) {
    // A week-column board is inherently wide, and a three-week window on
    // a phone answers nothing the list doesn't answer better.
    return (
      <div className="plan-mobile">
        <p className="plan-mobile-msg">Plan view is desktop-only.</p>
        <button className="btn" onClick={() => setView('list')}>Open the list</button>
      </div>
    );
  }

  if (!projectId) {
    return (
      <div className="plan-mobile">
        <p className="plan-mobile-msg">No projects in this workspace yet.</p>
      </div>
    );
  }

  return (
    <PlanBoard
      key={projectId}
      projectId={projectId}
    />
  );
}

function PlanBoard({ projectId }: { projectId: UUID }) {
  const versionAt = useFira((s) => s.planVersionAt);
  const versionSeq = useFira((s) => s.planVersionSeq);
  const setVersionAt = useFira((s) => s.setPlanVersionAt);
  const playground = useFira((s) => s.playgroundMode);
  const workspaceId = useFira((s) => s.activeWorkspaceId);
  const cursor = useFira((s) => s.cursor);
  const showHistory = useFira((s) => s.planShowHistory);
  const toggleHistory = useFira((s) => s.togglePlanHistory);
  const readOnly = versionAt !== null;
  const [history, setHistory] = useState<{ data: PlanHistory; requestedAt: string | null; requestedSeq: number | null } | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [retryHistory, setRetryHistory] = useState(0);
  const lastHistoryRequest = useRef(0);
  useEffect(() => { setHistory(null); }, [projectId, workspaceId]);
  useEffect(() => {
    if (playground || !showHistory) { setHistoryLoading(false); return; }
    let cancelled = false;
    setHistoryLoading(true);
    setHistoryError(null);
    // Throttle continuous scrubbing; cleanup ignores superseded reads.
    // Keep the last completed projection visible while the playhead moves.
    const timer = window.setTimeout(() => {
      lastHistoryRequest.current = performance.now();
      api.planAt(projectId, versionAt, versionSeq).then((data) => {
        if (!cancelled) setHistory({ data, requestedAt: versionAt, requestedSeq: versionSeq });
      }).catch((error: unknown) => {
        if (!cancelled) setHistoryError(error instanceof Error ? error.message : 'Could not load history');
      }).finally(() => { if (!cancelled) setHistoryLoading(false); });
    }, Math.max(0, 100 - (performance.now() - lastHistoryRequest.current)));
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [projectId, workspaceId, versionAt, versionSeq, cursor, playground, showHistory, retryHistory]);

  const tracks = useFira((s) => s.tracks);
  const sprints = useFira((s) => s.sprints);
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  // Tags are orthogonal to the board — sprint 31 changed nothing about
  // them — but the rail filters by them, so it reads them straight.
  const allTags = useFira((s) => s.tags);
  const weekOffset = useFira((s) => s.planWeekOffset);
  const weekCount = useFira((s) => s.planWeekCount);
  const weekWidth = useFira((s) => s.planWeekWidth);
  const showInbox = useFira((s) => s.planShowInbox);
  const showTasks = useFira((s) => s.planShowTasks);
  const showRetro = useFira((s) => s.planShowRetro);

  const setPlanWindow = useFira((s) => s.setPlanWindow);
  const setPlanWeekWidth = useFira((s) => s.setPlanWeekWidth);
  const togglePlanInbox = useFira((s) => s.togglePlanInbox);
  const togglePlanTasks = useFira((s) => s.togglePlanTasks);
  const togglePlanRetro = useFira((s) => s.togglePlanRetro);

  const addTrack = useFira((s) => s.addTrack);
  const setTrackTitle = useFira((s) => s.setTrackTitle);
  const deleteTrack = useFira((s) => s.deleteTrack);
  const reorderTracks = useFira((s) => s.reorderTracks);
  const addSprint = useFira((s) => s.addSprint);
  const setSprintTitle = useFira((s) => s.setSprintTitle);
  const setSprintDates = useFira((s) => s.setSprintDates);
  const setSprintTrack = useFira((s) => s.setSprintTrack);
  const deleteSprint = useFira((s) => s.deleteSprint);
  const setTaskSprint = useFira((s) => s.setTaskSprint);
  const addTask = useFira((s) => s.addTask);
  const tickTask = useFira((s) => s.tickTask);
  const openTask = useFira((s) => s.openTask);
  const setTaskSection = useFira((s) => s.setTaskSection);
  const reorderTasks = useFira((s) => s.reorderTasks);

  const [drag, setDrag] = useState<SpanDrag | null>(null);
  const dragRef = useRef<SpanDrag | null>(null);
  dragRef.current = drag;

  // "Place a sprint" mode. Armed by the toolbar's + Sprint button: the
  // grid lights up, the cursor becomes a crosshair, and you drag across
  // the weeks you want. Creating by dragging the span is the gesture a
  // timeline affords — a button that silently drops a card somewhere
  // off-screen is not.
  const [placing, setPlacing] = useState(false);
  const [range, setRange] = useState<PlaceRange | null>(null);
  const rangeRef = useRef<PlaceRange | null>(null);
  rangeRef.current = range;
  const [confirmTrack, setConfirmTrack] = useState<UUID | null>(null);
  const [confirmSprint, setConfirmSprint] = useState<UUID | null>(null);
  const gridRef = useRef<HTMLDivElement>(null);

  // The board resolves its own project when nothing has been picked
  // (list scope, else the first project). Write that back so the store
  // says what the screen says — the sidebar reads `planProjectId` to
  // decide which project to highlight, and would otherwise highlight
  // nothing while a board was plainly scoped to something.
  const setPlanProject = useFira((s) => s.setPlanProject);
  const planProjectId = useFira((s) => s.planProjectId);
  useEffect(() => {
    if (planProjectId !== projectId) setPlanProject(projectId);
  }, [projectId, planProjectId, setPlanProject]);

  const weekStartMs = weekStartFor(weekOffset);

  const liveSnapshot: PlanSnapshot = useMemo(
    () => buildPlanSnapshot({
      projectId, tracks, sprints, tasks, blocks, weekStartMs, weekCount,
    }),
    [projectId, tracks, sprints, tasks, blocks, weekStartMs, weekCount],
  );

  const snapshot: PlanSnapshot = useMemo(() => {
    if (!readOnly) return liveSnapshot;
    const data = history && !historyError ? history.data : null;
    const past = buildPlanSnapshot({ projectId, tracks: data?.tracks ?? [],
      sprints: data?.sprints ?? [], tasks: data?.tasks ?? [], blocks: [], weekStartMs, weekCount });
    return past;
  }, [readOnly, liveSnapshot, history, versionAt, versionSeq, historyError, projectId, weekStartMs, weekCount]);

  useEffect(() => {
    if (readOnly) { setDrag(null); setPlacing(false); setRange(null); setConfirmTrack(null); setConfirmSprint(null); }
  }, [readOnly]);

  const monthSpans = useMemo(() => monthSpansFor(snapshot.weeks), [snapshot.weeks]);

  // Open near "now" rather than at the left edge. The window reaches
  // back far enough to show recent history, so without this the board
  // opens on weeks that have already happened and the user has to
  // scroll to find today. Once per project — after that the scroll
  // position is theirs.
  const scrolledFor = useRef<UUID | null>(null);
  const scrollToNow = useCallback(() => {
    const el = gridRef.current;
    if (!el || snapshot.nowWeek < 0) return;
    // Two columns of lead-in, so "now" sits just inside the left edge
    // with its immediate past still visible.
    el.scrollLeft = Math.max(0, (snapshot.nowWeek - 2) * WEEK_W[weekWidth]);
  }, [snapshot.nowWeek, weekWidth]);

  useEffect(() => {
    if (scrolledFor.current === projectId) return;
    scrolledFor.current = projectId;
    scrollToNow();
  }, [projectId, scrollToNow]);

  // `now` resets the window *and* re-centres; resetting alone would
  // leave the user looking at wherever they had scrolled to.
  const backToNow = () => {
    setVersionAt(null);
    setPlanWindow(-6, 16);
    requestAnimationFrame(scrollToNow);
  };

  // --- span drag (move / resize along the week axis) ---------------------

  const beginDrag = (e: React.PointerEvent, sprintId: UUID, mode: SpanDrag['mode']) => {
    if (readOnly) return;
    if (e.button !== 0) return;
    const s = sprints.find((x) => x.id === sprintId);
    if (!s || !s.starts_on || !s.ends_on) return;
    // A grip has no click semantics, so preventDefault is free there —
    // and necessary: without it the native selection starts at
    // pointerdown and the drag paints the card's whole checklist blue.
    // The header can't do the same, because preventDefault would also
    // suppress the click that opens the rename editor on a press that
    // never became a drag; `user-select: none` covers it instead, plus
    // `[data-dragging]` on the wrap for everything the pointer crosses.
    if (mode !== 'move') e.preventDefault();
    e.stopPropagation();
    const from = parseDateKey(s.starts_on);
    const to = parseDateKey(s.ends_on);
    setDrag({
      sprintId, mode, pointerId: e.pointerId, startX: e.clientX,
      origStart: from, origEnd: to, curStart: from, curEnd: to,
      origTrackId: s.track_id, curTrackId: s.track_id,
      moved: false,
    });
  };

  // Listeners on `window`, not the element: a fast drag that outruns the
  // cursor, or a card that re-renders into a different lane, would
  // otherwise drop the gesture mid-flight.
  useEffect(() => {
    if (!drag) return;
    const colW = WEEK_W[weekWidth];
    const shiftWeeks = (dx: number) => Math.round(dx / colW);
    const addWeeks = (ms: number, n: number) => {
      const d = new Date(ms);
      return new Date(d.getFullYear(), d.getMonth(), d.getDate() + n * 7).getTime();
    };

    /// Which track row is under the cursor. The dragged card has
    /// `pointer-events: none` while dragging, so this hit-tests the row
    /// beneath it rather than the card itself. A row with no
    /// `data-track` (the retro band) isn't a drop target.
    const rowUnder = (x: number, y: number): { id: UUID | null } | null => {
      const el = document.elementFromPoint(x, y)?.closest('.plan-row') as HTMLElement | null;
      if (!el || el.dataset.track === undefined) return null;
      return { id: el.dataset.track === '' ? null : el.dataset.track };
    };

    const onMove = (e: PointerEvent) => {
      const d = dragRef.current;
      if (!d || e.pointerId !== d.pointerId) return;
      const dx = e.clientX - d.startX;
      const moved = d.moved || Math.abs(dx) >= CLICK_THRESHOLD_PX;
      const n = shiftWeeks(dx);
      let curStart = d.origStart;
      let curEnd = d.origEnd;
      if (d.mode === 'move') {
        curStart = addWeeks(d.origStart, n);
        curEnd = addWeeks(d.origEnd, n);
      } else if (d.mode === 'resize-end') {
        // One week is the minimum span: the schema rejects
        // ends_on == starts_on outright.
        curEnd = Math.max(addWeeks(d.origStart, 1), addWeeks(d.origEnd, n));
      } else {
        curStart = Math.min(addWeeks(d.origEnd, -1), addWeeks(d.origStart, n));
      }
      // Only a move retracks; a resize stays on its row.
      let curTrackId = d.curTrackId;
      if (d.mode === 'move') {
        const row = rowUnder(e.clientX, e.clientY);
        if (row) curTrackId = row.id;
      }
      if (curStart !== d.curStart || curEnd !== d.curEnd
        || curTrackId !== d.curTrackId || moved !== d.moved) {
        setDrag({ ...d, curStart, curEnd, curTrackId, moved });
      }
    };

    const onUp = (e: PointerEvent) => {
      const d = dragRef.current;
      if (!d || e.pointerId !== d.pointerId) return;
      if (d.moved) {
        // Two ops for one gesture is the house pattern — spec §7 already
        // has a list drag firing set_section *and* set_assignee. The
        // outbox preserves order and they're adjacent in the queue.
        if (d.curTrackId !== d.origTrackId) setSprintTrack(d.sprintId, d.curTrackId);
        if (d.curStart !== d.origStart || d.curEnd !== d.origEnd) {
          setSprintDates(d.sprintId, fmtDateKey(d.curStart), fmtDateKey(d.curEnd));
        }
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
  }, [drag, weekWidth, setSprintDates, setSprintTrack]);

  // The dragged card renders from the live drag, not the snapshot, so
  // the preview follows the cursor without a round trip — and it moves
  // between rows, because the drag carries the track too.
  const relWeek = (ms: number) =>
    Math.round((weekStartOf(ms) - weekStartMs) / (7 * 86400000));

  const draggedSprint = drag
    ? snapshot.tracks.flatMap((r) => r.sprints).find((sp) => sp.id === drag.sprintId) ?? null
    : null;

  const previewOf = (row: PlanTrackRow) => {
    if (!drag || !drag.moved || !draggedSprint) return row.sprints;
    const others = row.sprints.filter((sp) => sp.id !== drag.sprintId);
    if (row.id !== drag.curTrackId) return others;
    const rawStart = relWeek(drag.curStart);
    const rawEnd = relWeek(drag.curEnd);
    return [...others, {
      ...draggedSprint,
      // Takes on the destination row's colour mid-drag, so a retrack
      // reads as one before the pointer comes up.
      color: row.color,
      startWeek: Math.max(0, rawStart),
      endWeek: Math.min(weekCount, rawEnd),
      clipStart: rawStart < 0,
      clipEnd: rawEnd > weekCount,
      lane: 0,
      lanes: Math.max(1, row.lanes),
    }];
  };

  // --- placing a new sprint by sweeping a week range --------------------

  useEffect(() => {
    if (!placing) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setPlacing(false); setRange(null); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [placing]);

  useEffect(() => {
    if (!range) return;
    const cellUnder = (x: number, y: number) => {
      const el = document.elementFromPoint(x, y)?.closest('.plan-cell') as HTMLElement | null;
      if (!el || el.dataset.week === undefined) return null;
      const row = el.closest('.plan-row') as HTMLElement | null;
      if (!row || row.dataset.track === undefined) return null;
      return {
        trackId: row.dataset.track === '' ? null : row.dataset.track,
        idx: Number(el.dataset.week),
      };
    };
    const onMove = (e: PointerEvent) => {
      const r = rangeRef.current;
      if (!r) return;
      const hit = cellUnder(e.clientX, e.clientY);
      // Stay on the row the sweep began in — a sprint lives on one track.
      if (!hit || hit.trackId !== r.trackId || hit.idx === r.to) return;
      setRange({ ...r, to: hit.idx });
    };
    const onUp = () => {
      const r = rangeRef.current;
      setRange(null);
      setPlacing(false);
      if (!r) return;
      const lo = Math.min(r.from, r.to);
      const hi = Math.max(r.from, r.to);
      const startMs = snapshot.weeks[lo];
      const endMs = snapshot.weeks[hi];
      if (startMs == null || endMs == null) return;
      // `ends_on` is exclusive, so the last selected week is included by
      // adding one.
      const d = new Date(endMs);
      const end = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 7).getTime();
      addSprint(projectId, r.trackId, 'New sprint', fmtDateKey(startMs), fmtDateKey(end));
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
    };
  }, [range, snapshot.weeks, addSprint, projectId]);

  // --- gestures ---------------------------------------------------------


  const addTaskToSprint = (sprintId: UUID, title: string) => {
    // 'later', not 'now': addTask derives status from section, and a task
    // planned into a future sprint isn't in progress.
    const id = addTask(projectId, 'later', title);
    if (id) setTaskSprint(id, sprintId);
  };

  /// Put one task next to another in the order. There is no plan-specific
  /// ordering: a checklist row's position is its `sort_key`, the same one
  /// the list curates, so the board drives the same section-scoped
  /// `reorderTasks`. That's deliberate — a card that ordered its rows
  /// privately would reshuffle the moment you looked at the list.
  const moveTaskNextTo = (draggedId: UUID, targetId: UUID, before: boolean) => {
    if (draggedId === targetId) return;
    const dragged = tasks.find((t) => t.id === draggedId);
    const target = tasks.find((t) => t.id === targetId);
    if (!dragged || !target) return;
    if (dragged.project_id !== projectId || target.project_id !== projectId) return;
    // Ordering is `sort_key`, which is section-scoped, so honouring
    // "put this above that" across a boundary means moving the task's
    // *section* — which is exactly what the same drag does in the list.
    // The one crossing that isn't a reorder is the archive: dropping a
    // row into Done would file it away, and dragging one out would
    // un-archive it, neither of which is what "put this above that"
    // means. That crossing is refused; every other one is the list's
    // own behaviour.
    //
    // Keyed on `section`, not `status`: a ticked task still sitting in
    // Now is ordinary work that happens to be finished, and it
    // reorders like any other row.
    if (dragged.section !== target.section
      && (dragged.section === 'done' || target.section === 'done')) return;
    // A card can hold rows from several sections and `reorderTasks` is
    // section-scoped, so landing beside a row in another section means
    // joining that section first — exactly what a list drag does.
    if (dragged.section !== target.section) setTaskSection(draggedId, target.section);
    const ordered = tasks
      .filter((t) => t.project_id === projectId
        && t.section === target.section && t.id !== draggedId)
      .sort((a, b) => a.sort_key.localeCompare(b.sort_key))
      .map((t) => t.id);
    const at = ordered.indexOf(targetId);
    if (at < 0) return;
    ordered.splice(before ? at : at + 1, 0, draggedId);
    reorderTasks(projectId, target.section, ordered);
  };

  /// Turn one reconstructed fortnight into a real sprint. This is the
  /// band's only write, and the answer to "I can't edit them": a record
  /// isn't editable, so editing it means making it a plan first. After
  /// this the bucket's tasks have a `sprint_id`, so the bucket leaves the
  /// band of its own accord.
  ///
  /// Lands on "No track" rather than guessing one — the orphan row is
  /// visible and the card drags onto a track from there.
  const promoteBucket = (b: RetroBucket) => {
    if (readOnly) return;
    const id = addSprint(projectId, null, b.label, b.startsOn, b.endsOn);
    if (!id) return;
    for (const t of b.tasks) setTaskSprint(t.id, id);
  };

  const railTags = useMemo(
    () => allTags.filter((t) => t.project_id === projectId)
      .sort((a, b) => a.title.localeCompare(b.title)),
    [allTags, projectId],
  );

  const orphanRow = snapshot.tracks.find((r) => r.id === null) ?? null;
  const realRows = snapshot.tracks.filter((r) => r.id !== null);
  const confirmTrackRow = confirmTrack
    ? snapshot.tracks.find((r) => r.id === confirmTrack) ?? null
    : null;
  const confirmSprintCard = confirmSprint
    ? snapshot.tracks.flatMap((r) => r.sprints).find((sp) => sp.id === confirmSprint) ?? null
    : null;

  return (
    <div className="plan-wrap"
         data-history={readOnly || undefined}
         data-revision={readOnly && !historyError ? history?.data.revision : undefined}
         aria-busy={historyLoading}
         data-placing={placing || undefined}
         data-dragging={drag ? true : undefined}>
      <div className="cal-toolbar plan-toolbar">
        {/* Panning and sizing are separate controls. They used to be
            one cluster where every button changed the window's *size* —
            chevrons that grew it rather than moving it, and a lone "−"
            that meant "drop the last week". Nobody reads a chevron that
            way. */}
        <div className="week-nav">
          <button className="week-nav-btn" title="Back one week"
                  onClick={() => setPlanWindow(weekOffset - 1, weekCount)}>
            <ChevronLeft size={14} strokeWidth={1.75} />
          </button>
          <button className="week-nav-btn week-nav-today" title="Jump back to this week"
                  onClick={backToNow}>
            now
          </button>
          <button className="week-nav-btn" title="Forward one week"
                  onClick={() => setPlanWindow(weekOffset + 1, weekCount)}>
            <ChevronRight size={14} strokeWidth={1.75} />
          </button>
        </div>

        <div className="week-nav" title={`${weekCount} weeks shown`}>
          <button className="week-nav-btn" title="Show fewer weeks"
                  disabled={weekCount <= 4}
                  onClick={() => setPlanWindow(weekOffset, weekCount - 2)}>
            <Minus size={14} strokeWidth={1.75} />
          </button>
          <span className="week-nav-count">{weekCount}w</span>
          <button className="week-nav-btn" title="Show more weeks"
                  disabled={weekCount >= 52}
                  onClick={() => setPlanWindow(weekOffset, weekCount + 2)}>
            <Plus size={14} strokeWidth={1.75} />
          </button>
        </div>

        <div className="week-nav plan-width" role="group" aria-label="Week width">
          {(['s', 'm', 'l'] as const).map((w) => (
            <button key={w} className="week-nav-btn" data-on={weekWidth === w}
                    aria-pressed={weekWidth === w}
                    title={`${{ s: 'Narrow', m: 'Medium', l: 'Wide' }[w]} week columns`}
                    onClick={() => setPlanWeekWidth(w)}>
              {w.toUpperCase()}
            </button>
          ))}
        </div>

        <span className="plan-toolbar-sep" />

        {/* Independent switches, so one segmented control with a
            filled on-state rather than three loose buttons: they are a
            set, they are not exclusive, and `aria-pressed` says which.
            Each is also reachable from the thing it hides — the rail has
            its own close button. */}
        <div className="week-nav plan-toggles" role="group" aria-label="Show">
          <button className="week-nav-btn" data-on={showInbox}
                  aria-pressed={showInbox}
                  title={showInbox ? 'Hide the unplanned rail' : 'Show the unplanned rail'}
                  onClick={togglePlanInbox}>
            <PanelLeft size={12} strokeWidth={1.75} /> Inbox
          </button>
          <button className="week-nav-btn" data-on={showTasks}
                  aria-pressed={showTasks}
                  title={showTasks ? 'Hide each card\'s checklist' : 'Show each card\'s checklist'}
                  onClick={togglePlanTasks}>
            <ListChecks size={12} strokeWidth={1.75} /> Tasks
          </button>
          <button className="week-nav-btn" data-on={showRetro}
                  aria-pressed={showRetro}
                  title={showRetro
                    ? 'Hide the finished-work band'
                    : 'Show finished work that was never planned'}
                  onClick={togglePlanRetro}>
            <Archive size={12} strokeWidth={1.75} /> Unplanned
          </button>
          {!playground && <button className="week-nav-btn" data-on={showHistory}
                  aria-pressed={showHistory}
                  title={showHistory ? 'Hide history and return to the live plan' : 'Show the plan history scrubber'}
                  onClick={toggleHistory}>
            <History size={12} strokeWidth={1.75} /> Past
          </button>}
        </div>

        <span className="plan-toolbar-sep" />

        {!playground && showHistory && <div className="week-nav">
          <button className="week-nav-btn" aria-label="Return to live plan"
            data-on={!readOnly} onClick={() => setVersionAt(null)}>Live</button>
        </div>}
        <div className="week-nav plan-adds" role="group" aria-label="Add">
          <button className="week-nav-btn"
                  disabled={readOnly}
                  title="Add a track — one row on the board"
                  onClick={() => addTrack(projectId, 'New track')}>
            <Plus size={12} strokeWidth={1.75} /> Track
          </button>
          <button className="week-nav-btn" data-on={placing}
                  aria-pressed={placing}
                  disabled={readOnly}
                  title="Click, then drag across the weeks the sprint should cover"
                  onClick={() => { setPlacing((v) => !v); setRange(null); }}>
            <Plus size={12} strokeWidth={1.75} /> Sprint
          </button>
        </div>
        {placing && (
          <span className="plan-hint">Drag across the weeks · Esc to cancel</span>
        )}
      </div>

      <div className="plan-body">
        {showInbox && (
          <PlanRail
            tasks={snapshot.inbox}
            key={readOnly ? 'history' : 'live'}
            readOnly={readOnly}
            tags={readOnly ? [] : railTags}
            onOpen={openTask}
            onDropOut={(taskId) => setTaskSprint(taskId, null)}
            projectId={projectId}
          />
        )}

        <div className="plan-scroll" ref={gridRef}
             style={{ '--plan-week-w': `${WEEK_W[weekWidth]}px`,
                      '--plan-weeks': snapshot.weeks.length } as React.CSSProperties}>
          <div className="plan-axis">
            <div className="plan-axis-months">
              <div className="plan-axis-pad" />
              {monthSpans.map((m, i) => (
                <div key={`${m.label}-${i}`} className="plan-month"
                     style={{ gridColumn: `span ${m.weeks}` }}>
                  {/* The label floats inside its own span — see
                      `.plan-month > span`. */}
                  <span>{m.label}</span>
                </div>
              ))}
            </div>
            <div className="plan-axis-weeks">
              <div className="plan-axis-pad" />
              {snapshot.weeks.map((ms, i) => (
                <div key={ms} className="plan-week"
                     data-now={i === snapshot.nowWeek || undefined}>
                  {isoWeekLabel(ms)}
                </div>
              ))}
            </div>
          </div>

          <div className="plan-rows">
            {realRows.map((row, i) => (
              <TrackRow
                key={row.id ?? 'orphan'}
                readOnly={readOnly}
                row={row}
                sprints={previewOf(row)}
                showTasks={showTasks}
                weeks={snapshot.weeks}
                nowWeek={snapshot.nowWeek}
                dragging={drag?.moved ? drag.sprintId : null}
                dropping={drag?.moved ? drag.curTrackId === row.id : false}
                onRename={(title) => row.id && setTrackTitle(row.id, title)}
                onDelete={() => setConfirmTrack(row.id)}
                onMoveUp={i > 0 ? () => {
                  const ids = realRows.map((r) => r.id!) ;
                  [ids[i - 1], ids[i]] = [ids[i], ids[i - 1]];
                  reorderTracks(projectId, ids);
                } : undefined}
                onMoveDown={i < realRows.length - 1 ? () => {
                  const ids = realRows.map((r) => r.id!);
                  [ids[i], ids[i + 1]] = [ids[i + 1], ids[i]];
                  reorderTracks(projectId, ids);
                } : undefined}
                placing={placing}
                range={range && range.trackId === row.id ? range : null}
                onRangeStart={(idx) => setRange({ trackId: row.id, from: idx, to: idx })}
                onSprintPointerDown={(e, id) => beginDrag(e, id, 'move')}
                onSprintResizeDown={(e, id, edge) =>
                  beginDrag(e, id, edge === 'start' ? 'resize-start' : 'resize-end')}
                onSprintRename={setSprintTitle}
                onSprintDelete={setConfirmSprint}
                onDropTask={setTaskSprint}
                onTick={tickTask}
                onRemoveTask={(taskId) => setTaskSprint(taskId, null)}
                onAddTask={addTaskToSprint}
                onOpenTask={openTask}
                onReorderTask={moveTaskNextTo}
              />
            ))}

            {orphanRow && (
              <TrackRow
                readOnly={readOnly}
                row={orphanRow}
                sprints={previewOf(orphanRow)}
                showTasks={showTasks}
                weeks={snapshot.weeks}
                nowWeek={snapshot.nowWeek}
                dragging={drag?.moved ? drag.sprintId : null}
                dropping={drag?.moved ? drag.curTrackId === null : false}
                placing={placing}
                range={range && range.trackId === null ? range : null}
                onRangeStart={(idx) => setRange({ trackId: null, from: idx, to: idx })}
                onSprintPointerDown={(e, id) => beginDrag(e, id, 'move')}
                onSprintResizeDown={(e, id, edge) =>
                  beginDrag(e, id, edge === 'start' ? 'resize-start' : 'resize-end')}
                onSprintRename={setSprintTitle}
                onSprintDelete={setConfirmSprint}
                onDropTask={setTaskSprint}
                onTick={tickTask}
                onRemoveTask={(taskId) => setTaskSprint(taskId, null)}
                onAddTask={addTaskToSprint}
                onOpenTask={openTask}
                onReorderTask={moveTaskNextTo}
              />
            )}

            {/* The reconstructed past. Not a plan, and the row says so:
                it holds finished work that was never planned into a
                sprint, derived on every render from completed blocks and
                finish dates. Nothing generates or refreshes it, so work
                you finish today appears in today's fortnight whether or
                not you are using sprints at all.

                It is read-only *as a record* — but not a dead end. Drag
                a row into a sprint, or promote the whole fortnight, and
                it becomes an ordinary card. Either way those tasks then
                have a sprint_id and the bucket drops out of the band. */}
            {showRetro && snapshot.retro.length > 0 && (
              <div className="plan-row plan-row-retro">
                <div className="plan-row-head plan-row-head-stacked"
                     title={readOnly ? 'Finished work outside sprints at this revision, grouped by its recorded finish date (or creation date).'
                       : 'Finished work that was never planned into a sprint, '
                       + 'grouped by fortnight and rebuilt from completed time '
                       + 'blocks (or the finish date when there are none).\n\n'
                       + 'Derived live — there is nothing to regenerate. To plan '
                       + 'any of it, drag a row onto a sprint card or press '
                       + 'Promote to turn the whole fortnight into one.'}>
                  {/* Named for the toolbar switch that shows it, so the
                      button and the band are visibly the same thing. */}
                  <span className="plan-row-title">Unplanned</span>
                  <span className="plan-row-sub">finished, never planned</span>
                </div>
                <div className="plan-row-grid">
                  {snapshot.retro.map((b) => (
                    <div key={b.startMs} className="plan-card plan-card-retro"
                         data-clip-start={b.clipStart || undefined}
                         data-clip-end={b.clipEnd || undefined}
                         style={{ gridColumn: `${b.startWeek + 1} / ${b.endWeek + 1}`,
                                  gridRow: 1 }}>
                      <div className="plan-card-head">
                        <span className="plan-badge">{b.label}</span>
                        {/* Only offered for a bucket wholly inside the
                            window: promoting a clipped one would invent a
                            span out of the part you can see. */}
                        {!readOnly && !b.clipStart && !b.clipEnd && (
                          <button className="plan-card-promote"
                                  title={`Make a real sprint from ${b.label} `
                                    + `with these ${b.totalCount} task`
                                    + `${b.totalCount === 1 ? '' : 's'}. `
                                    + 'It lands on "No track" — drag it onto one.'}
                                  onClick={() => promoteBucket(b)}>
                            Promote
                          </button>
                        )}
                      </div>
                      {showTasks && (
                        <ul className="plan-card-tasks">
                          {b.tasks.map((t) => (
                            <li key={t.id} className="plan-task" data-done
                                draggable={!readOnly}
                                title={t.title}
                                onDragStart={(e) => {
                                  if (readOnly) { e.preventDefault(); return; }
                                  e.dataTransfer.effectAllowed = 'move';
                                  e.dataTransfer.setData(PLAN_TASK_MIME, t.id);
                                  e.dataTransfer.setData('text/plain', t.title);
                                }}
                                onClick={() => !readOnly && openTask(t.id)}>
                              <span className="plan-task-title">{t.title}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {!playground && showHistory && <section className="plan-history-panel" aria-label="Plan history">
        <PlanTimeline history={history?.data ?? null}
          selectedAt={versionAt} selectedSeq={versionSeq} onSelect={setVersionAt}
          status={historyError ? <><span className="plan-history-message" title={historyError}>{historyError}</span> <button onClick={() => setRetryHistory((v) => v + 1)}>Retry</button></>
            : historyLoading || !history ? 'Loading…'
            : !history.data.genesis ? 'No recorded plan history yet' : null} />
      </section>}

      {confirmSprintCard && (
        <ConfirmDelete
          title={`Delete sprint "${confirmSprintCard.title}"?`}
          body={
            confirmSprintCard.totalCount > 0 ? (
              <p>
                Its {confirmSprintCard.totalCount} task
                {confirmSprintCard.totalCount === 1 ? '' : 's'} lose their
                sprint and return to the rail. No task is deleted.
              </p>
            ) : (
              <p>The sprint is empty.</p>
            )
          }
          onCancel={() => setConfirmSprint(null)}
          onConfirm={() => {
            if (confirmSprint) deleteSprint(confirmSprint);
            setConfirmSprint(null);
          }}
        />
      )}

      {confirmTrackRow && (
        <ConfirmDelete
          title={`Delete track "${confirmTrackRow.title}"?`}
          body={
            <>
              {confirmTrackRow.sprints.length > 0 ? (
                <p>
                  Its {confirmTrackRow.sprints.length} sprint
                  {confirmTrackRow.sprints.length === 1 ? '' : 's'} move to a
                  "No track" row at the foot of the board. No task is deleted.
                </p>
              ) : (
                <p>The track is empty.</p>
              )}
            </>
          }
          onCancel={() => setConfirmTrack(null)}
          onConfirm={() => {
            if (confirmTrack) deleteTrack(confirmTrack);
            setConfirmTrack(null);
          }}
        />
      )}
    </div>
  );
}

function TrackRow(props: {
  readOnly?: boolean;
  row: PlanTrackRow;
  sprints: PlanTrackRow['sprints'];
  showTasks: boolean;
  weeks: number[];
  /// Index into `weeks` of the current week, or -1. Tints that column.
  nowWeek: number;
  /// Id of the card currently being dragged anywhere on the board.
  dragging: UUID | null;
  /// This row is the drag's current destination.
  dropping: boolean;
  onRename?: (title: string) => void;
  onDelete?: () => void;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  placing: boolean;
  range: PlaceRange | null;
  onRangeStart: (weekIdx: number) => void;
  onSprintPointerDown: (e: React.PointerEvent, id: UUID) => void;
  onSprintResizeDown: (e: React.PointerEvent, id: UUID, edge: 'start' | 'end') => void;
  onSprintRename: (id: UUID, title: string) => void;
  onSprintDelete: (id: UUID) => void;
  onDropTask: (taskId: UUID, sprintId: UUID) => void;
  onTick: (taskId: UUID, done: boolean) => void;
  onRemoveTask: (taskId: UUID) => void;
  onAddTask: (sprintId: UUID, title: string) => void;
  onOpenTask: (taskId: UUID) => void;
  onReorderTask: (draggedId: UUID, targetId: UUID, before: boolean) => void;
}) {
  const { row, sprints, showTasks, dropping, weeks, placing, range } = props;
  const [renaming, setRenaming] = useState(false);
  const [draft, setDraft] = useState(row.title);
  useEffect(() => { setDraft(row.title); }, [row.title]);

  const commit = () => {
    const t = draft.trim();
    setRenaming(false);
    if (t && t !== row.title && props.onRename) props.onRename(t);
    else setDraft(row.title);
  };

  const lanes = Math.max(1, row.lanes);

  return (
    <div className="plan-row"
         // Read by the drag's hit-test. Empty string is the "No track"
         // row; absent (the retro band) means "not a drop target".
         data-track={row.id ?? ''}
         data-over={dropping || undefined}
         style={{ '--track-color': row.color } as React.CSSProperties}>
      <div className="plan-row-head">
        {renaming ? (
          <input autoFocus className="plan-row-title-input" value={draft}
                 onChange={(e) => setDraft(e.target.value)}
                 onBlur={commit}
                 onKeyDown={(e) => {
                   if (e.key === 'Enter') commit();
                   if (e.key === 'Escape') { setDraft(row.title); setRenaming(false); }
                 }} />
        ) : (
          <button className="plan-row-title" title={row.title}
                  disabled={props.readOnly || props.onRename == null}
                  onClick={() => props.onRename && setRenaming(true)}>
            {row.title}
          </button>
        )}
        {!props.readOnly && props.onDelete && <div className="plan-row-actions" role="group" aria-label="Track controls">
            <button className="plan-row-btn" title="Move track up" aria-label="Move track up"
                    disabled={!props.onMoveUp} onClick={props.onMoveUp}>
              <ChevronUp size={12} strokeWidth={2} />
            </button>
            <button className="plan-row-btn" title="Move track down" aria-label="Move track down"
                    disabled={!props.onMoveDown} onClick={props.onMoveDown}>
              <ChevronDown size={12} strokeWidth={2} />
            </button>
            <button className="plan-row-btn plan-row-del" title="Delete track"
                    aria-label="Delete track"
                    onClick={props.readOnly ? undefined : props.onDelete}>
              <Trash2 size={11} strokeWidth={1.75} />
            </button>
        </div>}
      </div>
      {/* `minmax` rather than `auto`: a track with no cards collapses its
          lane row to 0px, which made the week cells zero-height and the
          row impossible to sweep a new sprint onto — the one row where
          you most want to. */}
      <div className="plan-row-grid"
           style={{ gridTemplateRows: `repeat(${lanes}, minmax(var(--plan-lane-h), auto))` }}>
        {/* Column rules behind the cards. Also the create gesture: on a
            timeline board, clicking the week you want a sprint to start
            is what people reach for first. */}
        {weeks.map((ms, i) => (
          <div key={ms} className="plan-cell"
               data-week={i}
               data-now={i === props.nowWeek || undefined}
               onPointerDown={(e) => {
                 if (!placing || e.button !== 0) return;
                 e.preventDefault();
                 props.onRangeStart(i);
               }}
               style={{ gridColumn: i + 1, gridRow: '1 / -1' }} />
        ))}
        {range && (
          <div className="plan-range"
               style={{
                 gridColumn: `${Math.min(range.from, range.to) + 1} / ${Math.max(range.from, range.to) + 2}`,
                 gridRow: '1 / -1',
               }}>
            {Math.abs(range.to - range.from) + 1}w
          </div>
        )}
        {sprints.map((sp) => (
          <PlanSprintCard
            key={sp.id}
            sprint={sp}
            showTasks={showTasks}
            dragging={props.dragging === sp.id}
            onMovePointerDown={props.readOnly ? undefined : (e) => props.onSprintPointerDown(e, sp.id)}
            onResizePointerDown={props.readOnly ? undefined : (e, edge) => props.onSprintResizeDown(e, sp.id, edge)}
            onRename={props.readOnly ? undefined : (title) => props.onSprintRename(sp.id, title)}
            onDelete={props.readOnly ? undefined : () => props.onSprintDelete(sp.id)}
            onDropTask={props.readOnly ? undefined : (taskId) => props.onDropTask(taskId, sp.id)}
            onTick={props.readOnly ? undefined : props.onTick}
            onRemoveTask={props.readOnly ? undefined : props.onRemoveTask}
            onAddTask={props.readOnly ? undefined : (title) => props.onAddTask(sp.id, title)}
            onOpenTask={props.readOnly ? undefined : props.onOpenTask}
            onReorderTask={props.readOnly ? undefined : props.onReorderTask}
          />
        ))}
      </div>
    </div>
  );
}

/// Sections in the order the list shows them. `done` is absent by
/// construction: the inbox predicate excludes finished work, which lives
/// in the retro band instead.
const RAIL_SECTIONS: { key: Section; label: string }[] = [
  { key: 'now', label: 'Now' },
  { key: 'later', label: 'Later' },
  { key: 'recurring', label: 'Recurring' },
  { key: 'someday', label: 'Someday' },
];

/// Unplanned project tasks — the board's left rail.
///
/// Deliberately the calendar rail's markup and classes, not a lookalike:
/// it is the same object (a task waiting to be scheduled) answering the
/// same question (what have I not placed yet), so it should not be a
/// second thing to learn. Filter box, collapsible groups with counts,
/// `.rail-task` rows, drag onto the board.
///
/// One substitution: the calendar groups by *project* and filters by
/// project, which is meaningless here because the board is already
/// scoped to one. Groups are **sections** and the filter panel is
/// **tags** — the two axes that actually divide a single project's
/// unplanned work.
function PlanRail({ tasks, tags, projectId, onOpen, onDropOut, readOnly = false }: {
  readOnly?: boolean;
  tasks: PlanTask[];
  tags: Tag[];
  projectId: UUID;
  onOpen: (id: UUID) => void;
  onDropOut: (taskId: UUID) => void;
}) {
  const [over, setOver] = useState(false);
  const [query, setQuery] = useState('');
  const [picked, setPicked] = useState<UUID[]>([]);
  const [tagMode, setTagMode] = useState<'and' | 'or'>('or');
  const [collapsed, setCollapsed] = useState<Set<Section>>(() => new Set());

  const q = query.trim().toLowerCase();
  const shown = tasks.filter((t) => {
    if (q && !t.title.toLowerCase().includes(q)
      && !(t.externalId?.toLowerCase().includes(q) ?? false)) return false;
    // Same and/or semantics as the list, because it is the list's
    // control doing the selecting.
    if (picked.length > 0) {
      const match = tagMode === 'and'
        ? picked.every((id) => t.tagIds.includes(id))
        : picked.some((id) => t.tagIds.includes(id));
      if (!match) return false;
    }
    return true;
  });
  // Every section, always, even at zero. A section that disappears when
  // it empties makes the rail's shape jump as you plan work, and "is
  // there anything in Now?" is a question the rail should answer rather
  // than leave to be inferred from an absence.
  const groups = RAIL_SECTIONS
    .map((sec) => ({ ...sec, tasks: shown.filter((t) => t.section === sec.key) }));

  const toggleSection = (key: Section) =>
    setCollapsed((cur) => {
      const next = new Set(cur);
      if (!next.delete(key)) next.add(key);
      return next;
    });

  return (
    <aside className="cal-rail plan-rail" data-over={over || undefined}
           onDragOver={(e) => {
             if (readOnly || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
             e.preventDefault();
             e.dataTransfer.dropEffect = 'move';
             setOver(true);
           }}
           onDragLeave={() => setOver(false)}
           onDrop={(e) => {
             setOver(false);
             if (readOnly || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
             e.preventDefault();
             const id = e.dataTransfer.getData(PLAN_TASK_MIME);
             if (id) onDropOut(id);
           }}>
      <div className="rail-head">
        <input
          className="rail-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter…"
          spellCheck={false}
          onKeyDown={(e) => { if (e.key === 'Escape') setQuery(''); }}
        />
      </div>
      <div className="rail-body">
        {tags.length > 0 && (
          <div className="plan-rail-tags">
            <ListTagFilter
              projectId={projectId}
              allTags={tags}
              tagIds={picked}
              mode={tagMode}
              scope="all"
              showAssigneeScope={false}
              onChange={setPicked}
              onModeChange={setTagMode}
              onScopeChange={() => {}}
            />
          </div>
        )}

        {/* The list's own section heading — caret, name, count, trailing
            rule — not the calendar rail's project-group bar. Same
            sections, same words, so the two surfaces read as one
            document. */}
        {groups.map((g) => {
          const shut = collapsed.has(g.key);
          return (
            <div key={g.key} className="rail-group plan-rail-group"
                 data-section={g.key}
                 data-collapsed={shut || undefined}>
              <div className="section-head" role="button" tabIndex={0}
                   aria-expanded={!shut}
                   onClick={() => toggleSection(g.key)}
                   onKeyDown={(e) => {
                     if (e.key === 'Enter' || e.key === ' ') {
                       e.preventDefault();
                       toggleSection(g.key);
                     }
                   }}>
                {/* Name first, flush with the rail's left gutter; the
                    rows indent under it. The caret led the row before,
                    which pushed every heading inward and left the
                    headings sitting to the *right* of their own tasks.

                    No trailing `.rule`. The list uses one because its
                    sections are page-wide and the line reads as an
                    underline; in a 220px column it reads instead as a
                    line *closing* the group above it, so each section
                    looked like a title, some subtasks, and then an end
                    marker. Whitespace separates the blocks here. */}
                <h2>{g.label}</h2>
                <span className="count">{g.tasks.length}</span>
                <span className="plan-rail-spacer" />
                <span className="caret">
                  {shut
                    ? <ChevronRight size={14} strokeWidth={1.75} />
                    : <ChevronDown size={14} strokeWidth={1.75} />}
                </span>
              </div>
              {/* One line, title only. The rail's rows are the same
                  object as a card's checklist rows and sit a few
                  hundred pixels from them, so they are built to the
                  same rhythm — `--plan-task-h`. The estimate, the
                  external id and the tag dots that used to ride along
                  here doubled the row's height to say things this view
                  doesn't ask: a plan board's question is *where does
                  this go*, and the tag filter above already slices by
                  tag. */}
              {!shut && g.tasks.map((t) => (
                <div key={t.id} className="plan-rail-task"
                     draggable={!readOnly}
                     onDragStart={(e) => {
                       e.dataTransfer.effectAllowed = 'move';
                       e.dataTransfer.setData(PLAN_TASK_MIME, t.id);
                       e.dataTransfer.setData('text/plain', t.title);
                     }}
                     onClick={() => !readOnly && onOpen(t.id)}
                     title={t.title}>
                  {t.title}
                </div>
              ))}
            </div>
          );
        })}

        {shown.length === 0 && (
          <p className="plan-rail-empty">
            {tasks.length === 0
              ? 'Everything is planned.'
              : 'Nothing matches that filter.'}
          </p>
        )}
      </div>
    </aside>
  );
}
