import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Archive, Check, ChevronDown, ChevronRight, Clock, MoreHorizontal, Pencil } from 'lucide-react';
import { useFira } from '../store';
import { SearchField } from './SearchField';
import { useCanEditProject } from '../permissions';
import { TagFilterChips, TagMenu } from './TagFilter';
import { useLongPress } from '../useLongPress';
import { useAutosizeTextarea, useIsMobile } from '../hooks';
import { fmtMin, fmtWeekOf, taskCompletedMin, taskPlannedMin, taskTimeLeft } from '../time';
import { ProjectIcon } from './ProjectIcon';
import { ConfirmDelete } from './ConfirmDelete';
import { Select } from './Select';
import type { SelectOption } from './Select';
import type { Sprint, Tag, Task, TimeBlock, Section, Track, UUID } from '../types';

const byKey = (a: Task, b: Task) => a.sort_key.localeCompare(b.sort_key);

/// Grow an inline-edit textarea to exactly the height of its own text.
///
/// Every textarea in this view renders `rows={1}` with `overflow-y:
/// hidden`, so a title that wraps loses everything past the first line
/// unless something stretches the box — and the caret scrolls the hidden
/// remainder in and out of view as it moves. Only the task title had a
/// stretcher, the CSS mirror in `.title-autosize::after`, and a mirror is
/// only right while it breaks lines exactly where the textarea does (see
/// the letter-spacing note on `.list-title-input`). Measuring the
/// textarea itself can't disagree with the textarea.
function fitToText(ta: HTMLTextAreaElement) {
  ta.style.height = 'auto';
  ta.style.height = `${ta.scrollHeight}px`;
}

export function ListView() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const projects = useFira((s) => s.projects);
  const allTags = useFira((s) => s.tags);
  const sprints = useFira((s) => s.sprints);
  const tracks = useFira((s) => s.tracks);
  const users = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const listFilter = useFira((s) => s.listFilter);
  const setListFilter = useFira((s) => s.setListFilter);
  const showListTimes = useFira((s) => s.showListTimes);
  const setShowListTimes = useFira((s) => s.setShowListTimes);
  const tickTask = useFira((s) => s.tickTask);
  const tickSubtask = useFira((s) => s.tickSubtask);
  const setSubtaskTitle = useFira((s) => s.setSubtaskTitle);
  const deleteSubtask = useFira((s) => s.deleteSubtask);
  const addSubtask = useFira((s) => s.addSubtask);
  const setTaskSection = useFira((s) => s.setTaskSection);
  const setTaskAssignee = useFira((s) => s.setTaskAssignee);
  const setTaskTitle = useFira((s) => s.setTaskTitle);
  const deleteTask = useFira((s) => s.deleteTask);
  const reorderTasks = useFira((s) => s.reorderTasks);
  const reorderSubtasks = useFira((s) => s.reorderSubtasks);
  const addTask = useFira((s) => s.addTask);
  const addTaskAfter = useFira((s) => s.addTaskAfter);
  const mergeTaskInto = useFira((s) => s.mergeTaskInto);
  const openTask = useFira((s) => s.openTask);
  const openEditProject = useFira((s) => s.openEditProject);
  const openCreateProject = useFira((s) => s.openCreateProject);
  const myWorkspaceRole = useFira((s) => s.myWorkspaceRole);
  const canCreateProject = myWorkspaceRole === 'owner';

  const project = projects.find((p) => p.id === listFilter.project_id);
  // Workspace owner can edit any project; project leads/owners can edit
  // theirs. Members and outsiders see no pencil.
  const canEditProject = useCanEditProject();
  const canEditThisProject = !!project && canEditProject(project.id);

  // Hooks must run unconditionally on every render — the empty-state branch
  // below is an early return, so all useState/useRef calls live above it.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ done: true, someday: true });
  const [collapsedAssignee, setCollapsedAssignee] = useState<Record<UUID, boolean>>({});
  const [collapsedArchiveGroups, setCollapsedArchiveGroups] = useState<Record<string, boolean>>({});
  const [confirmArchive, setConfirmArchive] = useState(false);
  const [projMenuOpen, setProjMenuOpen] = useState(false);
  const projMenuRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!projMenuOpen) return;
    const onDown = (e: PointerEvent) => {
      if (projMenuRef.current && !projMenuRef.current.contains(e.target as Node)) setProjMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setProjMenuOpen(false); };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [projMenuOpen]);
  const [dropTarget, setDropTarget] = useState<Section | null>(null);
  const [assigneeDropTarget, setAssigneeDropTarget] = useState<UUID | null>(null);
  const [rowDropAt, setRowDropAt] = useState<{ id: UUID; pos: 'before' | 'after' | 'merge' } | null>(null);
  // A merge is destructive (the source task is consumed and deleted), so
  // a drop onto the "merge" zone stages it here and waits for explicit
  // confirmation rather than firing immediately.
  const [pendingMerge, setPendingMerge] = useState<{ sourceId: UUID; targetId: UUID } | null>(null);
  // Per-task subtask-list visibility. Default is collapsed for every task —
  // the list now treats subtasks like Notion-style nested bullets that
  // expand on demand. When `addSubtask` / Tab-demote produce a new subtask
  // we auto-expand the parent so the user sees what they just created.
  const [expandedSubs, setExpandedSubs] = useState<Record<UUID, boolean>>({});
  // Auto-edit handoff: when a key action mints a fresh task or subtask,
  // we stamp its id here so the row picks it up on mount and switches
  // straight into edit mode (mirrors the TaskModal's `focusId` pattern).
  const [autoEditTaskId, setAutoEditTaskId] = useState<UUID | null>(null);
  const [autoEditSubId, setAutoEditSubId] = useState<UUID | null>(null);
  // After a drop, the cursor sits at the same screen position it was in
  // when the user released — but the row underneath it is now a *different*
  // task (the dragged task moved elsewhere), so :hover lights up the wrong
  // row. Suspend the hover background until the user nudges the cursor or
  // a short timeout lapses, whichever comes first.
  const [hoverSuspended, setHoverSuspended] = useState(false);
  // Title / ext-id / sprint search. Local and unpersisted, like the
  // calendar rail's filter — it's a "find that one task" tool, not a
  // standing view, so it clears when the project changes.
  const [query, setQuery] = useState('');
  useEffect(() => { setQuery(''); }, [listFilter.project_id]);

  // All hook calls (useRef / useEffect / useState) MUST run on every
  // render — including the empty-state path below. Hoisted up here
  // because the create-first-project flow transitions an instance from
  // empty (early-return) to populated (full render), and React's
  // rules-of-hooks rejects a hooks-count change between renders. The
  // refs / cleanup effect themselves don't depend on `project`; they
  // just need to be declared in stable order.
  const desktopDragIdRef = useRef<UUID | null>(null);
  const listScrollRef = useRef<HTMLDivElement>(null);
  // The sticky filter bar only draws its bottom rule once the list has
  // scrolled under it; at rest the section headings carry the only lines.
  const [listScrolled, setListScrolled] = useState(false);
  const dragScrollStopRef = useRef<(() => void) | null>(null);
  const dragCursorRef = useRef<{ x: number; y: number } | null>(null);
  const touchDraggedRef = useRef<UUID | null>(null);
  const touchDropAtRef = useRef<{ id: UUID; pos: 'before' | 'after' | 'merge' } | null>(null);
  const touchSectionRef = useRef<Section | null>(null);
  const touchAssigneeRef = useRef<UUID | null>(null);
  useEffect(() => () => { dragScrollStopRef.current?.(); }, []);

  const suspendHover = () => {
    setHoverSuspended(true);
    const onMove = () => {
      setHoverSuspended(false);
      document.removeEventListener('pointermove', onMove);
      window.clearTimeout(timer);
    };
    const timer = window.setTimeout(() => {
      setHoverSuspended(false);
      document.removeEventListener('pointermove', onMove);
    }, 600);
    document.addEventListener('pointermove', onMove);
  };

  if (!project) {
    // Three empty states:
    //   - workspace has projects but none is selected → prompt to pick one
    //   - workspace has no projects + caller can create → editorial CTA
    //   - workspace has no projects + caller is a plain member → tell them
    //     to ping an admin (membership in a workspace doesn't imply
    //     project access; that has to be granted explicitly)
    return (
      <div className="list">
        <div className="list-doc list-empty">
          {projects.length > 0 ? (
            <p className="list-empty-msg">Pick a project from the sidebar.</p>
          ) : canCreateProject ? (
            <div className="list-empty-cta">
              <p className="list-empty-msg">This workspace has no projects yet.</p>
              <button className="list-empty-link" onClick={openCreateProject}>
                Create your first project
              </button>
            </div>
          ) : (
            <div className="list-empty-cta">
              <p className="list-empty-msg">You're not a member of any project.</p>
              <p className="list-empty-sub">
                Ask a workspace admin to add you to one.
              </p>
            </div>
          )}
        </div>
      </div>
    );
  }

  const allProjectTasks = tasks.filter((t) => t.project_id === project.id);
  // Apply the tag + assignee filter to every section in one place so
  // reorder / assignee / archive helpers (which still operate on
  // `projectTasks`) see only the filtered slice.
  const tagFilter = listFilter.tag_ids;
  const tagMode = listFilter.tag_mode;
  // Default `all` covers persisted state from before this field existed.
  const assigneeScope = listFilter.assignee_scope ?? 'all';
  const projectSprints = sprints.filter((sp) => sp.project_id === project.id);
  const sprintById = new Map(projectSprints.map((sp) => [sp.id, sp] as const));
  // A persisted sprint id can outlive its sprint (deleted elsewhere, or
  // moved projects) — fall back to no sprint filter rather than an
  // inexplicably empty list.
  const rawSprintFilter = listFilter.sprint_filter ?? 'all';
  // Older saved values ('active', 'none') read as "all" now.
  const sprintFilter: SprintFilterValue = sprintById.has(rawSprintFilter) ? rawSprintFilter : 'all';
  const q = query.trim().toLowerCase();
  const filtersActive = q !== '' || sprintFilter !== 'all' || tagFilter.length > 0;
  const clearFilters = () => {
    setQuery('');
    setListFilter({ tag_ids: [], sprint_filter: 'all' });
  };
  const projectTasks = allProjectTasks.filter((t) => {
    if (assigneeScope === 'me' && t.assignee_id !== meId) return false;
    const sprint = t.sprint_id ? sprintById.get(t.sprint_id) : undefined;
    if (sprintFilter !== 'all' && t.sprint_id !== sprintFilter) return false;
    if (q && !(
      t.title.toLowerCase().includes(q)
      || (t.external_id?.toLowerCase().includes(q) ?? false)
      || (sprint?.title.toLowerCase().includes(q) ?? false)
    )) return false;
    if (tagFilter.length > 0) {
      if (tagMode === 'and') {
        return tagFilter.every((id) => t.tag_ids.includes(id));
      }
      return tagFilter.some((id) => t.tag_ids.includes(id));
    }
    return true;
  });
  // Row-level sprint label: redundant when the selector already pins
  // one sprint, so it's dropped there.
  // Title plus its track's colour, drawn as the same small square the
  // sprint picker uses, so the label reads as a sprint and not a date.
  const sprintLabelFor = (t: Task): SprintLabel | null => {
    if (sprintFilter !== 'all' || !t.sprint_id) return null;
    const sp = sprintById.get(t.sprint_id);
    const title = stripProjectPrefix(sp?.title ?? null, project.title);
    if (!sp || !title) return null;
    const color = sp.track_id ? tracks.find((tr) => tr.id === sp.track_id)?.color ?? null : null;
    return { title, color };
  };
  const hasProjectTags = allTags.some((t) => t.project_id === project.id);
  const showAssigneeScope = project.members.filter((m) => m.role !== 'inactive').length > 1;
  // Time totals across the filtered task set. Done / Planned aggregate
  // time blocks (completed / planned) so they reflect what's actually
  // booked on the calendar; Est sums task estimates; Total is the
  // calendar-side roll-up (Done + Planned), distinct from Est which is
  // the user's intent. Useful mainly when a tag filter is active — the
  // numbers answer "how much work is in this tag, and how much of it
  // have I scheduled?".
  let totalDone = 0;
  let totalPlanned = 0;
  let totalEst = 0;
  // For the bar and the overrun, only tasks that have an estimate count:
  // logged time on unestimated work isn't "over" anything. The overrun
  // is the sum of each task's own logged time past its estimate — not
  // total done minus total estimate, which counted unestimated work.
  let estDone = 0;
  let estPlanned = 0;
  let totalOver = 0;
  for (const t of projectTasks) {
    const done = taskCompletedMin(t, blocks);
    const planned = taskPlannedMin(t, blocks);
    totalDone += done;
    totalPlanned += planned;
    if (t.estimate_min != null && !t.has_private_time) {
      const est = t.estimate_min;
      totalEst += est;
      const doneIn = Math.min(done, est);
      estDone += doneIn;
      estPlanned += Math.min(planned, est - doneIn);
      totalOver += Math.max(0, done - est);
    }
  }
  const privateTimeExcluded = projectTasks.some((task) => task.has_private_time);

  const nowTasks = projectTasks.filter((t) => t.section === 'now').sort(byKey);
  const laterTasks = projectTasks.filter((t) => t.section === 'later').sort(byKey);
  const recurringTasks = projectTasks.filter((t) => t.section === 'recurring').sort(byKey);
  const somedayTasks = projectTasks.filter((t) => t.section === 'someday').sort(byKey);
  // Per-section estimate roll-up. Surfaced next to the task count so a
  // section's "weight" (especially Someday, which collects intentions
  // indefinitely) is visible without expanding the list.
  const sumEst = (xs: Task[]) => xs.reduce((s, t) => s + (t.estimate_min ?? 0), 0);
  const nowEst = sumEst(nowTasks);
  // Now reads as work remaining: each estimated task's time left, floored
  // at zero so one overrun doesn't eat into the rest.
  const nowLeft = nowTasks.reduce((s, t) => {
    if (t.estimate_min == null) return s;
    const l = taskTimeLeft(t, blocks);
    return s + Math.max(0, l ?? t.estimate_min);
  }, 0);
  const laterEst = sumEst(laterTasks);
  const recurringEst = sumEst(recurringTasks);
  const somedayEst = sumEst(somedayTasks);
  // Done section reads as actual time spent rather than original estimate —
  // for completed work, "how long did this take" is the meaningful number.
  const doneDone = projectTasks
    .filter((t) => t.section === 'done')
    .reduce((s, t) => s + taskCompletedMin(t, blocks), 0);
  // Done sorts newest-finished-first. Falls back to created_at for
  // legacy rows from before migration 0017 where finished_at wasn't
  // recorded — approximate but stable across edits.
  const doneTasks = projectTasks
    .filter((t) => t.section === 'done')
    .sort((a, b) => (b.finished_at ?? b.created_at).localeCompare(a.finished_at ?? a.created_at));
  const doneGroups = groupArchivedTasks(doneTasks);
  // Caller floats to the top of the assignee groups; the rest stay in
  // membership order. Members with role 'owner' (the workspace owner's
  // default per-project stance) or 'inactive' (a member who's been parked)
  // are hidden unless they have a Now task assigned — otherwise they'd
  // render as empty assignee groups regardless of involvement.
  const nowAssignees = new Set(nowTasks.map((t) => t.assignee_id).filter((x): x is UUID => !!x));
  const visibleMembers = project.members.filter(
    (m) => {
      // Me-scope collapses Now to just the caller's group — every other
      // member's tasks are filtered out anyway, so leaving their empty
      // headings around is just noise.
      if (assigneeScope === 'me') return m.user_id === meId;
      return (m.role !== 'owner' && m.role !== 'inactive') || nowAssignees.has(m.user_id);
    },
  );
  const memberIds = visibleMembers.map((m) => m.user_id);
  const assigneeIds = meId && memberIds.includes(meId)
    ? [meId, ...memberIds.filter((u) => u !== meId)]
    : memberIds;

  const userById = (id: string | null) => users.find((u) => u.id === id);

  const applyTaskMove = (draggedId: UUID, target: Task, insertBefore: boolean) => {
    if (!draggedId || draggedId === target.id) return;
    const dragged = tasks.find((t) => t.id === draggedId);
    if (!dragged || dragged.project_id !== target.project_id) return;
    if (dragged.section !== target.section) {
      setTaskSection(draggedId, target.section);
    }
    if (
      target.section === 'now' &&
      target.assignee_id != null &&
      dragged.assignee_id !== target.assignee_id
    ) {
      setTaskAssignee(draggedId, target.assignee_id);
    }
    const sectionList = projectTasks
      .filter((t) => t.section === target.section && t.id !== draggedId)
      .sort(byKey)
      .map((t) => t.id);
    const targetIdx = sectionList.indexOf(target.id);
    const insertIdx = insertBefore ? targetIdx : targetIdx + 1;
    sectionList.splice(insertIdx, 0, draggedId);
    reorderTasks(target.project_id, target.section, sectionList);
  };

  // (Refs for desktop / touch drag + edge-scroll cleanup are hoisted to
  // the top of the component so they pass rules-of-hooks across the
  // empty-state early return — see the block right after the useState
  // declarations.)
  const startEdgeScroll = (mode: 'drag' | 'touch') => {
    const container = listScrollRef.current;
    if (!container) return;
    dragScrollStopRef.current?.();
    dragCursorRef.current = null;

    let removeListener: (() => void) | undefined;
    if (mode === 'drag') {
      const onDragOver = (ev: DragEvent) => {
        dragCursorRef.current = { x: ev.clientX, y: ev.clientY };
      };
      const stopOnNativeEnd = () => dragScrollStopRef.current?.();
      document.addEventListener('dragover', onDragOver);
      // Cross-section drops can unmount the source row before React's
      // onDragEnd runs, so native document events provide final cleanup.
      document.addEventListener('drop', stopOnNativeEnd);
      document.addEventListener('dragend', stopOnNativeEnd);
      removeListener = () => {
        document.removeEventListener('dragover', onDragOver);
        document.removeEventListener('drop', stopOnNativeEnd);
        document.removeEventListener('dragend', stopOnNativeEnd);
      };
    }

    // Asymmetric zones: bottom is wider so the user can scroll down toward
    // the natural "tail" of a long list (someday / done / new tasks)
    // without having to push the cursor to the very last few pixels.
    // Top is moderately wide so dragging upward to Now still feels
    // responsive without hijacking the cursor too aggressively.
    const ZONE_TOP = 100;
    const ZONE_BOTTOM = 160;
    const MAX_SPEED = mode === 'drag' ? 4 : 8;
    let raf = 0;
    const tick = () => {
      const cur = dragCursorRef.current;
      if (cur) {
        const rect = container.getBoundingClientRect();
        const fromTop = cur.y - rect.top;
        const fromBottom = rect.bottom - cur.y;
        let dy = 0;
        if (fromTop < ZONE_TOP) {
          const t = Math.max(0, fromTop) / ZONE_TOP;
          dy = -MAX_SPEED * Math.pow(1 - t, 2);
        } else if (fromBottom < ZONE_BOTTOM) {
          const t = Math.max(0, fromBottom) / ZONE_BOTTOM;
          dy = MAX_SPEED * Math.pow(1 - t, 2);
        }
        if (dy !== 0) {
          container.scrollBy(0, dy);
          // Touch only: the finger hasn't moved, so no fresh touchmove
          // will retarget the drop indicator after the list scrolls
          // under it. Re-run the same hit-test against the unchanged
          // screen coords so the blue line tracks the row that's now
          // beneath the finger.
          if (mode === 'touch') onGripTouchMove(cur.x, cur.y);
        }
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    dragScrollStopRef.current = () => {
      cancelAnimationFrame(raf);
      removeListener?.();
      dragCursorRef.current = null;
      dragScrollStopRef.current = null;
    };
  };

  const onRowDragStart = (e: React.DragEvent, taskId: string) => {
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', taskId);
    desktopDragIdRef.current = taskId as UUID;
    startEdgeScroll('drag');
  };
  const onRowDragEnd = () => {
    desktopDragIdRef.current = null;
    dragScrollStopRef.current?.();
  };
  // Three-zone row hit-test for HTML5 drag. Top 30% → "before"
  // (cyan line above the row); bottom 30% → "after" (cyan line
  // below); middle 40% → "merge" (target row highlights, drop runs
  // mergeTaskInto). Splitting by % rather than absolute pixels keeps
  // the merge band predictable across font-size scales (-fs-scale
  // affects row height).
  const resolveRowDropPos = (clientY: number, rect: DOMRect): 'before' | 'after' | 'merge' => {
    const t = (clientY - rect.top) / rect.height;
    if (t < 0.3) return 'before';
    if (t > 0.7) return 'after';
    return 'merge';
  };
  const onRowDragOver = (e: React.DragEvent, target: Task) => {
    if (e.dataTransfer.types.includes('text/plain')) {
      e.preventDefault();
      e.stopPropagation();
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      const pos = resolveRowDropPos(e.clientY, rect);
      // Dedupe: dragover fires ~60×/s, and a fresh `{id, pos}` object
      // every time would re-render every TaskRow on every frame, which
      // saturates the main thread and effectively wedges scroll on a
      // long list. Only update when the target row or side actually
      // changed.
      setRowDropAt((cur) =>
        cur?.id === target.id && cur.pos === pos ? cur : { id: target.id as UUID, pos }
      );
    }
  };
  const onRowDrop = (e: React.DragEvent, target: Task) => {
    e.preventDefault();
    e.stopPropagation();
    dragScrollStopRef.current?.();
    setRowDropAt(null);
    setDropTarget(null);
    setAssigneeDropTarget(null);
    const draggedId = e.dataTransfer.getData('text/plain');
    if (!draggedId) { suspendHover(); return; }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const pos = resolveRowDropPos(e.clientY, rect);
    if (pos === 'merge' && draggedId !== target.id) {
      setPendingMerge({ sourceId: draggedId as UUID, targetId: target.id as UUID });
    } else {
      applyTaskMove(draggedId, target, pos === 'before');
    }
    suspendHover();
  };
  const onSectionDrop = (e: React.DragEvent, section: Section) => {
    e.preventDefault();
    dragScrollStopRef.current?.();
    const id = e.dataTransfer.getData('text/plain');
    if (id) setTaskSection(id, section);
    setDropTarget(null);
    setRowDropAt(null);
    suspendHover();
  };

  // Shared hold-drag pipeline for touch, mouse, and pen. Native grip
  // dragging uses the same drop rules through its HTML5 event handlers.
  const onGripTouchStart = (taskId: UUID) => {
    touchDraggedRef.current = taskId;
    touchDropAtRef.current = null;
    touchSectionRef.current = null;
    touchAssigneeRef.current = null;
    setRowDropAt(null);
    setDropTarget(null);
    setAssigneeDropTarget(null);
    startEdgeScroll('touch');
  };
  const onGripTouchMove = (clientX: number, clientY: number) => {
    const dragged = touchDraggedRef.current;
    if (!dragged) return;
    dragCursorRef.current = { x: clientX, y: clientY };
    const el = document.elementFromPoint(clientX, clientY) as HTMLElement | null;
    const rowEl = el?.closest('[data-task-id]') as HTMLElement | null;
    if (rowEl && rowEl.dataset.taskId && rowEl.dataset.taskId !== dragged) {
      const rect = rowEl.getBoundingClientRect();
      const pos = resolveRowDropPos(clientY, rect);
      const next = { id: rowEl.dataset.taskId as UUID, pos };
      touchDropAtRef.current = next;
      touchSectionRef.current = null;
      touchAssigneeRef.current = null;
      setRowDropAt(next);
      setDropTarget(null);
      setAssigneeDropTarget(null);
      return;
    }
    // Inside an assignee group but not on a row. Resolve to "before the
    // first task" or "after the last task" based on which half of the
    // group the finger is in — same convention `onRowDragOver` uses for
    // a single row, just scoped to the whole group's bounding box. The
    // user sees the cyan target line on a real row, and the commit
    // lands at top or bottom of that group with a reassign if needed.
    // Empty group: fall back to the assignee-only path; the cyan group
    // accent carries the drop indication when no row exists to mark.
    const assigneeEl = el?.closest('[data-assignee-id]') as HTMLElement | null;
    const aid = assigneeEl?.dataset.assigneeId as UUID | undefined;
    if (aid && assigneeEl) {
      const draggedTask = tasks.find((t) => t.id === dragged);
      const groupTasks = projectTasks
        .filter((t) =>
          t.section === 'now' &&
          t.assignee_id === aid &&
          t.id !== dragged,
        )
        .sort(byKey);
      if (groupTasks.length > 0 && draggedTask) {
        const rect = assigneeEl.getBoundingClientRect();
        const upperHalf = clientY < rect.top + rect.height / 2;
        const target = upperHalf ? groupTasks[0] : groupTasks[groupTasks.length - 1];
        const next = {
          id: target.id as UUID,
          pos: (upperHalf ? 'before' : 'after') as 'before' | 'after',
        };
        touchDropAtRef.current = next;
        touchSectionRef.current = null;
        touchAssigneeRef.current = null;
        setRowDropAt(next);
        setDropTarget(null);
        setAssigneeDropTarget(null);
      } else {
        touchAssigneeRef.current = aid;
        touchDropAtRef.current = null;
        touchSectionRef.current = null;
        setAssigneeDropTarget(aid);
        setRowDropAt(null);
        setDropTarget(null);
      }
      return;
    }
    const sectionEl = el?.closest('.section') as HTMLElement | null;
    const sec = sectionEl?.getAttribute('data-section') as Section | null;
    if (sec) {
      touchSectionRef.current = sec;
      touchDropAtRef.current = null;
      touchAssigneeRef.current = null;
      setDropTarget(sec);
      setRowDropAt(null);
      setAssigneeDropTarget(null);
      return;
    }
    touchDropAtRef.current = null;
    touchSectionRef.current = null;
    touchAssigneeRef.current = null;
    setRowDropAt(null);
    setDropTarget(null);
    setAssigneeDropTarget(null);
  };
  const onGripTouchEnd = (cancelled = false) => {
    const dragged = touchDraggedRef.current;
    const dropAt = touchDropAtRef.current;
    const section = touchSectionRef.current;
    const assignee = touchAssigneeRef.current;
    touchDraggedRef.current = null;
    touchDropAtRef.current = null;
    touchSectionRef.current = null;
    touchAssigneeRef.current = null;
    setRowDropAt(null);
    setDropTarget(null);
    setAssigneeDropTarget(null);
    dragScrollStopRef.current?.();
    if (!dragged || cancelled) return;
    if (dropAt) {
      const target = tasks.find((t) => t.id === dropAt.id);
      if (target) {
        if (dropAt.pos === 'merge' && dragged !== target.id) {
          setPendingMerge({ sourceId: dragged as UUID, targetId: target.id as UUID });
        } else {
          applyTaskMove(dragged, target, dropAt.pos === 'before');
        }
      }
    } else if (assignee) {
      const draggedTask = tasks.find((t) => t.id === dragged);
      if (draggedTask) {
        if (draggedTask.assignee_id !== assignee) setTaskAssignee(dragged, assignee);
        if (draggedTask.section !== 'now') setTaskSection(dragged, 'now');
      }
    } else if (section) {
      setTaskSection(dragged, section);
    }
    suspendHover();
  };

  const toggleExpanded = (taskId: UUID) =>
    setExpandedSubs((p) => ({ ...p, [taskId]: !p[taskId] }));

  // Up/Down navigation between editable rows. Reads the rendered DOM
  // order via querySelectorAll so collapsed subtasks (not in the DOM)
  // are naturally skipped — and so Now's assignee groups, Done, etc.
  // all chain into one document-order list with no extra bookkeeping
  // here. Stamping `data-task-id` on every .task-row and
  // `data-subtask-id` on every .subtask gives the lookup a stable
  // anchor; the autoEdit handoff drives focus into the resolved row.
  const navigateFrom = (currentEl: HTMLElement | null, dir: 'up' | 'down') => {
    const root = listScrollRef.current;
    if (!root || !currentEl) return false;
    // The chain spans every editable stop in document order: task
    // rows, subtask rows, *and* the per-section / per-assignee
    // "Add task…" rows. Section walking happens for free because all
    // sections live in the same .list container — collapsed
    // sections / subtask groups aren't in the DOM, so they're
    // skipped naturally.
    const rows = Array.from(
      root.querySelectorAll('.task-row[data-task-id], .subtask[data-subtask-id], .task-add'),
    ) as HTMLElement[];
    const idx = rows.indexOf(currentEl);
    if (idx === -1) return false;
    const next = rows[idx + (dir === 'up' ? -1 : 1)];
    if (!next) return false;
    if (next.dataset.taskId) { setAutoEditTaskId(next.dataset.taskId); return true; }
    if (next.dataset.subtaskId) { setAutoEditSubId(next.dataset.subtaskId); return true; }
    if (next.classList.contains('task-add')) {
      // Add-rows have no autoEdit handoff — their input is always
      // present, so just focus it directly. selectionStart=end so
      // the caret lands at the end of any pending draft.
      const ta = next.querySelector('textarea, input') as HTMLTextAreaElement | HTMLInputElement | null;
      ta?.focus();
      if (ta && 'value' in ta) {
        const len = ta.value.length;
        try { ta.setSelectionRange(len, len); } catch { /* radio/checkbox can throw */ }
      }
      return true;
    }
    return false;
  };

  // Enter from a task title: spawn a sibling right after it, in the same
  // section / assignee group, then hand focus to the new row's input.
  // The new task's title starts empty; the sort_key lands between the
  // current task and its successor (see store/addTaskAfter).
  const handleCreateSibling = (afterTask: Task, draft: string) => {
    if (draft.trim() !== afterTask.title) setTaskTitle(afterTask.id, draft.trim());
    const id = addTaskAfter(afterTask.id);
    if (id) setAutoEditTaskId(id);
  };

  // Tab from a task title: convert this task into a subtask of the
  // previous task in the same render group. Stage 1 ships the simple
  // case only — refuse if the source task has subtasks (can't nest)
  // or if there's no previous task to attach to. Description / blocks
  // / estimate / tags are dropped on demote; merge semantics come in
  // stage 3.
  const handleDemote = (task: Task, draft: string, prevTaskId: UUID | null) => {
    if (!prevTaskId || task.subtasks.length > 0) return false;
    const title = draft.trim() || task.title;
    if (!title) return false;
    const subId = addSubtask(prevTaskId, title);
    if (!subId) return false;
    setExpandedSubs((p) => ({ ...p, [prevTaskId]: true }));
    deleteTask(task.id);
    setAutoEditSubId(subId);
    return true;
  };

  // Enter from a subtask: append a sibling subtask right after this one
  // and focus its input. Mirrors the TaskModal subtask-list behavior.
  const handleSubAdd = (taskId: UUID, afterSubId?: UUID) => {
    const id = addSubtask(taskId, '', afterSubId);
    if (id) setAutoEditSubId(id);
  };

  // Shift+Tab from a subtask: promote it back to a task right after its
  // parent, in the same section. Subtasks have no metadata beyond title
  // / done, so this round-trip is lossless.
  const handleSubPromote = (parent: Task, subId: UUID, draft: string) => {
    const sub = parent.subtasks.find((s) => s.id === subId);
    if (!sub) return;
    const title = draft.trim() || sub.title;
    if (!title) return;
    const newId = addTaskAfter(parent.id, title);
    if (!newId) return;
    deleteSubtask(parent.id, subId);
    setAutoEditTaskId(newId);
  };

  // Shift+Up/Down on a task title moves the task itself one slot
  // within its render group (assignee bucket in Now, the section
  // otherwise). Reuses applyTaskMove so reorder + ops are identical
  // to dragging — the only thing different is the keyboard trigger.
  const shiftMoveTask = (taskId: UUID, sectionList: Task[], dir: 'up' | 'down') => {
    const i = sectionList.findIndex((t) => t.id === taskId);
    if (i === -1) return false;
    const targetIdx = dir === 'up' ? i - 1 : i + 1;
    if (targetIdx < 0 || targetIdx >= sectionList.length) return false;
    applyTaskMove(taskId, sectionList[targetIdx], dir === 'up');
    return true;
  };

  // Same idea for subtasks: swap with the adjacent sibling under the
  // same parent task. reorderSubtasks renumbers sort_keys for the
  // whole list, so a single swap requires sending the entire list.
  const shiftMoveSubtask = (parent: Task, subId: UUID, dir: 'up' | 'down') => {
    const ordered = [...parent.subtasks].sort((a, b) => a.sort_key.localeCompare(b.sort_key));
    const i = ordered.findIndex((s) => s.id === subId);
    if (i === -1) return false;
    const targetIdx = dir === 'up' ? i - 1 : i + 1;
    if (targetIdx < 0 || targetIdx >= ordered.length) return false;
    [ordered[i], ordered[targetIdx]] = [ordered[targetIdx], ordered[i]];
    reorderSubtasks(parent.id, ordered.map((s) => s.id));
    return true;
  };

  const renderRow = (t: Task, sectionList: Task[], idx: number) => (
    <TaskRow key={t.id} task={t} blocks={blocks}
             sprintLabel={sprintLabelFor(t)}
             onTick={tickTask}
             onSubTick={tickSubtask}
             onSubSave={setSubtaskTitle}
             onSubDelete={deleteSubtask}
             onOpen={openTask}
             onDragStart={onRowDragStart}
             onRowDragEnd={onRowDragEnd}
             onRowDragOver={onRowDragOver}
             onRowDrop={onRowDrop}
             onRowDragLeave={() => setRowDropAt(null)}
             onGripTouchStart={onGripTouchStart}
             onGripTouchMove={onGripTouchMove}
             onGripTouchEnd={onGripTouchEnd}
             dropMark={rowDropAt?.id === t.id ? rowDropAt.pos : null}
             expanded={!!expandedSubs[t.id]}
             onToggleExpanded={() => toggleExpanded(t.id)}
             prevTaskId={idx > 0 ? sectionList[idx - 1].id : null}
             autoEditTitle={autoEditTaskId === t.id}
             onAutoEditTitleConsumed={() => setAutoEditTaskId(null)}
             autoEditSubId={autoEditSubId}
             onAutoEditSubConsumed={() => setAutoEditSubId(null)}
             onTitleSave={setTaskTitle}
             onTitleDelete={deleteTask}
             onCreateSibling={(draft) => handleCreateSibling(t, draft)}
             onDemote={(draft) => handleDemote(t, draft, idx > 0 ? sectionList[idx - 1].id : null)}
             onSubAdd={(afterSubId) => handleSubAdd(t.id, afterSubId)}
             onSubPromote={(subId, draft) => handleSubPromote(t, subId, draft)}
             onNavigate={navigateFrom}
             onShiftMoveTask={(dir) => shiftMoveTask(t.id, sectionList, dir)}
             onShiftMoveSubtask={(subId, dir) => shiftMoveSubtask(t, subId, dir)} />
  );

  const archivable = projectTasks.filter((t) => t.status === 'done' && t.section !== 'done');
  const archiveDone = () => {
    for (const t of archivable) setTaskSection(t.id, 'done');
  };

  return (
    <div className="list" ref={listScrollRef} data-suspend-hover={hoverSuspended || undefined}
         data-scrolled={listScrolled || undefined}
         onScroll={(e) => {
           const next = e.currentTarget.scrollTop > 72;
           if (next !== listScrolled) setListScrolled(next);
         }}>
      <div className="list-doc" style={{ ['--proj-color' as string]: project.color }}>
        {/* One sticky header: the project on the left; search, sprint,
            tags, scope and the ⋯ menu on the right. The search is compact
            until focused or filled. Picked tags sit underneath as chips. */}
        <div className="list-head" data-filtering={filtersActive || undefined}>
          <div className="list-head-row">
            <span className="proj-icon" aria-hidden>
              <ProjectIcon name={project.icon} color={project.color} size={24} strokeWidth={1.75} />
            </span>
            <h1>{project.title}</h1>
            <div className="list-head-controls">
              <SearchField
                className="list-search"
                label="Filter tasks by title, issue key or sprint"
                value={query}
                onValueChange={setQuery}
                onKeyDown={(e) => { if (e.key === 'Escape') { setQuery(''); e.currentTarget.blur(); } }}
                placeholder="Filter tasks"
                data-has-value={query ? 'true' : undefined}
              />
              {(projectSprints.length > 0 || sprintFilter !== 'all') && (
                <SprintSelect
                  value={sprintFilter}
                  sprints={projectSprints}
                  tracks={tracks.filter((tr) => tr.project_id === project.id)}
                  onChange={(sprint_filter) => setListFilter({ sprint_filter })}
                />
              )}
              {hasProjectTags && (
                <TagMenu
                  projectId={project.id}
                  allTags={allTags}
                  tagIds={listFilter.tag_ids}
                  onChange={(tag_ids) => setListFilter({ tag_ids })}
                />
              )}
              {showAssigneeScope && (
                <div className="seg list-scope" role="group" aria-label="Assignee scope">
                  <button type="button" data-on={assigneeScope === 'all' || undefined}
                          aria-pressed={assigneeScope === 'all'}
                          onClick={() => setListFilter({ assignee_scope: 'all' })}
                          title="Show every task in this project">All</button>
                  <button type="button" data-on={assigneeScope === 'me' || undefined}
                          aria-pressed={assigneeScope === 'me'}
                          onClick={() => setListFilter({ assignee_scope: 'me' })}
                          title="Show only tasks assigned to me">Me</button>
                </div>
              )}
              <div className="proj-menu" ref={projMenuRef}>
                <button className="icon-btn proj-edit-btn"
                        aria-label="Project actions" aria-haspopup="true" aria-expanded={projMenuOpen}
                        data-open={projMenuOpen || undefined}
                        onClick={() => setProjMenuOpen((v) => !v)}
                        title="Project actions">
                  <MoreHorizontal size={16} strokeWidth={1.75} />
                </button>
                {projMenuOpen && (
                  <div className="proj-menu-pop" role="menu">
                    <button type="button" role="menuitemcheckbox" aria-checked={showListTimes}
                            className="proj-menu-item"
                            onClick={() => { setProjMenuOpen(false); setShowListTimes(!showListTimes); }}>
                      <Clock size={14} strokeWidth={1.75} /> Show time
                      {showListTimes && <Check size={14} strokeWidth={2} className="proj-menu-check" />}
                    </button>
                    {canEditThisProject && (
                      <button type="button" role="menuitem" className="proj-menu-item"
                              onClick={() => { setProjMenuOpen(false); openEditProject(project.id); }}>
                        <Pencil size={14} strokeWidth={1.75} /> Edit project
                      </button>
                    )}
                    <button type="button" role="menuitem" className="proj-menu-item"
                            disabled={archivable.length === 0}
                            onClick={() => { setProjMenuOpen(false); setConfirmArchive(true); }}
                            title="Move every ticked task into the Done section">
                      <Archive size={14} strokeWidth={1.75} />
                      Archive completed
                      {archivable.length > 0 && <span className="proj-menu-count">{archivable.length}</span>}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
          {listFilter.tag_ids.length > 0 && (
            <div className="list-head-chips">
              <TagFilterChips
                allTags={allTags}
                tagIds={listFilter.tag_ids}
                mode={listFilter.tag_mode}
                onChange={(tag_ids) => setListFilter({ tag_ids })}
                onModeChange={(tag_mode) => setListFilter({ tag_mode })}
              />
              <button type="button" className="list-clear-all" onClick={clearFilters}
                      title="Clear search, sprint and tag filters">
                Clear all
              </button>
            </div>
          )}
        </div>

        {filtersActive && projectTasks.length === 0 && (
          <p className="list-filter-empty">
            No tasks match.{' '}
            <button type="button" className="list-empty-link" onClick={clearFilters}>Clear filters</button>
          </p>
        )}

        {showListTimes && (
          <div className="list-time" aria-label="Filtered totals">
            {totalEst > 0 && (() => {
              // Estimate = the bar up to the notch; logged overrun runs
              // past it in amber. Scaled so estimate + overrun fill it.
              // The overrun gets at most 35% of the bar (same cap as the
              // rail) so the estimate part stays readable.
              const overShown = Math.min(totalOver, totalEst * 35 / 65);
              const span = totalEst + overShown;
              const pct = (m: number) => `${(m / span) * 100}%`;
              return (
                <div className="list-time-bar" title="Tasks with an estimate: done, planned, and logged time past the estimate">
                  <div className="ltb-done" style={{ width: pct(estDone) }} />
                  <div className="ltb-planned" style={{ width: pct(estPlanned) }} />
                  <div className="ltb-rest" style={{ width: pct(totalEst - estDone - estPlanned) }} />
                  {totalOver > 0 && <>
                    <div className="ltb-tick" aria-hidden />
                    <div className="ltb-over" style={{ width: pct(overShown) }} />
                  </>}
                </div>
              );
            })()}
            <div className="list-totals">
              <span><strong>{fmtMin(totalDone)}</strong> {privateTimeExcluded ? 'visible done' : 'done'}</span>
              <span><strong>{fmtMin(totalPlanned)}</strong> {privateTimeExcluded ? 'visible planned' : 'planned'}</span>
              <span><strong>{fmtMin(totalEst)}</strong> estimated</span>
              {privateTimeExcluded && <span>Private time excluded</span>}
              {totalOver > 0 && (
                <span className="list-totals-over" title="Sum of each task's logged time past its own estimate">
                  +{fmtMin(totalOver)} over estimate
                </span>
              )}
            </div>
          </div>
        )}

        {/* NOW */}
        <div className="section" data-section="now"
             style={dropTarget === 'now' ? { background: 'var(--accent-tint)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('now'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'now')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, now: !collapsed.now })}>
            <span className="caret">{collapsed.now ? <ChevronRight size={14} strokeWidth={1.75} /> : <ChevronDown size={14} strokeWidth={1.75} />}</span>
            <h2>Now</h2>
            <SectionCount value={nowTasks.length} total={filtersActive ? allProjectTasks.filter((t) => t.section === 'now').length : undefined} />
            <span className="rule" />
            <span className="est">
              {showListTimes && nowEst > 0 && <span title={`${fmtMin(nowEst)} estimated in total`}>{fmtMin(nowLeft)} left · </span>}
              Week of {fmtWeekOf()}
            </span>
          </div>
          {!collapsed.now && (
            <>
              {assigneeIds.length > 1 ? assigneeIds.map((aid) => {
                const u = userById(aid);
                const subTasks = nowTasks.filter((t) => t.assignee_id === aid);
                const firstName = u?.name?.split(' ')[0] ?? 'them';
                // People with nothing in Now fold to one line by default;
                // expanding still gives them the add-task row.
                const empty = subTasks.length === 0;
                const folded = collapsedAssignee[aid] ?? empty;
                const isAssigneeDrop = assigneeDropTarget === aid;
                return (
                  <div key={aid}
                       data-assignee-drop={isAssigneeDrop ? 'true' : undefined}
                       data-assignee-id={aid}
                       className="assignee-group"
                       onDragOver={(e) => {
                         e.preventDefault();
                         e.stopPropagation();
                         // Resolve to before-first / after-last based on
                         // which half of the group the cursor is in —
                         // same convention the touch path uses, so the
                         // user sees the target line on a real row
                         // instead of a vague group highlight.
                         const draggedId = desktopDragIdRef.current;
                         const groupTasks = draggedId
                           ? projectTasks
                               .filter((t) => t.section === 'now' && t.assignee_id === aid && t.id !== draggedId)
                               .sort(byKey)
                           : [];
                         if (groupTasks.length === 0) {
                           setAssigneeDropTarget(aid);
                           setRowDropAt(null);
                           return;
                         }
                         const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                         const upperHalf = e.clientY < rect.top + rect.height / 2;
                         const target = upperHalf ? groupTasks[0] : groupTasks[groupTasks.length - 1];
                         setRowDropAt({ id: target.id as UUID, pos: upperHalf ? 'before' : 'after' });
                         setAssigneeDropTarget(null);
                       }}
                       onDragLeave={(e) => {
                         const next = e.relatedTarget as Node | null;
                         if (!next || !(e.currentTarget as Node).contains(next)) {
                           setAssigneeDropTarget((cur) => (cur === aid ? null : cur));
                         }
                       }}
                       onDrop={(e) => {
                         e.preventDefault();
                         e.stopPropagation();
                         setAssigneeDropTarget(null);
                         setRowDropAt(null);
                         setDropTarget(null);
                         const draggedId = e.dataTransfer.getData('text/plain');
                         if (!draggedId) return;
                         const dragged = tasks.find((t) => t.id === draggedId);
                         if (!dragged || dragged.project_id !== project.id) return;
                         // Same top/bottom split on commit. With tasks
                         // in the group: route through applyTaskMove so
                         // both reorder and reassign happen atomically.
                         // Empty group: just reassign + flip to Now.
                         const groupTasks = projectTasks
                           .filter((t) => t.section === 'now' && t.assignee_id === aid && t.id !== draggedId)
                           .sort(byKey);
                         if (groupTasks.length > 0) {
                           const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                           const upperHalf = e.clientY < rect.top + rect.height / 2;
                           const target = upperHalf ? groupTasks[0] : groupTasks[groupTasks.length - 1];
                           applyTaskMove(draggedId, target, upperHalf);
                           return;
                         }
                         if (dragged.assignee_id !== aid) setTaskAssignee(draggedId, aid);
                         if (dragged.section !== 'now') setTaskSection(draggedId, 'now');
                       }}>
                    <div className="assignee-head"
                         onClick={() => setCollapsedAssignee({ ...collapsedAssignee, [aid]: !folded })}>
                      <span className="ah-caret">{folded ? <ChevronRight size={14} strokeWidth={1.75} /> : <ChevronDown size={14} strokeWidth={1.75} />}</span>
                      <div className="avatar" data-me={u?.id === meId}>{u?.initials ?? '?'}</div>
                      <span>{u?.name}{u?.id === meId ? ' (you)' : ''}</span>
                      {empty ? <span className="ah-empty">No tasks</span> : <span className="ah-count">{subTasks.length}</span>}
                      <span className="ah-rule" />
                    </div>
                    {!folded && (
                      <>
                        {subTasks.map((t, i) => renderRow(t, subTasks, i))}
                        <AddTaskRow
                          placeholder={`Add task for ${firstName}`}
                          onAdd={(title) => addTask(project.id, 'now', title, aid, tagFilter)}
                          onNavigate={navigateFrom}
                        />
                      </>
                    )}
                  </div>
                );
              }) : (
                (() => {
                  const flatNow = nowTasks.filter((t) => t.assignee_id != null);
                  return (
                    <>
                      {flatNow.map((t, i) => renderRow(t, flatNow, i))}
                      <AddTaskRow onAdd={(title) => addTask(project.id, 'now', title, undefined, tagFilter)} onNavigate={navigateFrom} />
                    </>
                  );
                })()
              )}
              {(() => {
                // Unassigned bucket: surfaces Now tasks with no owner. We
                // render it only when it has tasks so it doesn't add noise
                // to projects where every Now task is owned. Unassigning
                // through the modal auto-flips to Later (see
                // setTaskAssignee), so this bucket should normally stay
                // small — it exists for legacy data and explicit
                // "ownerless" Now tasks.
                const unassigned = nowTasks.filter((t) => t.assignee_id == null);
                if (unassigned.length === 0) return null;
                const folded = !!collapsedAssignee['__unassigned'];
                return (
                  <div className="assignee-group">
                    <div className="assignee-head"
                         onClick={() => setCollapsedAssignee({ ...collapsedAssignee, ['__unassigned']: !folded })}>
                      <span className="ah-caret">{folded ? <ChevronRight size={14} strokeWidth={1.75} /> : <ChevronDown size={14} strokeWidth={1.75} />}</span>
                      <div className="avatar">?</div>
                      <span>Unassigned</span>
                      <span className="ah-count">{unassigned.length}</span>
                      <span className="ah-rule" />
                    </div>
                    {!folded && unassigned.map((t, i) => renderRow(t, unassigned, i))}
                  </div>
                );
              })()}
            </>
          )}
        </div>

        {/* LATER */}
        <div className="section" data-section="later"
             style={dropTarget === 'later' ? { background: 'var(--accent-tint)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('later'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'later')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, later: !collapsed.later })}>
            <span className="caret">{collapsed.later ? <ChevronRight size={14} strokeWidth={1.75} /> : <ChevronDown size={14} strokeWidth={1.75} />}</span>
            <h2>Later</h2>
            <SectionCount value={laterTasks.length} total={filtersActive ? allProjectTasks.filter((t) => t.section === 'later').length : undefined} />
            <span className="rule" />
            <span className="est">
              {showListTimes && laterEst > 0 && <span title="Sum of estimates in this section">{fmtMin(laterEst)} estimated · </span>}
              Parking lot
            </span>
          </div>
          {!collapsed.later && (
            <>
              {laterTasks.map((t, i) => renderRow(t, laterTasks, i))}
              <AddTaskRow onAdd={(title) => addTask(project.id, 'later', title, undefined, tagFilter)} onNavigate={navigateFrom} />
            </>
          )}
        </div>

        {/* RECURRING */}
        <div className="section" data-section="recurring"
             style={dropTarget === 'recurring' ? { background: 'var(--accent-tint)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('recurring'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'recurring')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, recurring: !collapsed.recurring })}>
            <span className="caret">{collapsed.recurring ? <ChevronRight size={14} strokeWidth={1.75} /> : <ChevronDown size={14} strokeWidth={1.75} />}</span>
            <h2>Recurring</h2>
            <SectionCount value={recurringTasks.length} total={filtersActive ? allProjectTasks.filter((t) => t.section === 'recurring').length : undefined} />
            <span className="rule" />
            <span className="est">
              {showListTimes && recurringEst > 0 && <span title="Sum of estimates in this section">{fmtMin(recurringEst)} estimated · </span>}
              Ongoing
            </span>
          </div>
          {!collapsed.recurring && (
            <>
              {recurringTasks.map((t, i) => renderRow(t, recurringTasks, i))}
              <AddTaskRow onAdd={(title) => addTask(project.id, 'recurring', title, undefined, tagFilter)} onNavigate={navigateFrom} />
            </>
          )}
        </div>

        {/* SOMEDAY */}
        <div className="section" data-section="someday"
             style={dropTarget === 'someday' ? { background: 'var(--accent-tint)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('someday'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'someday')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, someday: !collapsed.someday })}>
            <span className="caret">{collapsed.someday ? <ChevronRight size={14} strokeWidth={1.75} /> : <ChevronDown size={14} strokeWidth={1.75} />}</span>
            <h2>Someday</h2>
            <SectionCount value={somedayTasks.length} total={filtersActive ? allProjectTasks.filter((t) => t.section === 'someday').length : undefined} />
            <span className="rule" />
            <span className="est">
              {showListTimes && somedayEst > 0 && <span title="Sum of estimates in this section">{fmtMin(somedayEst)} estimated · </span>}
              Maybe
            </span>
          </div>
          {!collapsed.someday && (
            <>
              {somedayTasks.map((t, i) => renderRow(t, somedayTasks, i))}
              <AddTaskRow onAdd={(title) => addTask(project.id, 'someday', title, undefined, tagFilter)} onNavigate={navigateFrom} />
            </>
          )}
        </div>

        {/* DONE */}
        <div className="section" data-section="done"
             onDragOver={(e) => { e.preventDefault(); setDropTarget('done'); }}
             onDrop={(e) => onSectionDrop(e, 'done')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, done: !collapsed.done })}>
            <span className="caret">{collapsed.done ? <ChevronRight size={14} strokeWidth={1.75} /> : <ChevronDown size={14} strokeWidth={1.75} />}</span>
            <h2>Done</h2>
            <SectionCount value={doneTasks.length} total={filtersActive ? allProjectTasks.filter((t) => t.section === 'done').length : undefined} />
            <span className="rule" />
            <span className="est">
              {showListTimes && <span title={privateTimeExcluded ? "visible completed time" : "completed time"}>{fmtMin(doneDone)}{privateTimeExcluded ? ' visible' : ''} done · </span>}
              Archive
            </span>
          </div>
          {!collapsed.done && (
            <>
              {doneGroups.map((group) => {
                const folded = !!collapsedArchiveGroups[group.key];
                return (
                  <div className="archive-date-group" key={group.key}>
                    <div
                      className="archive-date-head"
                      onClick={() => setCollapsedArchiveGroups((current) => ({
                        ...current, [group.key]: !folded,
                      }))}
                    >
                      <span className="archive-caret">
                        {folded ? <ChevronRight size={13} strokeWidth={1.75} /> : <ChevronDown size={13} strokeWidth={1.75} />}
                      </span>
                      <span>{group.label}</span>
                      <span className="rule" />
                      <span className="count">{group.tasks.length}</span>
                    </div>
                    {!folded && group.tasks.map((t) => renderRow(t, doneTasks, doneTasks.indexOf(t)))}
                  </div>
                );
              })}
            </>
          )}
        </div>
      </div>
      {confirmArchive && (
        <ConfirmDelete
          title="Archive ticked tasks?"
          confirmLabel={`Archive ${archivable.length}`}
          tone="neutral"
          body={
            <p>
              {archivable.length === 1 ? '1 ticked task moves' : `${archivable.length} ticked tasks move`} into
              the Done section. Nothing is deleted.
            </p>
          }
          onCancel={() => setConfirmArchive(false)}
          onConfirm={() => { archiveDone(); setConfirmArchive(false); }}
        />
      )}
      {pendingMerge && (() => {
        const source = tasks.find((t) => t.id === pendingMerge.sourceId);
        const target = tasks.find((t) => t.id === pendingMerge.targetId);
        // A task vanished between the drop and the confirm (deleted /
        // synced away) — nothing safe to merge, so drop the prompt.
        if (!source || !target) { setPendingMerge(null); return null; }
        return (
          <ConfirmDelete
            title="Merge tasks?"
            confirmLabel="Merge"
            body={
              <p>
                <strong>{source.title}</strong> will be folded into{' '}
                <strong>{target.title}</strong> — its subtasks, description, and
                time are carried over, then it's removed. This can't be undone.
              </p>
            }
            onCancel={() => setPendingMerge(null)}
            onConfirm={() => {
              void mergeTaskInto(pendingMerge.sourceId, pendingMerge.targetId);
              // Auto-expand so the user sees what they just merged into
              // the target — mirrors the Tab-demote handler's behavior.
              setExpandedSubs((p) => ({ ...p, [pendingMerge.targetId]: true }));
              setPendingMerge(null);
            }}
          />
        );
      })()}
    </div>
  );
}

// Section header count that pulses (color + scale + glow) on every
// change. Skips the initial mount so navigating into the list doesn't
// flash all four counts at once. Re-keys the span on each change so the
// CSS animation restarts cleanly even when the value bounces during
// the previous animation.
type SprintLabel = { title: string; color: string | null };

/// Sprint titles often start with the project's name ("Atlas · Nov 16");
/// on that project's own page the prefix is noise.
function stripProjectPrefix(title: string | null, projectTitle: string): string | null {
  if (!title) return title;
  for (const sep of [' · ', ' - ', ' – ', ': ']) {
    const prefix = projectTitle + sep;
    if (title.startsWith(prefix) && title.length > prefix.length) return title.slice(prefix.length);
  }
  return title;
}

/// Sprint selector for the list toolbar, built on the shared `Select`
/// popover so it matches the rest of the app instead of OS chrome.
/// "All sprints" first; active sprints follow grouped by track (in
/// track order, "No track" last), and inactive sprints collect in a
/// trailing group. Each sprint shows its date span as a hint line.
type SprintFilterValue = UUID | 'all';
function SprintSelect({ value, sprints, tracks, onChange }: {
  value: SprintFilterValue;
  sprints: Sprint[];
  tracks: Track[];
  onChange: (v: SprintFilterValue) => void;
}) {
  const options = useMemo(() => {
    const bySort = (a: { sort_key: string }, b: { sort_key: string }) => a.sort_key.localeCompare(b.sort_key);
    const colorOf = new Map(tracks.map((tr) => [tr.id, tr.color]));
    const toOpt = (sp: Sprint, group: string): SelectOption<SprintFilterValue> => {
      const color = sp.track_id ? colorOf.get(sp.track_id) : undefined;
      return {
        value: sp.id, label: sp.title, group, groupColor: group === 'Inactive' ? undefined : color,
        hint: sprintSpan(sp) ?? undefined,
        dot: color ?? '',
      };
    };
    const active = sprints.filter((sp) => sp.active).sort(bySort);
    const known = new Set(tracks.map((tr) => tr.id));
    const opts: SelectOption<SprintFilterValue>[] = [
      { value: 'all', label: 'All sprints' },
    ];
    for (const tr of [...tracks].sort(bySort)) {
      for (const sp of active) if (sp.track_id === tr.id) opts.push(toOpt(sp, tr.title));
    }
    for (const sp of active) if (!sp.track_id || !known.has(sp.track_id)) opts.push(toOpt(sp, 'No track'));
    for (const sp of sprints.filter((x) => !x.active).sort(bySort)) opts.push(toOpt(sp, 'Inactive'));
    return opts;
  }, [sprints, tracks]);
  return (
    <Select<SprintFilterValue>
      size="sm"
      className={`list-sprint-select${value !== 'all' ? ' list-sprint-select-set' : ''}`}
      value={value}
      options={options}
      onChange={onChange}
      menuMinWidth={320}
      ariaLabel="Filter by sprint"
      title="Filter by sprint"
    />
  );
}

/// "Oct 5 – Oct 18" from a sprint's week-aligned span. `ends_on` is
/// exclusive, so the last shown day is the one before it.
function sprintSpan(sp: Sprint): string | null {
  if (!sp.starts_on) return null;
  const parse = (d: string) => {
    const [y, m, day] = d.split('-').map(Number);
    return new Date(y, m - 1, day);
  };
  const fmt = (d: Date) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const start = parse(sp.starts_on);
  if (!sp.ends_on) return `from ${fmt(start)}`;
  const last = parse(sp.ends_on);
  last.setDate(last.getDate() - 1);
  return `${fmt(start)} – ${fmt(last)}`;
}

/// While filtering, "1 of 7": what's shown out of what's in the section.
function SectionCount({ value, total }: { value: number; total?: number }) {
  const [bump, setBump] = useState(0);
  const prev = useRef(value);
  useEffect(() => {
    if (prev.current !== value) {
      prev.current = value;
      setBump((b) => b + 1);
    }
  }, [value]);
  return (
    <span key={bump} className="count" data-pulse={bump > 0 || undefined}>
      {value}{total != null && total !== value && <span className="count-of"> of {total}</span>}
    </span>
  );
}

function AddTaskRow({ onAdd, placeholder = 'Add task', onNavigate }: {
  onAdd: (title: string) => void;
  placeholder?: string;
  onNavigate?: (currentEl: HTMLElement | null, dir: 'up' | 'down') => boolean;
}) {
  const [value, setValue] = useState('');
  const inputRef = useRef<HTMLTextAreaElement>(null);
  // A title long enough to wrap is typed here as often as it's edited in
  // place, and this textarea is `rows={1}` with `overflow-y: hidden` too:
  // without a re-fit the second line is invisible while you type it.
  useLayoutEffect(() => {
    if (inputRef.current) fitToText(inputRef.current);
  }, [value]);

  const commit = () => {
    const v = value.trim();
    if (v) onAdd(v);
    setValue('');
  };

  return (
    <div className="task-add" data-editing="true" onClick={() => inputRef.current?.focus()}>
      <span className="task-add-plus">+</span>
      {/* `<textarea rows={1}>` instead of `<input>` because Safari /
       * iCloud's "Hide My Email" QuickType chip is keyed off `<input>`
       * elements specifically — it doesn't fire on textareas. We size
       * it as a single line via CSS (`resize: none`, line-height match)
       * so the user-visible affordance is identical to an input. Enter
       * commits, Shift+Enter inserts a newline (rare; tasks are
       * typically single-line). */}
      <textarea
        ref={inputRef}
        className="task-add-input"
        rows={1}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); commit(); }
          else if (e.key === 'Escape') { setValue(''); inputRef.current?.blur(); }
          else if (e.key === 'ArrowUp' && onNavigate) {
            const ta = e.currentTarget;
            const before = ta.value.slice(0, ta.selectionStart);
            if (before.includes('\n')) return;
            const row = ta.closest('.task-add') as HTMLElement | null;
            if (onNavigate(row, 'up')) e.preventDefault();
          }
          else if (e.key === 'ArrowDown' && onNavigate) {
            const ta = e.currentTarget;
            const after = ta.value.slice(ta.selectionEnd);
            if (after.includes('\n')) return;
            const row = ta.closest('.task-add') as HTMLElement | null;
            if (onNavigate(row, 'down')) e.preventDefault();
          }
        }}
        placeholder={placeholder}
        name="task_title"
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="sentences"
        spellCheck={false}
      />
    </div>
  );
}

function ListSubtaskRow({
  id, title, done, autoEdit, allowInlineEdit,
  onToggle, onSave, onDelete, onAutoEditConsumed, onEnterAdd, onShiftTabPromote,
  onNavigate, onShiftMove,
}: {
  id: UUID;
  title: string;
  done: boolean;
  autoEdit: boolean;
  /// Mobile keeps the existing tap-passthrough-to-modal behavior; only
  /// desktop wires up click-to-edit + Enter / Shift+Tab structure ops.
  allowInlineEdit: boolean;
  onToggle: () => void;
  onSave: (v: string) => void;
  onDelete: () => void;
  onAutoEditConsumed: () => void;
  onEnterAdd: (draft: string) => void;
  onShiftTabPromote: (draft: string) => void;
  onNavigate: (currentEl: HTMLElement | null, dir: 'up' | 'down') => boolean;
  onShiftMove: (dir: 'up' | 'down') => boolean;
}) {
  const [editing, setEditing] = useState(autoEdit);
  const [draft, setDraft] = useState(title);
  const inputRef = useAutosizeTextarea(draft, editing);

  useEffect(() => { setDraft(title); }, [title]);
  useEffect(() => {
    if (!editing) return;
    const el = inputRef.current;
    if (!el) return;
    el.focus();
    el.setSelectionRange(el.value.length, el.value.length);
  }, [editing]);
  // One-shot: a freshly-minted subtask (Enter on previous, or Tab demote
  // from a task) gets stamped with autoEdit — drop into edit mode and
  // tell the parent to clear the flag so re-renders don't loop.
  useEffect(() => {
    if (autoEdit) { setEditing(true); onAutoEditConsumed(); }
  }, [autoEdit, onAutoEditConsumed]);

  // Empty title on commit means the user deleted everything — treat as delete,
  // matching the modal's behavior so the two views feel like one tool.
  const commit = () => {
    const v = draft.trim();
    if (!v) { onDelete(); return; }
    if (v !== title) onSave(v);
    setEditing(false);
  };

  return (
    <div className={editing ? 'subtask subtask-edit' : 'subtask'} data-done={done} data-subtask-id={id}>
      <span
        className="sc"
        onClick={(e) => { e.stopPropagation(); onToggle(); }}
        aria-label={done ? 'Mark not done' : 'Mark done'}
      >
        {done && <Check size={11} strokeWidth={3} />}
      </span>
      {editing ? (
        <textarea
          ref={inputRef}
          rows={1}
          className="subtask-edit-input"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onClick={(e) => e.stopPropagation()}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              const v = draft.trim();
              if (!v) { onDelete(); return; }
              if (v !== title) onSave(v);
              setEditing(false);
              onEnterAdd(v);
            }
            else if (e.key === 'Tab' && e.shiftKey) {
              e.preventDefault();
              const v = draft.trim();
              if (!v) { onDelete(); return; }
              if (v !== title) onSave(v);
              setEditing(false);
              onShiftTabPromote(v);
            }
            else if (e.key === 'ArrowUp') {
              if (e.shiftKey) {
                if (onShiftMove('up')) e.preventDefault();
                return;
              }
              const inp = e.currentTarget;
              const row = inp.closest('.subtask') as HTMLElement | null;
              if (onNavigate(row, 'up')) e.preventDefault();
            }
            else if (e.key === 'ArrowDown') {
              if (e.shiftKey) {
                if (onShiftMove('down')) e.preventDefault();
                return;
              }
              const inp = e.currentTarget;
              const row = inp.closest('.subtask') as HTMLElement | null;
              if (onNavigate(row, 'down')) e.preventDefault();
            }
            else if (e.key === 'Escape') { setDraft(title); setEditing(false); }
            else if (e.key === 'Backspace' && !draft) { e.preventDefault(); onDelete(); }
          }}
          name="subtask_title"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="sentences"
          spellCheck={false}
        />
      ) : (
        <span
          className="sname"
          style={{ flex: 1, cursor: allowInlineEdit ? 'text' : undefined }}
          onClick={(e) => {
            // Desktop: click the subtask body to edit. Mobile falls
            // through to the parent row's open-modal handler so the
            // list's typing UX stays desktop-only (no "tab" key on
            // phones, see the original brief).
            if (!allowInlineEdit) return;
            e.stopPropagation();
            setEditing(true);
          }}
        >
          {title}
        </span>
      )}
    </div>
  );
}

interface RowProps {
  task: Task;
  /// Sprint title shown in the trail (desktop only); null hides it.
  sprintLabel: SprintLabel | null;
  blocks: TimeBlock[];
  onTick: (id: string) => void;
  onSubTick: (taskId: string, subId: string) => void;
  onSubSave: (taskId: UUID, subId: UUID, title: string) => void;
  onSubDelete: (taskId: UUID, subId: UUID) => void;
  onOpen: (id: string) => void;
  onDragStart: (e: React.DragEvent, id: string) => void;
  onRowDragEnd: () => void;
  onRowDragOver: (e: React.DragEvent, target: Task) => void;
  onRowDrop: (e: React.DragEvent, target: Task) => void;
  onRowDragLeave: () => void;
  onGripTouchStart: (taskId: UUID) => void;
  onGripTouchMove: (clientX: number, clientY: number) => void;
  onGripTouchEnd: (cancelled?: boolean) => void;
  dropMark: 'before' | 'after' | 'merge' | null;
  expanded: boolean;
  onToggleExpanded: () => void;
  prevTaskId: UUID | null;
  autoEditTitle: boolean;
  onAutoEditTitleConsumed: () => void;
  autoEditSubId: UUID | null;
  onAutoEditSubConsumed: () => void;
  onTitleSave: (taskId: UUID, title: string) => void;
  onTitleDelete: (taskId: UUID) => void;
  onCreateSibling: (draft: string) => void;
  onDemote: (draft: string) => boolean;
  onSubAdd: (afterSubId?: UUID) => void;
  onSubPromote: (subId: UUID, draft: string) => void;
  onNavigate: (currentEl: HTMLElement | null, dir: 'up' | 'down') => boolean;
  onShiftMoveTask: (dir: 'up' | 'down') => boolean;
  onShiftMoveSubtask: (subId: UUID, dir: 'up' | 'down') => boolean;
}

function TaskRow({
  task, sprintLabel, blocks, onTick, onSubTick, onSubSave, onSubDelete, onOpen,
  onDragStart, onRowDragEnd, onRowDragOver, onRowDrop, onRowDragLeave,
  onGripTouchStart, onGripTouchMove, onGripTouchEnd,
  dropMark,
  expanded, onToggleExpanded, prevTaskId,
  autoEditTitle, onAutoEditTitleConsumed,
  autoEditSubId, onAutoEditSubConsumed,
  onTitleSave, onTitleDelete, onCreateSibling, onDemote,
  onSubAdd, onSubPromote, onNavigate,
  onShiftMoveTask, onShiftMoveSubtask,
}: RowProps) {
  const isMobile = useIsMobile();
  // Where the last press landed: a native drag that begins in a text
  // field, a subtask or a control is cancelled, so selecting text or
  // ticking never picks up the whole row.
  const downTarget = useRef<HTMLElement | null>(null);
  const tags = useFira((s) => s.tags);
  const filterIds = useFira((s) => s.listFilter.tag_ids);
  const showListTimes = useFira((s) => s.showListTimes);
  const filterSet = useMemo(() => new Set(filterIds), [filterIds]);
  // Reorder so any tag matching the active filter floats to the front of
  // the row's chip list — that way the 3-chip cap always shows the
  // tags the user actually filtered on, regardless of how the task was
  // tagged. Stable for unmatched (relative order preserved).
  const sortedTagIds = useMemo(() => {
    if (filterSet.size === 0) return task.tag_ids;
    const matched: UUID[] = [];
    const rest: UUID[] = [];
    for (const id of task.tag_ids) {
      (filterSet.has(id) ? matched : rest).push(id);
    }
    return [...matched, ...rest];
  }, [task.tag_ids, filterSet]);
  const visibleTagIds = sortedTagIds.slice(0, 2);
  const moreCount = task.tag_ids.length - visibleTagIds.length;
  const left = taskTimeLeft(task, blocks);
  // Blue is a reward for landing a task under budget, so it only applies
  // once the task is done. On an unfinished task a big remaining number
  // just means the work hasn't started yet — nothing worth celebrating.
  // Both gates must clear: 2h is the floor below which the saving isn't
  // worth flagging at all, and 30% keeps it proportionate to the estimate.
  const plentyLeft =
    task.status === 'done' &&
    left != null &&
    task.estimate_min != null &&
    left >= 120 &&
    left >= task.estimate_min * 0.3;

  // Hold-to-drag follows the input type, independent of layout width.
  // Touch retains document touch events so Safari cannot take over a locked drag.
  const docCleanupRef = useRef<(() => void) | null>(null);
  const suppressDragClickUntil = useRef(0);
  const onLongPress = (e: React.PointerEvent) => {
    navigator.vibrate?.(8);
    onGripTouchStart(task.id);
    let started = false;
    const move = (clientX: number, clientY: number) => {
      if (!started) {
        if (Math.abs(clientX - e.clientX) < 4 && Math.abs(clientY - e.clientY) < 4) return;
        started = true;
      }
      onGripTouchMove(clientX, clientY);
    };
    const finish = (cancelled = false) => {
      docCleanupRef.current?.();
      suppressDragClickUntil.current = Date.now() + 350;
      onGripTouchEnd(cancelled);
    };
    if (e.pointerType !== 'touch') {
      const row = (e.target as HTMLElement).closest('.task-row') as HTMLElement;
      row.setPointerCapture(e.pointerId);
      const onMove = (ev: PointerEvent) => {
        if (ev.pointerId === e.pointerId) move(ev.clientX, ev.clientY);
      };
      const onEnd = (ev: PointerEvent) => { if (ev.pointerId === e.pointerId) finish(); };
      const onCancel = (ev: PointerEvent) => { if (ev.pointerId === e.pointerId) finish(true); };
      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onEnd);
      document.addEventListener('pointercancel', onCancel);
      docCleanupRef.current = () => {
        document.removeEventListener('pointermove', onMove);
        document.removeEventListener('pointerup', onEnd);
        document.removeEventListener('pointercancel', onCancel);
        docCleanupRef.current = null;
      };
      return;
    }
    const onTouchMove = (ev: TouchEvent) => {
      const touch = ev.touches[0];
      if (!touch) return;
      ev.preventDefault();
      move(touch.clientX, touch.clientY);
    };
    const onTouchEnd = () => finish();
    const onTouchCancel = () => finish(true);
    document.addEventListener('touchmove', onTouchMove, { passive: false });
    document.addEventListener('touchend', onTouchEnd);
    document.addEventListener('touchcancel', onTouchCancel);
    docCleanupRef.current = () => {
      document.removeEventListener('touchmove', onTouchMove);
      document.removeEventListener('touchend', onTouchEnd);
      document.removeEventListener('touchcancel', onTouchCancel);
      docCleanupRef.current = null;
    };
  };

  useEffect(() => () => { docCleanupRef.current?.(); }, []);
  const longPress = useLongPress(onLongPress, { holdMs: 220, cancelPx: 8, acceptMouse: true });
  const shouldSuppressDragClick = () =>
    Date.now() < suppressDragClickUntil.current || longPress.shouldSuppressClick();

  // Inline title editor. Desktop only — mobile falls through to the
  // existing tap-to-open-modal flow because there's no Tab key on phones
  // and adding extra editing toolbars is out of scope (see brief).
  const allowInlineEdit = !isMobile;
  const [editingTitle, setEditingTitle] = useState(autoEditTitle);
  const [titleDraft, setTitleDraft] = useState(task.title);
  const titleRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => { setTitleDraft(task.title); }, [task.title]);
  useEffect(() => {
    if (editingTitle) {
      const el = titleRef.current;
      if (el) {
        el.focus();
        // Park the caret at the end so typing extends the title rather
        // than overwriting from the start (common rich-editor convention).
        const len = el.value.length;
        el.setSelectionRange(len, len);
      }
    }
  }, [editingTitle]);
  // Re-fit on every keystroke, not just on open: the draft changes width
  // as the user types, and the row has to grow and shrink with it.
  useLayoutEffect(() => {
    if (editingTitle && titleRef.current) fitToText(titleRef.current);
  }, [editingTitle, titleDraft]);
  // One-shot autoEdit handoff: a freshly-minted task (Enter on previous,
  // Shift+Tab promote from a subtask) gets stamped with autoEditTitle so
  // it lands in edit mode on mount.
  useEffect(() => {
    if (autoEditTitle) { setEditingTitle(true); onAutoEditTitleConsumed(); }
  }, [autoEditTitle, onAutoEditTitleConsumed]);

  const commitTitle = () => {
    const v = titleDraft.trim();
    if (!v) {
      // Empty after edit means "delete this row" — same trim-empty
      // contract the subtask editor uses, so the two views feel like
      // one tool.
      onTitleDelete(task.id);
      return;
    }
    if (v !== task.title) onTitleSave(task.id, v);
    setEditingTitle(false);
  };

  return (
    <div className="task-row"
         data-status={task.status}
         data-drop-mark={dropMark ?? undefined}
         data-task-id={task.id}
         data-pressing={longPress.isPressing ? 'true' : undefined}
         // A mouse drags the row straight away (native drag only starts
         // once the pointer moves, so a click still opens the task).
         // Touch keeps the long-press below.
         draggable={!isMobile && !editingTitle}
         onMouseDownCapture={(e) => { downTarget.current = e.target as HTMLElement; }}
         onDragStart={(e) => {
           if (downTarget.current?.closest('input, textarea, button, a, [contenteditable="true"], .subtask, .task-check')) {
             e.preventDefault();
             return;
           }
           onDragStart(e, task.id);
         }}
         onDragEnd={onRowDragEnd}
         onDragOver={(e) => onRowDragOver(e, task)}
         onDragLeave={onRowDragLeave}
         onDrop={(e) => onRowDrop(e, task)}
         {...longPress.bind}
         onPointerDown={(e) => {
           const target = e.target as HTMLElement;
           if (e.button !== 0 || !e.isPrimary) return;
           if (target.closest('button, a, input, textarea, [contenteditable="true"], .task-check, .sc, .task-toggle, .subtask')) return;
           // Mouse on desktop uses the native drag above, not a hold.
           if (e.pointerType === 'mouse' && !isMobile) return;
           longPress.bind.onPointerDown(e);
         }}
         onClick={(e) => {
           if (shouldSuppressDragClick()) return;
           const el = e.target as HTMLElement;
           // Suppress the "open modal" path only for the controls that
           // own their own click action: tick / subtask tick / drag
           // grip / expand caret. Inline title + subtask editing live
           // on the text spans / inputs themselves and stopPropagation
           // there — clicking surrounding row body still pops the
           // modal, matching pre-inline-edit behavior.
           if (el.closest('.task-check, .sc, .task-toggle')) return;
           if (el.closest('.title-autosize, .subtask-edit-input')) return;
           onOpen(task.id);
         }}>
      <div className="task-check"
           data-checked={task.status === 'done'}
           onClick={(e) => { e.stopPropagation(); onTick(task.id); }}>
        {task.status === 'done' && <Check size={11} strokeWidth={3} />}
      </div>
      <div className="task-title-wrap">
        <div className="task-title-line" data-editing={editingTitle || undefined}>
          {editingTitle ? (
            <span className="title-autosize" data-value={titleDraft}>
              <textarea
                ref={titleRef}
                className="list-title-input"
                rows={1}
                cols={1}
                value={titleDraft}
                onChange={(e) => setTitleDraft(e.target.value)}
                onBlur={commitTitle}
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    const v = titleDraft.trim();
                    if (!v) { onTitleDelete(task.id); return; }
                    if (v !== task.title) onTitleSave(task.id, v);
                    setEditingTitle(false);
                    onCreateSibling(v);
                  }
                  else if (e.key === 'Tab' && !e.shiftKey) {
                    e.preventDefault();
                    // Demote into a subtask of the previous task. Stage 1
                    // ignores the keypress when a demote isn't possible
                    // (no prev task, or current task already has subtasks)
                    // — the input stays in edit mode so the user can
                    // continue typing without losing their place.
                    if (!prevTaskId || task.subtasks.length > 0) return;
                    const ok = onDemote(titleDraft);
                    if (ok) setEditingTitle(false);
                  }
                  else if (e.key === 'Backspace' && !titleDraft) {
                    // Backspace on an empty title removes the row —
                    // matches the subtask handler. We *do* navigate up
                    // first: without it the textarea unmounts with the
                    // task and focus falls back to the body, at which
                    // point the next ↑ / ↓ scroll the page instead of
                    // jumping to the next editable row. Skipped when
                    // the task carries subtasks: a stray empty title
                    // shouldn't one-key destroy nested data.
                    if (task.subtasks.length > 0) return;
                    e.preventDefault();
                    const row = e.currentTarget.closest('.task-row') as HTMLElement | null;
                    onNavigate(row, 'up');
                    setEditingTitle(false);
                    onTitleDelete(task.id);
                  }
                  else if (e.key === 'ArrowUp') {
                    // Shift-modified: move the task itself one slot up
                    // within its render group (assignee bucket in Now,
                    // section list otherwise). Plain Up: move edit
                    // focus to the previous visible row. Multi-line
                    // titles only navigate when the caret is on the
                    // first line so intra-textarea Up still works.
                    if (e.shiftKey) {
                      if (onShiftMoveTask('up')) e.preventDefault();
                      return;
                    }
                    const ta = e.currentTarget;
                    const before = ta.value.slice(0, ta.selectionStart);
                    if (before.includes('\n')) return;
                    const row = ta.closest('.task-row') as HTMLElement | null;
                    if (onNavigate(row, 'up')) e.preventDefault();
                  }
                  else if (e.key === 'ArrowDown') {
                    if (e.shiftKey) {
                      if (onShiftMoveTask('down')) e.preventDefault();
                      return;
                    }
                    const ta = e.currentTarget;
                    const after = ta.value.slice(ta.selectionEnd);
                    if (after.includes('\n')) return;
                    const row = ta.closest('.task-row') as HTMLElement | null;
                    if (onNavigate(row, 'down')) e.preventDefault();
                  }
                  else if (e.key === 'Escape') {
                    setTitleDraft(task.title);
                    setEditingTitle(false);
                  }
                }}
                name="task_title"
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="sentences"
                spellCheck={false}
              />
            </span>
          ) : (
            <span
              className="task-title"
              data-editable={allowInlineEdit || undefined}
              onClick={(e) => {
                // Edit zone scoped to the title text itself — clicking
                // the surrounding row body still opens the modal. On
                // mobile this is a no-op so taps fall through to the
                // existing tap-to-open-modal flow.
                if (shouldSuppressDragClick()) { e.stopPropagation(); return; }
                if (!allowInlineEdit) return;
                e.stopPropagation();
                setEditingTitle(true);
              }}
            >
              {task.title}
            </span>
          )}
          <span className="task-title-tail">
          {task.subtasks.length > 0 && (
            <button
              type="button"
              className="task-toggle"
              data-expanded={expanded || undefined}
              onClick={(e) => { e.stopPropagation(); onToggleExpanded(); }}
              aria-label={expanded ? 'Hide subtasks' : 'Show subtasks'}
              title={expanded ? 'Hide subtasks' : `Show ${task.subtasks.length} subtask${task.subtasks.length === 1 ? '' : 's'}`}
            >
              {/* Just the "2/4" count; clicking it shows the subtasks. */}
              <span className="task-toggle-count">
                {task.subtasks.filter((st) => st.done).length}/{task.subtasks.length}
              </span>
              </button>
          )}
          </span>
        </div>
        {expanded && task.subtasks.length > 0 && (
          <div className="subtasks">
            {task.subtasks.map((s) => (
              <ListSubtaskRow
                key={s.id}
                id={s.id}
                title={s.title}
                done={s.done}
                autoEdit={autoEditSubId === s.id}
                allowInlineEdit={allowInlineEdit}
                onAutoEditConsumed={onAutoEditSubConsumed}
                onToggle={() => onSubTick(task.id, s.id)}
                onSave={(v) => onSubSave(task.id, s.id, v)}
                onDelete={() => onSubDelete(task.id, s.id)}
                onEnterAdd={() => onSubAdd(s.id)}
                onShiftTabPromote={(draft) => onSubPromote(s.id, draft)}
                onNavigate={onNavigate}
                onShiftMove={(dir) => onShiftMoveSubtask(s.id, dir)}
              />
            ))}
          </div>
        )}
      </div>
      {(() => {
        // Mobile: one chip max + a quiet `+N` for the rest, no est-meta
        // (the row is already cramped). Desktop: keep up to 3 chips +
        // est-meta as before.
        const mobileTagIds = visibleTagIds.slice(0, 1);
        const mobileMore = task.tag_ids.length - mobileTagIds.length;
        const trailTagIds = isMobile ? mobileTagIds : visibleTagIds;
        const trailMore = isMobile ? mobileMore : moreCount;
        // Desktop ext-id rides at the head of the trail so the issue
        // key sits at the row's right edge instead of crowding the
        // title text. Mobile keeps it hidden (sprint 17 row strip).
        const showExtId = !isMobile && !!task.external_id;
        // Sprint name follows the ext-id, desktop only for the same
        // reason — on a phone the row has no room to spare.
        const showSprint = !isMobile && !!sprintLabel;
        // Trail collapses to nothing when there's neither a tag chip
        // nor an ext-id to render — same data-driven hide we had
        // before, just extended to consider the new ext-id slot.
        if (isMobile && trailTagIds.length === 0) return null;
        // Desktop: id · sprint · tags · time, each only when present; the
        // trail sizes to its content so the title keeps the most room.
        return (
          <div className="task-trail" data-has-filter={filterSet.size > 0 || undefined}
               data-times={showListTimes || undefined}>
            {showExtId && <span className="ext-id">{task.external_id}</span>}
            {showSprint ? (
              <span className="sprint-label" title={`Sprint: ${sprintLabel!.title}`}>
                <span className="sprint-label-dot" style={sprintLabel!.color ? { background: sprintLabel!.color } : undefined} aria-hidden />
                <span className="sprint-label-text">{sprintLabel!.title}</span>
              </span>
            ) : null}
            {(trailTagIds.length > 0 || trailMore > 0) && <span className="task-tags">
            {trailTagIds.map((tid) => {
              const tag = tags.find((t) => t.id === tid);
              if (!tag) return null;
              const matched = filterSet.has(tid);
              return (
                <span
                  key={tid}
                  className="chip tag-chip"
                  data-match={matched || undefined}
                  style={{ ['--tag-color' as string]: tag.color }}
                >
                  {tag.title}
                </span>
              );
            })}
            {trailMore > 0 && (
              <span
                className="chip tag-chip-more"
                title={`+${trailMore} more tag${trailMore === 1 ? '' : 's'}`}
              >
                +{trailMore}
              </span>
            )}
            </span>}
            {!isMobile && showListTimes && (
              task.has_private_time ? <span className="left-est" title="Time left cannot be calculated from visible blocks">Private time excluded</span> : task.estimate_min != null && left != null ? (
                left < 0 ? (
                  <span className="left-est" data-over="true">+{fmtMin(-left)} over</span>
                ) : (
                  <span className="left-est" data-plenty={plentyLeft || undefined}>{fmtMin(left)} left</span>
                )
              ) : (
                <span className="left-est" data-none="true">No estimate</span>
              )
            )}
          </div>
        );
      })()}
    </div>
  );
}

function groupArchivedTasks(tasks: Task[]): Array<{ key: string; label: string; tasks: Task[] }> {
  const groups = new Map<string, { label: string; tasks: Task[] }>();
  for (const task of tasks) {
    const timestamp = task.finished_at ?? task.created_at;
    const { key, label } = archiveDateGroup(timestamp);
    const group = groups.get(key);
    if (group) group.tasks.push(task);
    else groups.set(key, { label, tasks: [task] });
  }
  return [...groups.entries()].map(([key, group]) => ({ key, ...group }));
}

function archiveDateGroup(iso: string): { key: string; label: string } {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return { key: "unknown", label: "Earlier" };
  const midnight = (value: Date) => new Date(value.getFullYear(), value.getMonth(), value.getDate()).getTime();
  const daysAgo = Math.max(0, Math.round((midnight(new Date()) - midnight(date)) / 86_400_000));
  const dayKey = new Intl.DateTimeFormat("en-CA", { year: "numeric", month: "2-digit", day: "2-digit" }).format(date);
  if (daysAgo === 0) return { key: `day-${dayKey}`, label: "Today" };
  if (daysAgo === 1) return { key: `day-${dayKey}`, label: "Yesterday" };
  if (daysAgo < 7) return {
    key: `day-${dayKey}`,
    label: new Intl.DateTimeFormat(undefined, { weekday: "long", month: "short", day: "numeric" }).format(date),
  };
  if (daysAgo < 14) return { key: "last-week", label: "Last week" };
  const now = new Date();
  if (date.getFullYear() === now.getFullYear() && date.getMonth() === now.getMonth()) {
    return { key: "earlier-this-month", label: "Earlier this month" };
  }
  const monthKey = `${date.getFullYear()}-${date.getMonth()}`;
  return {
    key: `month-${monthKey}`,
    label: new Intl.DateTimeFormat(undefined, { month: "long", year: "numeric" }).format(date),
  };
}

// Sticky tag filter strip. Sits at the top of the scroll container so the
// active filter stays visible as the user scrolls down through Now / Later
// / Done. The Me/All scope pill is omitted when a project has only one
// active member; the tag chips section hides itself when the project has no
// tags so empty chips do not show up as visual noise.
