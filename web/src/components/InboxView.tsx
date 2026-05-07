import { useEffect, useMemo, useRef, useState } from 'react';
import { Check, ChevronDown, ChevronRight, Clock, ClockFading, Pencil } from 'lucide-react';
import { useFira } from '../store';
import { useLongPress } from '../useLongPress';
import { useIsMobile } from '../hooks';
import { fmtMin, taskCompletedMin, taskPlannedMin, taskTimeLeft } from '../time';
import { ProjectIcon } from './ProjectIcon';
import type { Tag, Task, TimeBlock, Section, UUID } from '../types';

const byKey = (a: Task, b: Task) => a.sort_key.localeCompare(b.sort_key);

export function InboxView() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const projects = useFira((s) => s.projects);
  const allTags = useFira((s) => s.tags);
  const users = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const inboxFilter = useFira((s) => s.inboxFilter);
  const setInboxFilter = useFira((s) => s.setInboxFilter);
  const showInboxTimes = useFira((s) => s.showInboxTimes);
  const setShowInboxTimes = useFira((s) => s.setShowInboxTimes);
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

  const project = projects.find((p) => p.id === inboxFilter.project_id);
  // Workspace owner can edit any project; project leads/owners (the
  // per-project role 'owner' carries the same edit power as 'lead', it
  // just controls inbox visibility) can edit theirs. Members and outsiders
  // see no pencil.
  const myProjectMembership = project?.members.find((m) => m.user_id === meId) ?? null;
  const canEditThisProject = myWorkspaceRole === 'owner'
    || myProjectMembership?.role === 'lead'
    || myProjectMembership?.role === 'owner';

  // Hooks must run unconditionally on every render — the empty-state branch
  // below is an early return, so all useState/useRef calls live above it.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ done: true, someday: true });
  const [collapsedAssignee, setCollapsedAssignee] = useState<Record<UUID, boolean>>({});
  const [dropTarget, setDropTarget] = useState<Section | null>(null);
  const [assigneeDropTarget, setAssigneeDropTarget] = useState<UUID | null>(null);
  const [rowDropAt, setRowDropAt] = useState<{ id: UUID; pos: 'before' | 'after' | 'merge' } | null>(null);
  // Per-task subtask-list visibility. Default is collapsed for every task —
  // the inbox now treats subtasks like Notion-style nested bullets that
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

  // All hook calls (useRef / useEffect / useState) MUST run on every
  // render — including the empty-state path below. Hoisted up here
  // because the create-first-project flow transitions an instance from
  // empty (early-return) to populated (full render), and React's
  // rules-of-hooks rejects a hooks-count change between renders. The
  // refs / cleanup effect themselves don't depend on `project`; they
  // just need to be declared in stable order.
  const desktopDragIdRef = useRef<UUID | null>(null);
  const inboxScrollRef = useRef<HTMLDivElement>(null);
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
      <div className="inbox">
        <div className="inbox-doc inbox-empty">
          {projects.length > 0 ? (
            <p className="inbox-empty-msg">Pick a project from the sidebar.</p>
          ) : canCreateProject ? (
            <div className="inbox-empty-cta">
              <p className="inbox-empty-msg">This workspace has no projects yet.</p>
              <button className="inbox-empty-link" onClick={openCreateProject}>
                Create your first project
              </button>
            </div>
          ) : (
            <div className="inbox-empty-cta">
              <p className="inbox-empty-msg">You're not a member of any project.</p>
              <p className="inbox-empty-sub">
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
  const tagFilter = inboxFilter.tag_ids;
  const tagMode = inboxFilter.tag_mode;
  // Default `all` covers persisted state from before this field existed.
  const assigneeScope = inboxFilter.assignee_scope ?? 'all';
  const projectTasks = allProjectTasks.filter((t) => {
    if (assigneeScope === 'me' && t.assignee_id !== meId) return false;
    if (tagFilter.length > 0) {
      if (tagMode === 'and') {
        return tagFilter.every((id) => t.tag_ids.includes(id));
      }
      return tagFilter.some((id) => t.tag_ids.includes(id));
    }
    return true;
  });
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
  for (const t of projectTasks) {
    totalDone += taskCompletedMin(t, blocks);
    totalPlanned += taskPlannedMin(t, blocks);
    if (t.estimate_min != null) totalEst += t.estimate_min;
  }
  const totalAll = totalDone + totalPlanned;

  const nowTasks = projectTasks.filter((t) => t.section === 'now').sort(byKey);
  const laterTasks = projectTasks.filter((t) => t.section === 'later').sort(byKey);
  const somedayTasks = projectTasks.filter((t) => t.section === 'someday').sort(byKey);
  // Per-section estimate roll-up. Surfaced next to the task count so a
  // section's "weight" (especially Someday, which collects intentions
  // indefinitely) is visible without expanding the list.
  const sumEst = (xs: Task[]) => xs.reduce((s, t) => s + (t.estimate_min ?? 0), 0);
  const nowEst = sumEst(nowTasks);
  const laterEst = sumEst(laterTasks);
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
    const container = inboxScrollRef.current;
    if (!container) return;
    dragScrollStopRef.current?.();
    dragCursorRef.current = null;

    let removeListener: (() => void) | undefined;
    if (mode === 'drag') {
      const onDragOver = (ev: DragEvent) => {
        dragCursorRef.current = { x: ev.clientX, y: ev.clientY };
      };
      document.addEventListener('dragover', onDragOver);
      removeListener = () => document.removeEventListener('dragover', onDragOver);
    }

    // Asymmetric zones: bottom is wider so the user can scroll down toward
    // the natural "tail" of a long list (someday / done / new tasks)
    // without having to push the cursor to the very last few pixels.
    // Top is moderately wide so dragging upward to Now still feels
    // responsive without hijacking the cursor too aggressively.
    const ZONE_TOP = 100;
    const ZONE_BOTTOM = 160;
    const MAX_SPEED = 8;
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
    setRowDropAt(null);
    setDropTarget(null);
    setAssigneeDropTarget(null);
    const draggedId = e.dataTransfer.getData('text/plain');
    if (!draggedId) { suspendHover(); return; }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const pos = resolveRowDropPos(e.clientY, rect);
    if (pos === 'merge' && draggedId !== target.id) {
      mergeTaskInto(draggedId, target.id);
      // Auto-expand so the user sees what they just merged into the
      // target — mirrors the Tab-demote handler's expansion behavior.
      setExpandedSubs((p) => ({ ...p, [target.id]: true }));
    } else {
      applyTaskMove(draggedId, target, pos === 'before');
    }
    suspendHover();
  };
  const onSectionDrop = (e: React.DragEvent, section: Section) => {
    e.preventDefault();
    const id = e.dataTransfer.getData('text/plain');
    if (id) setTaskSection(id, section);
    setDropTarget(null);
    setRowDropAt(null);
    suspendHover();
  };

  // Touch-based drag for the grip column. HTML5 drag-and-drop doesn't
  // fire from touch, so we run a parallel pointer-events flow that
  // resolves to the same applyTaskMove / setTaskSection logic on
  // release. The grip uses setPointerCapture so subsequent moves come
  // back to it even when the finger leaves the row. (Refs are hoisted
  // to the top — see the block after the useState declarations.)
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
  const onGripTouchEnd = () => {
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
    if (!dragged) return;
    if (dropAt) {
      const target = tasks.find((t) => t.id === dropAt.id);
      if (target) {
        if (dropAt.pos === 'merge' && dragged !== target.id) {
          mergeTaskInto(dragged, target.id);
          setExpandedSubs((p) => ({ ...p, [target.id]: true }));
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
    const root = inboxScrollRef.current;
    if (!root || !currentEl) return false;
    // The chain spans every editable stop in document order: task
    // rows, subtask rows, *and* the per-section / per-assignee
    // "Add task…" rows. Section walking happens for free because all
    // sections live in the same .inbox container — collapsed
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
    <div className="inbox" ref={inboxScrollRef} data-suspend-hover={hoverSuspended || undefined}>
      <div className="inbox-doc" style={{ ['--proj-color' as string]: project.color }}>
        <div className="inbox-proj-head">
          <span className="icon" style={{ color: project.color }}>
            <ProjectIcon name={project.icon} color={project.color} size={20} strokeWidth={1.6} />
          </span>
          <h1>{project.title}</h1>
          <div className="proj-actions">
            <span className="meta">
              {projectTasks.length} tasks · {project.members.length} {project.members.length === 1 ? 'member' : 'members'}
            </span>
            <button
              className="icon-btn proj-edit-btn time-toggle-btn"
              onClick={() => setShowInboxTimes(!showInboxTimes)}
              data-off={!showInboxTimes || undefined}
              title={showInboxTimes ? 'Hide time labels' : 'Show time labels'}
              aria-label={showInboxTimes ? 'Hide time labels' : 'Show time labels'}
            >
              {showInboxTimes
                ? <Clock size={14} strokeWidth={1.75} />
                : <ClockFading size={14} strokeWidth={1.75} />}
            </button>
            {canEditThisProject && (
              <button className="icon-btn proj-edit-btn"
                      onClick={() => openEditProject(project.id)}
                      title="Edit project">
                <Pencil size={14} strokeWidth={1.75} />
              </button>
            )}
            <button className="btn archive-btn"
                    onClick={archiveDone}
                    disabled={archivable.length === 0}
                    title="Move every ticked task into the Done section">
              Archive ticked
              {archivable.length > 0 && <span className="archive-count">{archivable.length}</span>}
            </button>
          </div>
        </div>

        <InboxTagFilter
          projectId={project.id}
          allTags={allTags}
          tagIds={inboxFilter.tag_ids}
          mode={inboxFilter.tag_mode}
          scope={assigneeScope}
          onChange={(tag_ids) => setInboxFilter({ tag_ids })}
          onModeChange={(tag_mode) => setInboxFilter({ tag_mode })}
          onScopeChange={(assignee_scope) => setInboxFilter({ assignee_scope })}
        />

        {showInboxTimes && (
          <div className="totals inbox-totals" aria-label="Filtered totals">
            <span className="totals-done"><strong>{fmtMin(totalDone)}</strong> done</span>
            <span className="totals-planned"><strong>{fmtMin(totalPlanned)}</strong> planned</span>
            <span className="totals-total"><strong>{fmtMin(totalAll)}</strong> total</span>
            <span className="totals-est"><strong>{fmtMin(totalEst)}</strong> est</span>
          </div>
        )}

        {/* NOW */}
        <div className="section" data-section="now"
             style={dropTarget === 'now' ? { background: 'var(--accent-soft)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('now'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'now')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, now: !collapsed.now })}>
            <span className="caret">{collapsed.now ? '▸' : '▾'}</span>
            <h2>Now</h2>
            <SectionCount value={nowTasks.length} />
            <span className="rule" />
            {showInboxTimes && <span className="est" title="estimated time">{fmtMin(nowEst)}</span>}
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>week of apr 27</span>
          </div>
          {!collapsed.now && (
            <>
              {assigneeIds.length > 1 ? assigneeIds.map((aid) => {
                const u = userById(aid);
                const subTasks = nowTasks.filter((t) => t.assignee_id === aid);
                const firstName = u?.name?.split(' ')[0] ?? 'them';
                const folded = !!collapsedAssignee[aid];
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
                      <span className="ah-caret">{folded ? '▸' : '▾'}</span>
                      <div className="avatar" data-me={u?.id === meId}>{u?.initials ?? '?'}</div>
                      <span>{u?.name}{u?.id === meId ? ' (you)' : ''}</span>
                      <span className="ah-rule" />
                      <span className="ah-count">{subTasks.length}</span>
                    </div>
                    {!folded && (
                      <>
                        {subTasks.map((t, i) => renderRow(t, subTasks, i))}
                        <AddTaskRow
                          placeholder={`Add task for ${firstName}…`}
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
                      <span className="ah-caret">{folded ? '▸' : '▾'}</span>
                      <div className="avatar">?</div>
                      <span>Unassigned</span>
                      <span className="ah-rule" />
                      <span className="ah-count">{unassigned.length}</span>
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
             style={dropTarget === 'later' ? { background: 'var(--accent-soft)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('later'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'later')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, later: !collapsed.later })}>
            <span className="caret">{collapsed.later ? '▸' : '▾'}</span>
            <h2>Later</h2>
            <SectionCount value={laterTasks.length} />
            <span className="rule" />
            {showInboxTimes && <span className="est" title="estimated time">{fmtMin(laterEst)}</span>}
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>parking lot</span>
          </div>
          {!collapsed.later && (
            <>
              {laterTasks.map((t, i) => renderRow(t, laterTasks, i))}
              <AddTaskRow onAdd={(title) => addTask(project.id, 'later', title, undefined, tagFilter)} onNavigate={navigateFrom} />
            </>
          )}
        </div>

        {/* SOMEDAY */}
        <div className="section" data-section="someday"
             style={dropTarget === 'someday' ? { background: 'var(--accent-soft)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('someday'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'someday')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, someday: !collapsed.someday })}>
            <span className="caret">{collapsed.someday ? '▸' : '▾'}</span>
            <h2>Someday</h2>
            <SectionCount value={somedayTasks.length} />
            <span className="rule" />
            {showInboxTimes && <span className="est" title="estimated time">{fmtMin(somedayEst)}</span>}
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>maybe</span>
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
            <span className="caret">{collapsed.done ? '▸' : '▾'}</span>
            <h2>Done</h2>
            <SectionCount value={doneTasks.length} />
            <span className="rule" />
            {showInboxTimes && <span className="est" title="completed time">{fmtMin(doneDone)}</span>}
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>archive</span>
          </div>
          {!collapsed.done && (
            <>
              {doneTasks.map((t, i) => renderRow(t, doneTasks, i))}
              <AddTaskRow onAdd={(title) => addTask(project.id, 'done', title, undefined, tagFilter)} onNavigate={navigateFrom} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// Section header count that pulses (color + scale + glow) on every
// change. Skips the initial mount so navigating into the inbox doesn't
// flash all four counts at once. Re-keys the span on each change so the
// CSS animation restarts cleanly even when the value bounces during
// the previous animation.
function SectionCount({ value }: { value: number }) {
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
      {value}
    </span>
  );
}

function AddTaskRow({ onAdd, placeholder = 'Add task…', onNavigate }: {
  onAdd: (title: string) => void;
  placeholder?: string;
  onNavigate?: (currentEl: HTMLElement | null, dir: 'up' | 'down') => boolean;
}) {
  const [value, setValue] = useState('');
  const inputRef = useRef<HTMLTextAreaElement>(null);

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

function InboxSubtaskRow({
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
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { setDraft(title); }, [title]);
  useEffect(() => { if (editing) inputRef.current?.focus(); }, [editing]);
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
        <input
          ref={inputRef}
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
          type="text"
          autoComplete="one-time-code"
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
            // inbox's typing UX stays desktop-only (no "tab" key on
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
  onGripTouchEnd: () => void;
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
  task, blocks, onTick, onSubTick, onSubSave, onSubDelete, onOpen,
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
  const [dragOnHandle, setDragOnHandle] = useState(false);
  const isMobile = useIsMobile();
  const tags = useFira((s) => s.tags);
  const filterIds = useFira((s) => s.inboxFilter.tag_ids);
  const showInboxTimes = useFira((s) => s.showInboxTimes);
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
  const visibleTagIds = sortedTagIds.slice(0, 3);
  const moreCount = task.tag_ids.length - visibleTagIds.length;
  const left = taskTimeLeft(task, blocks);
  const lowLeft = left != null && task.estimate_min != null && left < task.estimate_min * 0.2 && left > 0;

  // Long-press → drag for the whole row on touch. The hook drives
  // `isPressing` (renders as `data-pressing="true"` for the CSS visual)
  // and gives us the moment-of-lock callback in which we hand the
  // gesture off to the drag pipeline. Tap (release before holdMs) and
  // scroll-cancel (>8 px movement) just don't fire onLongPress — the
  // row's normal onClick handles the tap path.
  const docCleanupRef = useRef<(() => void) | null>(null);
  const onLongPress = (e: React.PointerEvent) => {
    // Skip only the children that own their own click action (checkboxes
    // toggle done; we don't want a long-press on those to drag instead).
    // The grip is *not* excluded — it's a pure visual hint on touch, so
    // long-pressing on it should drag the row exactly like long-pressing
    // anywhere else. The split is cleanly Desktop (HTML5 drag, grip
    // mouse-down) vs Mobile (long-press, single path).
    const target = e.target as HTMLElement;
    if (target.closest('.task-check, .sc')) return;
    navigator.vibrate?.(8);
    onGripTouchStart(task.id);
    // Once locked, attach a non-passive document touchmove so iOS can't
    // scroll the page during the drag. Pointer events from React stop
    // firing when iOS reroutes the gesture to its own scroller, so we
    // route through document touch events for the move/end phase.
    let started = false;
    const startX = e.clientX;
    const startY = e.clientY;
    const ENGAGE_PX = 4;
    const onTouchMove = (ev: TouchEvent) => {
      const t0 = ev.touches[0];
      if (!t0) return;
      ev.preventDefault();
      if (!started) {
        if (Math.abs(t0.clientX - startX) < ENGAGE_PX
          && Math.abs(t0.clientY - startY) < ENGAGE_PX) return;
        started = true;
      }
      onGripTouchMove(t0.clientX, t0.clientY);
    };
    const detach = () => {
      document.removeEventListener('touchmove', onTouchMove);
      document.removeEventListener('touchend', onTouchEnd);
      document.removeEventListener('touchcancel', onTouchCancel);
      docCleanupRef.current = null;
    };
    const onTouchEnd = () => { detach(); onGripTouchEnd(); };
    const onTouchCancel = () => { detach(); onGripTouchEnd(); };
    document.addEventListener('touchmove', onTouchMove, { passive: false });
    document.addEventListener('touchend', onTouchEnd);
    document.addEventListener('touchcancel', onTouchCancel);
    docCleanupRef.current = detach;
  };

  // If the component unmounts mid-drag, drop the document listeners.
  useEffect(() => () => { docCleanupRef.current?.(); }, []);

  const longPress = useLongPress(onLongPress, { holdMs: 220, cancelPx: 8 });

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
         draggable={dragOnHandle}
         onDragStart={(e) => onDragStart(e, task.id)}
         onDragEnd={() => { setDragOnHandle(false); onRowDragEnd(); }}
         onDragOver={(e) => onRowDragOver(e, task)}
         onDragLeave={onRowDragLeave}
         onDrop={(e) => onRowDrop(e, task)}
         {...(isMobile ? longPress.bind : {})}
         onClick={(e) => {
           if (longPress.shouldSuppressClick()) return;
           const el = e.target as HTMLElement;
           // Suppress the "open modal" path only for the controls that
           // own their own click action: tick / subtask tick / drag
           // grip / expand caret. Inline title + subtask editing live
           // on the text spans / inputs themselves and stopPropagation
           // there — clicking surrounding row body still pops the
           // modal, matching pre-inline-edit behavior.
           if (el.closest('.task-check, .sc, .task-grip, .task-toggle')) return;
           if (el.closest('.inbox-title-input, .subtask-edit-input')) return;
           onOpen(task.id);
         }}>
      {/* Two drag paths, split by input type:
       *   - Desktop: HTML5 drag-and-drop. The grip's mouse-down arms
       *     `draggable={dragOnHandle}` on the row so a normal click
       *     anywhere else on the row doesn't accidentally enter drag.
       *   - Mobile: long-press anywhere on the row (the useLongPress
       *     hook on the row itself). The grip is a pure visual hint;
       *     it does not own its own touch handler. Touching the grip
       *     bubbles to the row, the long-press timer arms, and the
       *     same code path runs as if the user had pressed the title.
       */}
      <div className="task-grip"
           title="Drag to reorder"
           onMouseDown={() => setDragOnHandle(true)}
           onMouseUp={() => setDragOnHandle(false)}
           onClick={(e) => e.stopPropagation()}>
        <span>::</span>
      </div>
      <div className="task-check"
           data-checked={task.status === 'done'}
           onClick={(e) => { e.stopPropagation(); onTick(task.id); }}>
        {task.status === 'done' ? '✓' : ''}
      </div>
      <div className="task-title-wrap">
        <div className="task-title-line">
          {editingTitle ? (
            <textarea
              ref={titleRef}
              className="inbox-title-input"
              rows={1}
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
          ) : (
            <span
              className="task-title"
              data-editable={allowInlineEdit || undefined}
              onClick={(e) => {
                // Edit zone scoped to the title text itself — clicking
                // the surrounding row body still opens the modal. On
                // mobile this is a no-op so taps fall through to the
                // existing tap-to-open-modal flow.
                if (!allowInlineEdit) return;
                e.stopPropagation();
                setEditingTitle(true);
              }}
            >
              {task.title}
            </span>
          )}
          {!editingTitle && allowInlineEdit && (
            // Click-past-text edit zone, always between title and
            // toggle. Narrow to 1 char when a toggle follows so the
            // chevron stays close to the title; wide (5 ch) when
            // there's no toggle so the user gets a generous click-
            // to-type-at-end target.
            <span
              className="task-title-edit-pad"
              data-narrow={task.subtasks.length > 0 || undefined}
              aria-hidden="true"
              onClick={(e) => { e.stopPropagation(); setEditingTitle(true); }}
            />
          )}
          {task.subtasks.length > 0 && (
            <button
              type="button"
              className="task-toggle"
              data-expanded={expanded || undefined}
              onClick={(e) => { e.stopPropagation(); onToggleExpanded(); }}
              aria-label={expanded ? 'Hide subtasks' : 'Show subtasks'}
              title={expanded ? 'Hide subtasks' : `Show ${task.subtasks.length} subtask${task.subtasks.length === 1 ? '' : 's'}`}
            >
              {expanded
                ? <ChevronDown size={14} strokeWidth={1.75} />
                : <ChevronRight size={14} strokeWidth={1.75} />}
            </button>
          )}
        </div>
        {expanded && task.subtasks.length > 0 && (
          <div className="subtasks">
            {task.subtasks.map((s) => (
              <InboxSubtaskRow
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
        // Trail collapses to nothing when there's neither a tag chip
        // nor an ext-id to render — same data-driven hide we had
        // before, just extended to consider the new ext-id slot.
        if (isMobile && trailTagIds.length === 0) return null;
        if (!isMobile && trailTagIds.length === 0 && !showExtId && !showInboxTimes) return null;
        return (
          <div className="task-trail" data-has-filter={filterSet.size > 0 || undefined}>
            {showExtId && (
              <span className="ext-id">{task.external_id}</span>
            )}
            {trailTagIds.map((tid) => {
              const tag = tags.find((t) => t.id === tid);
              if (!tag) return null;
              const matched = filterSet.has(tid);
              return (
                <span
                  key={tid}
                  className="chip tag-chip"
                  data-match={matched || undefined}
                  style={{
                    height: 16,
                    fontSize: 'calc(9px * var(--fs-scale))',
                    ['--tag-color' as string]: tag.color,
                  }}
                >
                  {tag.title}
                </span>
              );
            })}
            {trailMore > 0 && (
              <span
                className="chip tag-chip-more"
                style={{ height: 16, fontSize: 'calc(9px * var(--fs-scale))' }}
                title={`+${trailMore} more tag${trailMore === 1 ? '' : 's'}`}
              >
                +{trailMore}
              </span>
            )}
            {!isMobile && showInboxTimes && (
              task.estimate_min != null && left != null ? (
                left < 0 ? (
                  <span className="left-est" data-over="true">{fmtMin(-left)} over</span>
                ) : (
                  <span className="left-est" data-low={lowLeft || undefined}>{fmtMin(left)} left</span>
                )
              ) : (
                <span style={{ color: 'var(--ink-4)' }}>no est</span>
              )
            )}
          </div>
        );
      })()}
    </div>
  );
}

// Sticky tag filter strip. Sits at the top of the scroll container so the
// active filter stays visible as the user scrolls down through Now / Later
// / Done. Always renders the Me/All scope pill; the tag chips section
// hides itself when the project has no tags so empty chips don't show
// up as visual noise.
function InboxTagFilter({
  projectId, allTags, tagIds, mode, scope,
  onChange, onModeChange, onScopeChange,
}: {
  projectId: UUID;
  allTags: Tag[];
  tagIds: UUID[];
  mode: 'and' | 'or';
  scope: 'me' | 'all';
  onChange: (ids: UUID[]) => void;
  onModeChange: (mode: 'and' | 'or') => void;
  onScopeChange: (scope: 'me' | 'all') => void;
}) {
  // Sort by title length descending so longer chips lead each row.
  // flex-wrap places left-to-right in source order, and seeding rows
  // with long chips lets shorter ones slot into the trailing space —
  // fewer ragged half-empty rows than alphabetical order, especially
  // on narrow widths. Alphabetical secondary sort keeps the order
  // stable for chips of equal length.
  const projectTags = allTags
    .filter((t) => t.project_id === projectId)
    .sort((a, b) => b.title.length - a.title.length || a.title.localeCompare(b.title));

  const selected = new Set(tagIds);
  const toggle = (id: UUID) => {
    if (selected.has(id)) onChange(tagIds.filter((x) => x !== id));
    else onChange([...tagIds, id]);
  };
  const clear = () => onChange([]);
  const hasTags = projectTags.length > 0;

  return (
    <div className="inbox-tag-filter">
      {hasTags && (
        <div className="inbox-tag-filter-chips">
          {projectTags.map((t) => {
            const on = selected.has(t.id);
            return (
              <button
                key={t.id}
                type="button"
                className="chip tag-chip inbox-tag-filter-chip"
                data-on={on || undefined}
                style={{ ['--tag-color' as string]: t.color }}
                onClick={() => toggle(t.id)}
                title={t.title}
              >
                {t.title}
              </button>
            );
          })}
        </div>
      )}
      {/* Controls are always rendered, even with 0 / 1 tag selected, so
       * the layout doesn't shift as the user toggles chips. With one
       * tag, OR/AND yields the same set — the toggle still works, just
       * has no visible effect until a second tag is added. Clear is a
       * safe no-op when nothing is selected. */}
      <div className="inbox-tag-filter-controls">
        <div className="inbox-tag-filter-mode" role="group" aria-label="Assignee scope">
          <button
            type="button"
            className="inbox-tag-filter-mode-seg"
            data-active={scope === 'all' || undefined}
            onClick={() => onScopeChange('all')}
            title="Show every task in this project"
          >
            all
          </button>
          <button
            type="button"
            className="inbox-tag-filter-mode-seg"
            data-active={scope === 'me' || undefined}
            onClick={() => onScopeChange('me')}
            title="Show only tasks assigned to me"
          >
            me
          </button>
        </div>
        {hasTags && (
          <>
            <div className="inbox-tag-filter-mode" role="group" aria-label="Tag match mode">
              <button
                type="button"
                className="inbox-tag-filter-mode-seg"
                data-active={mode === 'or' || undefined}
                onClick={() => onModeChange('or')}
                title="Match tasks with any selected tag"
              >
                or
              </button>
              <button
                type="button"
                className="inbox-tag-filter-mode-seg"
                data-active={mode === 'and' || undefined}
                onClick={() => onModeChange('and')}
                title="Match tasks with every selected tag"
              >
                and
              </button>
            </div>
            <button
              type="button"
              className="inbox-tag-filter-clear"
              onClick={clear}
              disabled={tagIds.length === 0}
              title="Clear tag filter"
            >
              clear
            </button>
          </>
        )}
      </div>
    </div>
  );
}
