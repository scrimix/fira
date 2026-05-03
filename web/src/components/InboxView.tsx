import { useEffect, useRef, useState } from 'react';
import { Check, Pencil } from 'lucide-react';
import { useFira } from '../store';
import { useLongPress } from '../useLongPress';
import { ProjectIcon } from './ProjectIcon';
import type { Task, TimeBlock, Section, UUID } from '../types';

const byKey = (a: Task, b: Task) => a.sort_key.localeCompare(b.sort_key);

export function InboxView() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const projects = useFira((s) => s.projects);
  const users = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const inboxFilter = useFira((s) => s.inboxFilter);
  const tickTask = useFira((s) => s.tickTask);
  const tickSubtask = useFira((s) => s.tickSubtask);
  const setSubtaskTitle = useFira((s) => s.setSubtaskTitle);
  const deleteSubtask = useFira((s) => s.deleteSubtask);
  const setTaskSection = useFira((s) => s.setTaskSection);
  const setTaskAssignee = useFira((s) => s.setTaskAssignee);
  const reorderTasks = useFira((s) => s.reorderTasks);
  const addTask = useFira((s) => s.addTask);
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
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ done: true });
  const [collapsedAssignee, setCollapsedAssignee] = useState<Record<UUID, boolean>>({});
  const [dropTarget, setDropTarget] = useState<Section | null>(null);
  const [assigneeDropTarget, setAssigneeDropTarget] = useState<UUID | null>(null);
  const [rowDropAt, setRowDropAt] = useState<{ id: UUID; pos: 'before' | 'after' } | null>(null);

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

  const projectTasks = tasks.filter((t) => t.project_id === project.id);
  const nowTasks = projectTasks.filter((t) => t.section === 'now').sort(byKey);
  const laterTasks = projectTasks.filter((t) => t.section === 'later').sort(byKey);
  const doneTasks = projectTasks.filter((t) => t.section === 'done').sort(byKey);
  // Caller floats to the top of the assignee groups; the rest stay in
  // membership order. Members with role 'owner' (the workspace owner's
  // default per-project stance) or 'inactive' (a member who's been parked)
  // are hidden unless they have a Now task assigned — otherwise they'd
  // render as empty assignee groups regardless of involvement.
  const nowAssignees = new Set(nowTasks.map((t) => t.assignee_id).filter((x): x is UUID => !!x));
  const visibleMembers = project.members.filter(
    (m) => (m.role !== 'owner' && m.role !== 'inactive') || nowAssignees.has(m.user_id),
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

  const onRowDragStart = (e: React.DragEvent, taskId: string) => {
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', taskId);
  };
  const onRowDragOver = (e: React.DragEvent, target: Task) => {
    if (e.dataTransfer.types.includes('text/plain')) {
      e.preventDefault();
      e.stopPropagation();
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      const pos: 'before' | 'after' = e.clientY < rect.top + rect.height / 2 ? 'before' : 'after';
      setRowDropAt({ id: target.id, pos });
    }
  };
  const onRowDrop = (e: React.DragEvent, target: Task) => {
    e.preventDefault();
    e.stopPropagation();
    setRowDropAt(null);
    setDropTarget(null);
    setAssigneeDropTarget(null);
    const draggedId = e.dataTransfer.getData('text/plain');
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const insertBefore = e.clientY < rect.top + rect.height / 2;
    applyTaskMove(draggedId, target, insertBefore);
  };
  const onSectionDrop = (e: React.DragEvent, section: Section) => {
    e.preventDefault();
    const id = e.dataTransfer.getData('text/plain');
    if (id) setTaskSection(id, section);
    setDropTarget(null);
    setRowDropAt(null);
  };

  // Touch-based drag for the grip column. HTML5 drag-and-drop doesn't
  // fire from touch, so we run a parallel pointer-events flow that
  // resolves to the same applyTaskMove / setTaskSection logic on
  // release. The grip uses setPointerCapture so subsequent moves come
  // back to it even when the finger leaves the row.
  const touchDraggedRef = useRef<UUID | null>(null);
  const touchDropAtRef = useRef<{ id: UUID; pos: 'before' | 'after' } | null>(null);
  const touchSectionRef = useRef<Section | null>(null);
  const touchAssigneeRef = useRef<UUID | null>(null);
  const onGripTouchStart = (taskId: UUID) => {
    touchDraggedRef.current = taskId;
    touchDropAtRef.current = null;
    touchSectionRef.current = null;
    touchAssigneeRef.current = null;
    setRowDropAt(null);
    setDropTarget(null);
    setAssigneeDropTarget(null);
  };
  const onGripTouchMove = (clientX: number, clientY: number) => {
    const dragged = touchDraggedRef.current;
    if (!dragged) return;
    const el = document.elementFromPoint(clientX, clientY) as HTMLElement | null;
    const rowEl = el?.closest('[data-task-id]') as HTMLElement | null;
    if (rowEl && rowEl.dataset.taskId && rowEl.dataset.taskId !== dragged) {
      const rect = rowEl.getBoundingClientRect();
      const pos: 'before' | 'after' = clientY < rect.top + rect.height / 2 ? 'before' : 'after';
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
    if (!dragged) return;
    if (dropAt) {
      const target = tasks.find((t) => t.id === dropAt.id);
      if (target) applyTaskMove(dragged, target, dropAt.pos === 'before');
    } else if (assignee) {
      const draggedTask = tasks.find((t) => t.id === dragged);
      if (draggedTask) {
        if (draggedTask.assignee_id !== assignee) setTaskAssignee(dragged, assignee);
        if (draggedTask.section !== 'now') setTaskSection(dragged, 'now');
      }
    } else if (section) {
      setTaskSection(dragged, section);
    }
  };

  const renderRow = (t: Task, showSubs: boolean) => (
    <TaskRow key={t.id} task={t} blocks={blocks}
             onTick={tickTask}
             onSubTick={tickSubtask}
             onSubSave={setSubtaskTitle}
             onSubDelete={deleteSubtask}
             onOpen={openTask}
             onDragStart={onRowDragStart}
             onRowDragOver={onRowDragOver}
             onRowDrop={onRowDrop}
             onRowDragLeave={() => setRowDropAt(null)}
             onGripTouchStart={onGripTouchStart}
             onGripTouchMove={onGripTouchMove}
             onGripTouchEnd={onGripTouchEnd}
             dropMark={rowDropAt?.id === t.id ? rowDropAt.pos : null}
             showSubs={showSubs} />
  );

  const archivable = projectTasks.filter((t) => t.status === 'done' && t.section !== 'done');
  const archiveDone = () => {
    for (const t of archivable) setTaskSection(t.id, 'done');
  };

  return (
    <div className="inbox">
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

        {/* NOW */}
        <div className="section" data-section="now"
             style={dropTarget === 'now' ? { background: 'var(--accent-soft)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('now'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onSectionDrop(e, 'now')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, now: !collapsed.now })}>
            <span className="caret">{collapsed.now ? '▸' : '▾'}</span>
            <h2>Now</h2>
            <span className="count">{nowTasks.length}</span>
            <span className="rule" />
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
                         setAssigneeDropTarget(aid);
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
                        {subTasks.map((t) => renderRow(t, true))}
                        <AddTaskRow
                          placeholder={`Add task for ${firstName}…`}
                          onAdd={(title) => addTask(project.id, 'now', title, aid)}
                        />
                      </>
                    )}
                  </div>
                );
              }) : (
                <>
                  {nowTasks.filter((t) => t.assignee_id != null).map((t) => renderRow(t, true))}
                  <AddTaskRow onAdd={(title) => addTask(project.id, 'now', title)} />
                </>
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
                    {!folded && unassigned.map((t) => renderRow(t, true))}
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
            <span className="count">{laterTasks.length}</span>
            <span className="rule" />
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>parking lot</span>
          </div>
          {!collapsed.later && (
            <>
              {laterTasks.map((t) => renderRow(t, false))}
              <AddTaskRow onAdd={(title) => addTask(project.id, 'later', title)} />
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
            <span className="count">{doneTasks.length}</span>
            <span className="rule" />
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>archive</span>
          </div>
          {!collapsed.done && (
            <>
              {doneTasks.map((t) => renderRow(t, false))}
              <AddTaskRow onAdd={(title) => addTask(project.id, 'done', title)} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function AddTaskRow({ onAdd, placeholder = 'Add task…' }: {
  onAdd: (title: string) => void;
  placeholder?: string;
}) {
  const [value, setValue] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const commit = () => {
    const v = value.trim();
    if (v) onAdd(v);
    setValue('');
  };

  return (
    <div className="task-add" data-editing="true" onClick={() => inputRef.current?.focus()}>
      <span className="task-add-plus">+</span>
      <input
        ref={inputRef}
        className="task-add-input"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); commit(); }
          else if (e.key === 'Escape') { setValue(''); inputRef.current?.blur(); }
        }}
        placeholder={placeholder}
        // iOS Safari pops "Hide My Email" / iCloud password chips on
        // any generic text input regardless of autocomplete hints. Using
        // type="search" routes around the heuristic; the search-specific
        // chrome (magnifier, cancel button) is suppressed in CSS.
        name="task_title"
        type="search"
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="sentences"
        spellCheck={false}
      />
    </div>
  );
}

function InboxSubtaskRow({ title, done, onToggle, onSave, onDelete }: {
  title: string;
  done: boolean;
  onToggle: () => void;
  onSave: (v: string) => void;
  onDelete: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(title);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { setDraft(title); }, [title]);
  useEffect(() => { if (editing) inputRef.current?.focus(); }, [editing]);

  // Empty title on commit means the user deleted everything — treat as delete,
  // matching the modal's behavior so the two views feel like one tool.
  const commit = () => {
    const v = draft.trim();
    if (!v) { onDelete(); return; }
    if (v !== title) onSave(v);
    setEditing(false);
  };

  return (
    // No stopPropagation: on inbox, the subtask body should behave as
    // part of the parent row — tap opens the task, long-press drags
    // the task. The checkbox (.sc) handles its own click and stops
    // there, so toggling done doesn't also open the modal.
    <div className={editing ? 'subtask subtask-edit' : 'subtask'} data-done={done}>
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
            if (e.key === 'Enter') { e.preventDefault(); commit(); }
            else if (e.key === 'Escape') { setDraft(title); setEditing(false); }
            else if (e.key === 'Backspace' && !draft) { e.preventDefault(); onDelete(); }
          }}
          name="subtask_title"
          type="search"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="sentences"
          spellCheck={false}
        />
      ) : (
        // Edit-on-click disabled in the inbox: too easy to hit while
        // aiming for the parent task row, and the resulting edit input
        // looks like a click miss. Subtasks are still editable from
        // the task modal — open the parent to rename or delete.
        <span className="sname" style={{ flex: 1 }}>
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
  onRowDragOver: (e: React.DragEvent, target: Task) => void;
  onRowDrop: (e: React.DragEvent, target: Task) => void;
  onRowDragLeave: () => void;
  onGripTouchStart: (taskId: UUID) => void;
  onGripTouchMove: (clientX: number, clientY: number) => void;
  onGripTouchEnd: () => void;
  dropMark: 'before' | 'after' | null;
  showSubs: boolean;
}

function TaskRow({
  task, blocks, onTick, onSubTick, onSubSave, onSubDelete, onOpen,
  onDragStart, onRowDragOver, onRowDrop, onRowDragLeave,
  onGripTouchStart, onGripTouchMove, onGripTouchEnd,
  dropMark, showSubs,
}: RowProps) {
  const [dragOnHandle, setDragOnHandle] = useState(false);

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

  return (
    <div className="task-row"
         data-status={task.status}
         data-drop-mark={dropMark ?? undefined}
         data-task-id={task.id}
         data-pressing={longPress.isPressing ? 'true' : undefined}
         draggable={dragOnHandle}
         onDragStart={(e) => onDragStart(e, task.id)}
         onDragEnd={() => setDragOnHandle(false)}
         onDragOver={(e) => onRowDragOver(e, task)}
         onDragLeave={onRowDragLeave}
         onDrop={(e) => onRowDrop(e, task)}
         {...longPress.bind}
         onClick={(e) => {
           if (longPress.shouldSuppressClick()) return;
           const el = e.target as HTMLElement;
           // Subtask body taps fall through to open the task — only the
           // two checkboxes and the grip suppress the open.
           if (el.closest('.task-check, .sc, .task-grip')) return;
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
        <div>
          <span className="task-title">{task.title}</span>
        </div>
        {showSubs && task.subtasks.length > 0 && (
          <div className="subtasks">
            {task.subtasks.map((s) => (
              <InboxSubtaskRow
                key={s.id}
                title={s.title}
                done={s.done}
                onToggle={() => onSubTick(task.id, s.id)}
                onSave={(v) => onSubSave(task.id, s.id, v)}
                onDelete={() => onSubDelete(task.id, s.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
