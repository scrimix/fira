import { useEffect, useRef, useState } from 'react';
import { Pencil } from 'lucide-react';
import { useFira } from '../store';
import { fmtMin, taskTimeLeft } from '../time';
import { ProjectIcon } from './ProjectIcon';
import type { Task, TimeBlock, Section, UUID } from '../types';

const byKey = (a: Task, b: Task) => a.sort_key.localeCompare(b.sort_key);

export function InboxView() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const projects = useFira((s) => s.projects);
  const users = useFira((s) => s.users);
  const inboxFilter = useFira((s) => s.inboxFilter);
  const tickTask = useFira((s) => s.tickTask);
  const tickSubtask = useFira((s) => s.tickSubtask);
  const addSubtask = useFira((s) => s.addSubtask);
  const setSubtaskTitle = useFira((s) => s.setSubtaskTitle);
  const deleteSubtask = useFira((s) => s.deleteSubtask);
  const setTaskSection = useFira((s) => s.setTaskSection);
  const setTaskAssignee = useFira((s) => s.setTaskAssignee);
  const reorderTasks = useFira((s) => s.reorderTasks);
  const addTask = useFira((s) => s.addTask);
  const openTask = useFira((s) => s.openTask);
  const openEditProject = useFira((s) => s.openEditProject);

  const project = projects.find((p) => p.id === inboxFilter.project_id);
  if (!project) {
    return <div className="inbox"><div className="inbox-doc">No project selected.</div></div>;
  }

  const projectTasks = tasks.filter((t) => t.project_id === project.id);
  const nowTasks = projectTasks.filter((t) => t.section === 'now').sort(byKey);
  const laterTasks = projectTasks.filter((t) => t.section === 'later').sort(byKey);
  const doneTasks = projectTasks.filter((t) => t.section === 'done').sort(byKey);
  const assigneeIds = project.members;

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ done: true });
  const [collapsedAssignee, setCollapsedAssignee] = useState<Record<UUID, boolean>>({});
  const [dropTarget, setDropTarget] = useState<Section | null>(null);
  const [assigneeDropTarget, setAssigneeDropTarget] = useState<UUID | null>(null);
  const [rowDropAt, setRowDropAt] = useState<{ id: UUID; pos: 'before' | 'after' } | null>(null);
  const userById = (id: string | null) => users.find((u) => u.id === id);

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
    const draggedId = e.dataTransfer.getData('text/plain');
    if (!draggedId || draggedId === target.id) return;
    const dragged = tasks.find((t) => t.id === draggedId);
    if (!dragged || dragged.project_id !== target.project_id) return;
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const insertBefore = e.clientY < rect.top + rect.height / 2;

    // Cross-section: switch section first, then reorder within target section.
    if (dragged.section !== target.section) {
      setTaskSection(draggedId, target.section);
    }
    // Cross-assignee: dropping onto a row owned by a different person within
    // the Now section reassigns the task to that person.
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
  const onSectionDrop = (e: React.DragEvent, section: Section) => {
    e.preventDefault();
    const id = e.dataTransfer.getData('text/plain');
    if (id) setTaskSection(id, section);
    setDropTarget(null);
    setRowDropAt(null);
  };

  const renderRow = (t: Task, showSubs: boolean) => (
    <TaskRow key={t.id} task={t} blocks={blocks}
             onTick={tickTask}
             onSubTick={tickSubtask}
             onAddSub={addSubtask}
             onSubSave={setSubtaskTitle}
             onSubDelete={deleteSubtask}
             onOpen={openTask}
             onDragStart={onRowDragStart}
             onRowDragOver={onRowDragOver}
             onRowDrop={onRowDrop}
             onRowDragLeave={() => setRowDropAt(null)}
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
              {project.source.toUpperCase()} · {projectTasks.length} tasks · {project.members.length} {project.members.length === 1 ? 'member' : 'members'}
            </span>
            <button className="icon-btn proj-edit-btn"
                    onClick={() => openEditProject(project.id)}
                    title="Edit project">
              <Pencil size={14} strokeWidth={1.75} />
            </button>
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
                      <div className="avatar" data-me={u?.email === 'maya@fira.dev'}>{u?.initials ?? '?'}</div>
                      <span>{u?.name}{u?.email === 'maya@fira.dev' ? ' (you)' : ''}</span>
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
                  {nowTasks.map((t) => renderRow(t, true))}
                  <AddTaskRow onAdd={(title) => addTask(project.id, 'now', title)} />
                </>
              )}
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
    <div className={editing ? 'subtask subtask-edit' : 'subtask'} data-done={done}
         onClick={(e) => e.stopPropagation()}>
      <span className="sc" onClick={onToggle}>{done ? '✓' : ''}</span>
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
        />
      ) : (
        <span className="sname" onClick={() => setEditing(true)} style={{ cursor: 'text', flex: 1 }}>
          {title}
        </span>
      )}
    </div>
  );
}

function AddSubtaskRowInline({ onAdd }: { onAdd: (title: string) => void }) {
  const [value, setValue] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const commit = () => {
    const v = value.trim();
    if (v) onAdd(v);
    setValue('');
    inputRef.current?.focus();
  };

  return (
    <div className="subtask-add" data-editing="true"
         onClick={(e) => { e.stopPropagation(); inputRef.current?.focus(); }}>
      <span className="sc-spacer">+</span>
      <input
        ref={inputRef}
        className="subtask-add-input"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onClick={(e) => e.stopPropagation()}
        onBlur={() => {
          const v = value.trim();
          if (v) onAdd(v);
          setValue('');
        }}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); commit(); }
          else if (e.key === 'Escape') { setValue(''); inputRef.current?.blur(); }
        }}
        placeholder="Add subtask…"
      />
    </div>
  );
}

interface RowProps {
  task: Task;
  blocks: TimeBlock[];
  onTick: (id: string) => void;
  onSubTick: (taskId: string, subId: string) => void;
  onAddSub: (taskId: UUID, title: string) => void;
  onSubSave: (taskId: UUID, subId: UUID, title: string) => void;
  onSubDelete: (taskId: UUID, subId: UUID) => void;
  onOpen: (id: string) => void;
  onDragStart: (e: React.DragEvent, id: string) => void;
  onRowDragOver: (e: React.DragEvent, target: Task) => void;
  onRowDrop: (e: React.DragEvent, target: Task) => void;
  onRowDragLeave: () => void;
  dropMark: 'before' | 'after' | null;
  showSubs: boolean;
}

function TaskRow({
  task, blocks, onTick, onSubTick, onAddSub, onSubSave, onSubDelete, onOpen,
  onDragStart, onRowDragOver, onRowDrop, onRowDragLeave, dropMark, showSubs,
}: RowProps) {
  const left = taskTimeLeft(task, blocks);
  const lowLeft = left != null && task.estimate_min != null && left < task.estimate_min * 0.2 && left > 0;
  const [dragOnHandle, setDragOnHandle] = useState(false);

  return (
    <div className="task-row"
         data-status={task.status}
         data-drop-mark={dropMark ?? undefined}
         draggable={dragOnHandle}
         onDragStart={(e) => onDragStart(e, task.id)}
         onDragEnd={() => setDragOnHandle(false)}
         onDragOver={(e) => onRowDragOver(e, task)}
         onDragLeave={onRowDragLeave}
         onDrop={(e) => onRowDrop(e, task)}
         onClick={(e) => {
           const el = e.target as HTMLElement;
           if (el.closest('.task-check, .subtask, .subtask-add, .task-grip')) return;
           onOpen(task.id);
         }}>
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
          {task.external_id && <span className="ext-id">{task.external_id}</span>}
          <span className="task-title">{task.title}</span>
        </div>
        {showSubs && (
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
            <AddSubtaskRowInline onAdd={(title) => onAddSub(task.id, title)} />
          </div>
        )}
      </div>
      <div className="task-trail">
        {task.tags.slice(0, 1).map((tg) => (
          <span key={tg} className="chip" style={{ height: 16, fontSize: 9 }}>{tg}</span>
        ))}
        {task.estimate_min != null && left != null ? (
          left < 0 ? (
            <span className="left-est" data-over="true">{fmtMin(-left)} over</span>
          ) : (
            <span className="left-est" data-low={lowLeft}>{fmtMin(left)} left</span>
          )
        ) : (
          <span style={{ color: 'var(--ink-4)' }}>no est</span>
        )}
        <span className="src" title={task.source}>
          {task.source === 'jira' ? 'J' : task.source === 'notion' ? 'N' : '·'}
        </span>
      </div>
    </div>
  );
}
