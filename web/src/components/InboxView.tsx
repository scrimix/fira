import { useState } from 'react';
import { useFira } from '../store';
import { fmtMin, taskCompletedMin, taskTimeLeft } from '../time';
import type { Task, TimeBlock, Section } from '../types';

export function InboxView() {
  const tasks = useFira((s) => s.tasks);
  const blocks = useFira((s) => s.blocks);
  const projects = useFira((s) => s.projects);
  const users = useFira((s) => s.users);
  const inboxFilter = useFira((s) => s.inboxFilter);
  const tickTask = useFira((s) => s.tickTask);
  const tickSubtask = useFira((s) => s.tickSubtask);
  const setTaskSection = useFira((s) => s.setTaskSection);
  const openTask = useFira((s) => s.openTask);

  const project = projects.find((p) => p.id === inboxFilter.project_id);
  if (!project) {
    return <div className="inbox"><div className="inbox-doc">No project selected.</div></div>;
  }

  const projectTasks = tasks.filter((t) => t.project_id === project.id);
  const nowTasks = projectTasks.filter((t) => t.section === 'now');
  const laterTasks = projectTasks.filter((t) => t.section === 'later');
  const doneTasks = projectTasks.filter((t) => t.section === 'done');
  const assigneeIds = project.members;

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ done: true });
  const [dropTarget, setDropTarget] = useState<Section | null>(null);
  const userById = (id: string | null) => users.find((u) => u.id === id);

  const onDragStart = (e: React.DragEvent, taskId: string) => {
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', taskId);
  };
  const onDrop = (e: React.DragEvent, section: Section) => {
    e.preventDefault();
    const id = e.dataTransfer.getData('text/plain');
    if (id) setTaskSection(id, section);
    setDropTarget(null);
  };

  const renderRow = (t: Task, showSubs: boolean) => (
    <TaskRow key={t.id} task={t} blocks={blocks}
             onTick={tickTask}
             onSubTick={tickSubtask}
             onOpen={openTask}
             onDragStart={onDragStart}
             showSubs={showSubs} />
  );

  return (
    <div className="inbox">
      <div className="inbox-doc" style={{ ['--proj-color' as string]: project.color }}>
        <div className="inbox-proj-head">
          <span className="icon">{project.icon}</span>
          <h1>{project.title}</h1>
          <span className="meta">
            {project.source.toUpperCase()} · {projectTasks.length} tasks · {project.members.length} {project.members.length === 1 ? 'member' : 'members'}
          </span>
        </div>

        {/* NOW */}
        <div className="section" data-section="now"
             style={dropTarget === 'now' ? { background: 'var(--accent-soft)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('now'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onDrop(e, 'now')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, now: !collapsed.now })}>
            <span className="caret">{collapsed.now ? '▸' : '▾'}</span>
            <h2>Now</h2>
            <span className="count">{nowTasks.length}</span>
            <span className="rule" />
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>week of apr 27</span>
          </div>
          {!collapsed.now && (
            assigneeIds.length > 1 ? assigneeIds.map((aid) => {
              const u = userById(aid);
              const subTasks = nowTasks.filter((t) => t.assignee_id === aid);
              return (
                <div key={aid}>
                  <div className="assignee-head">
                    <div className="avatar" data-me={u?.email === 'maya@fira.dev'}>{u?.initials ?? '?'}</div>
                    <span>{u?.name}{u?.email === 'maya@fira.dev' ? ' (you)' : ''}</span>
                    <span className="ah-rule" />
                    <span className="ah-count">{subTasks.length}</span>
                  </div>
                  {subTasks.map((t) => renderRow(t, true))}
                </div>
              );
            }) : nowTasks.map((t) => renderRow(t, true))
          )}
        </div>

        {/* LATER */}
        <div className="section" data-section="later"
             style={dropTarget === 'later' ? { background: 'var(--accent-soft)' } : undefined}
             onDragOver={(e) => { e.preventDefault(); setDropTarget('later'); }}
             onDragLeave={() => setDropTarget(null)}
             onDrop={(e) => onDrop(e, 'later')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, later: !collapsed.later })}>
            <span className="caret">{collapsed.later ? '▸' : '▾'}</span>
            <h2>Later</h2>
            <span className="count">{laterTasks.length}</span>
            <span className="rule" />
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>parking lot</span>
          </div>
          {!collapsed.later && laterTasks.map((t) => renderRow(t, false))}
        </div>

        {/* DONE */}
        <div className="section" data-section="done"
             onDragOver={(e) => { e.preventDefault(); setDropTarget('done'); }}
             onDrop={(e) => onDrop(e, 'done')}>
          <div className="section-head" onClick={() => setCollapsed({ ...collapsed, done: !collapsed.done })}>
            <span className="caret">{collapsed.done ? '▸' : '▾'}</span>
            <h2>Done</h2>
            <span className="count">{doneTasks.length}</span>
            <span className="rule" />
            <span className="count" style={{ fontFamily: 'var(--font-mono)' }}>archive</span>
          </div>
          {!collapsed.done && doneTasks.map((t) => renderRow(t, false))}
        </div>
      </div>
    </div>
  );
}

interface RowProps {
  task: Task;
  blocks: TimeBlock[];
  onTick: (id: string) => void;
  onSubTick: (taskId: string, subId: string) => void;
  onOpen: (id: string) => void;
  onDragStart: (e: React.DragEvent, id: string) => void;
  showSubs: boolean;
}

function TaskRow({ task, blocks, onTick, onSubTick, onOpen, onDragStart, showSubs }: RowProps) {
  const left = taskTimeLeft(task, blocks);
  const completed = taskCompletedMin(task, blocks);
  const overEst = task.estimate_min != null && completed > task.estimate_min;
  const lowLeft = left != null && task.estimate_min != null && left < task.estimate_min * 0.2 && left > 0;

  return (
    <div className="task-row"
         data-status={task.status}
         draggable
         onDragStart={(e) => onDragStart(e, task.id)}
         onClick={(e) => {
           const el = e.target as HTMLElement;
           if (el.closest('.task-check, .subtask')) return;
           onOpen(task.id);
         }}>
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
        {showSubs && task.subtasks.length > 0 && (
          <div className="subtasks">
            {task.subtasks.map((s) => (
              <div key={s.id} className="subtask" data-done={s.done}
                   onClick={(e) => e.stopPropagation()}>
                <span className="sc" onClick={() => onSubTick(task.id, s.id)}>
                  {s.done ? '✓' : ''}
                </span>
                <span className="sname">{s.title}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="task-trail">
        {task.tags.slice(0, 1).map((tg) => (
          <span key={tg} className="chip" style={{ height: 16, fontSize: 9 }}>{tg}</span>
        ))}
        {task.estimate_min != null ? (
          left === 0 ? (
            <span className="left-est">{overEst ? `+${fmtMin(completed - (task.estimate_min ?? 0))}` : 'done'}</span>
          ) : (
            <span className="left-est" data-low={lowLeft}>{fmtMin(left ?? 0)} left</span>
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
