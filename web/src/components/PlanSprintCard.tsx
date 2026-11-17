import { useEffect, useRef, useState } from 'react';
import { Check, Plus } from 'lucide-react';
import type { PlanSprint, PlanTask } from '../plan';
import type { UUID } from '../types';

export const PLAN_TASK_MIME = 'application/x-fira-plan-task';

interface Props {
  sprint: PlanSprint;
  showTasks: boolean;
  /// Every mutation arrives as an optional callback. Replay mode passes
  /// `undefined` and each affordance renders only when its callback
  /// exists, so a forgotten `if (readOnly)` *cannot* write — there's no
  /// function to call. Same pattern MonthGrid uses for `onPick`.
  onTick?: (taskId: UUID, done: boolean) => void;
  onRemoveTask?: (taskId: UUID) => void;
  onAddTask?: (title: string) => void;
  /// Opens the task modal. A checklist row is a real task, so clicking
  /// it does what clicking a task does everywhere else in the app.
  onOpenTask?: (taskId: UUID) => void;
  /// Drop one checklist row next to another in saved sort-key order,
  /// preserving list section and completion state.
  onReorderTask?: (draggedId: UUID, targetId: UUID, before: boolean) => void;
  onRename?: (title: string) => void;
  onEdit?: () => void;
  onDelete?: () => void;
  /// Tasks of this sprint parked in Later/Someday, and the action that
  /// moves them to Now. The menu item shows only when there are some.
  parkedCount?: number;
  onMoveToNow?: () => void;
  onDropTask?: (taskId: UUID) => void;
  /// Pointer-drag handle for the card's whole position — week span and
  /// track row in one gesture. Deliberately NOT HTML5 DnD: the card is
  /// also a *drop target* for tasks, and a native drag on the same
  /// element swallows the pointer stream so neither works.
  onMovePointerDown?: (e: React.PointerEvent) => void;
  onResizePointerDown?: (e: React.PointerEvent, edge: 'start' | 'end') => void;
  dragging?: boolean;
}

export function PlanSprintCard({
  sprint, showTasks, onTick, onRemoveTask, onAddTask, onOpenTask, onReorderTask,
  onEdit, onDropTask, onMovePointerDown, onResizePointerDown,
  dragging,
}: Props) {
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState('');
  const [over, setOver] = useState(false);
  const [taskDrop, setTaskDrop] = useState<{ id: UUID; before: boolean } | null>(null);
  const taskDropRef = useRef<typeof taskDrop>(null);
  const markTaskDrop = (target: typeof taskDrop) => {
    taskDropRef.current = target;
    setTaskDrop(current => current?.id === target?.id && current?.before === target?.before ? current : target);
  };
  useEffect(() => {
    const clear = () => { markTaskDrop(null); setOver(false); };
    document.addEventListener('dragend', clear);
    document.addEventListener('drop', clear);
    return () => {
      document.removeEventListener('dragend', clear);
      document.removeEventListener('drop', clear);
    };
  }, []);
  const addRef = useRef<HTMLInputElement>(null);

  useEffect(() => { if (adding) addRef.current?.focus(); }, [adding]);

  const commitAdd = () => {
    const t = draft.trim();
    if (t && onAddTask) onAddTask(t);
    setDraft('');
    // Stay open: planning a sprint means typing several in a row.
    addRef.current?.focus();
  };

  // The header is the move handle, so a click only opens the sprint when
  // the pointer didn't travel (a drag ends in a click on the same node).
  const downAt = useRef<{ x: number; y: number } | null>(null);
  const openFromHead = (e: React.MouseEvent) => {
    const d = downAt.current;
    downAt.current = null;
    if (!onEdit || (d && Math.hypot(e.clientX - d.x, e.clientY - d.y) > 4)) return;
    onEdit();
  };

  return (
    <div
      className="plan-card"
      data-done={sprint.allDone || undefined}
      data-dragging={dragging || undefined}
      data-over={over || undefined}
      data-clip-start={sprint.clipStart || undefined}
      data-clip-end={sprint.clipEnd || undefined}
      style={{
        '--track-color': sprint.color,
        gridColumn: `${sprint.startWeek + 1} / ${sprint.endWeek + 1}`,
        gridRow: sprint.lane + 1,
      } as React.CSSProperties}
      onDragOver={(e) => {
        if (!onDropTask || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        setOver(false);
        if (!onDropTask || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
        e.preventDefault();
        const taskId = e.dataTransfer.getData(PLAN_TASK_MIME);
        if (taskId) onDropTask(taskId);
      }}
    >
      {/* Full-height grips at both edges. The old 6px hot zone inside
          the header was effectively undiscoverable. */}
      {onResizePointerDown && (
        <>
          <div className="plan-card-grip" data-edge="start"
               onPointerDown={(e) => onResizePointerDown(e, 'start')} />
          <div className="plan-card-grip" data-edge="end"
               onPointerDown={(e) => onResizePointerDown(e, 'end')} />
        </>
      )}
      <div className="plan-card-head"
           data-openable={onEdit ? true : undefined}
           title={onEdit ? 'Open sprint' : undefined}
           onPointerDown={(e) => { downAt.current = { x: e.clientX, y: e.clientY }; onMovePointerDown?.(e); }}
           onClick={openFromHead}>
        <span className="plan-card-dot" aria-hidden />
        <span className="plan-card-title" title={sprint.title}>{sprint.title}</span>
      </div>

      {showTasks && (
        <ul className="plan-card-tasks"
          onDragOver={(e) => {
            if (!onReorderTask || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
            e.preventDefault();
            e.stopPropagation();
            setOver(false);
            e.dataTransfer.dropEffect = 'move';
            // Resolve one boundary for the whole checklist. The bottom
            // half of a row and the top half of its neighbour share it.
            const source = document.querySelector<HTMLElement>('[data-plan-task-source]');
            const sourceId = source?.dataset.taskId;
            const rows = [...e.currentTarget.querySelectorAll<HTMLElement>('.plan-task')]
              .filter(row => row.dataset.taskId !== sourceId);
            const next = rows.find(row => {
              const rect = row.getBoundingClientRect();
              return e.clientY < rect.top + rect.height / 2;
            });
            const insertion = next ? rows.indexOf(next) : rows.length;
            const sourceIndex = sprint.tasks.findIndex(task => task.id === sourceId);
            const before = !!next;
            const target = next ?? rows[rows.length - 1];
            // Dropping back in the original slot is a no-op, not another
            // apparent position on either side of the dragged row.
            markTaskDrop(!target || (sourceIndex >= 0 && insertion === sourceIndex)
              ? null : { id: target.dataset.taskId!, before });
          }}
          onDragLeave={(e) => {
            if (!e.currentTarget.contains(e.relatedTarget as Node | null)) markTaskDrop(null);
          }}
          onDrop={(e) => {
            if (!onReorderTask || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
            e.preventDefault();
            e.stopPropagation();
            // Commit exactly the boundary that was painted, without
            // reinterpreting the drop event's coordinates or row target.
            const target = taskDropRef.current;
            markTaskDrop(null);
            const draggedId = e.dataTransfer.getData(PLAN_TASK_MIME);
            if (!draggedId) return;
            if (!sprint.tasks.length) { onDropTask?.(draggedId); return; }
            if (!target) return;
            if (!sprint.tasks.some(task => task.id === draggedId)) onDropTask?.(draggedId);
            onReorderTask(draggedId, target.id, target.before);
          }}>
          {sprint.tasks.map((t) => (
            <PlanCardTask
              key={t.id}
              task={t}
              onTick={onTick}
              onRemove={onRemoveTask}
              onOpen={onOpenTask}
              drop={taskDrop?.id === t.id ? (taskDrop.before ? 'before' : 'after') : undefined}
            />
          ))}
          {onAddTask && (
            <li className="plan-card-add">
              {adding ? (
                <input
                  ref={addRef}
                  className="plan-card-add-input"
                  placeholder="Task title"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onBlur={() => { commitAdd(); setAdding(false); }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') { e.preventDefault(); commitAdd(); }
                    if (e.key === 'Escape') { setDraft(''); setAdding(false); }
                  }}
                />
              ) : (
                <button className="plan-card-add-btn" onClick={() => setAdding(true)}>
                  <Plus size={11} strokeWidth={2} /> Add task
                </button>
              )}
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

function PlanCardTask({ task, onTick, onRemove, onOpen, drop }: {
  task: PlanTask;
  onTick?: (taskId: UUID, done: boolean) => void;
  onRemove?: (taskId: UUID) => void;
  onOpen?: (taskId: UUID) => void;
  drop?: 'before' | 'after';
}) {
  return (
    <li
      className="plan-task"
      data-done={task.done || undefined}
      data-task-id={task.id}
      data-section={task.section}
      data-drop={drop}
      // Editable boards only. Dragging to the rail unplans the task;
      // the task modal's Sprint field does the same.
      draggable={onRemove != null}
      onDragStart={(e) => {
        e.currentTarget.dataset.planTaskSource = 'true';
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData(PLAN_TASK_MIME, task.id);
        // Drag image only, as the calendar rail does.
        e.dataTransfer.setData('text/plain', task.title);
      }}
      onDragEnd={(e) => { delete e.currentTarget.dataset.planTaskSource; }}
      onClick={() => onOpen?.(task.id)}
      title={onOpen ? task.title : undefined}
    >
      <button
        className="plan-task-tick"
        disabled={onTick == null}
        aria-label={task.done ? 'Mark not done' : 'Mark done'}
        onClick={(e) => { e.stopPropagation(); onTick?.(task.id, !task.done); }}
      >
        {task.done && <Check size={10} strokeWidth={2.5} />}
      </button>
      <span className="plan-task-title">{task.title}</span>
    </li>
  );
}
