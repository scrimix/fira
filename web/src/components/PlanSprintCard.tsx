import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Check, Pencil, Plus, Trash2 } from 'lucide-react';
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
  /// Drop one checklist row next to another. Ordering is `sort_key`,
  /// which is section-scoped, so the board hands this straight to the
  /// same `reorderTasks` the list drives.
  onReorderTask?: (draggedId: UUID, targetId: UUID, before: boolean) => void;
  onRename?: (title: string) => void;
  onDelete?: () => void;
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
  onRename, onDelete, onDropTask, onMovePointerDown, onResizePointerDown,
  dragging,
}: Props) {
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState('');
  const [renaming, setRenaming] = useState(false);
  const [titleDraft, setTitleDraft] = useState(sprint.title);
  const [over, setOver] = useState(false);
  const addRef = useRef<HTMLInputElement>(null);
  const renameRef = useRef<HTMLInputElement>(null);

  useEffect(() => { if (adding) addRef.current?.focus(); }, [adding]);
  useEffect(() => { if (renaming) renameRef.current?.focus(); }, [renaming]);
  useEffect(() => { setTitleDraft(sprint.title); }, [sprint.title]);

  const commitAdd = () => {
    const t = draft.trim();
    if (t && onAddTask) onAddTask(t);
    setDraft('');
    // Stay open: planning a sprint means typing several in a row.
    addRef.current?.focus();
  };

  const commitRename = () => {
    const t = titleDraft.trim();
    setRenaming(false);
    if (t && t !== sprint.title && onRename) onRename(t);
    else setTitleDraft(sprint.title);
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
      <div className="plan-card-head" onPointerDown={onMovePointerDown}>
        <span className="plan-badge">{sprint.code}</span>
        {renaming ? (
          <input
            ref={renameRef}
            className="plan-card-title-input"
            value={titleDraft}
            onChange={(e) => setTitleDraft(e.target.value)}
            onBlur={commitRename}
            onPointerDown={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === 'Enter') commitRename();
              if (e.key === 'Escape') { setTitleDraft(sprint.title); setRenaming(false); }
            }}
          />
        ) : (
          // Plain text, not a button. The header is the move handle and
          // the title fills most of it, so anything click-to-edit here
          // fights the drag: either the title swallows pointerdown and
          // the card won't move from the place everyone grabs it, or it
          // doesn't and every short drag ends in an edit box. Renaming
          // gets its own target instead.
          <span className="plan-card-title" title={sprint.title}>
            {sprint.title}
          </span>
        )}
        {onRename && !renaming && (
          <button
            className="plan-card-btn"
            title="Rename sprint"
            onPointerDown={(e) => e.stopPropagation()}
            onClick={() => setRenaming(true)}
          >
            <Pencil size={11} strokeWidth={2} />
          </button>
        )}
        {onDelete && (
          <button
            className="plan-card-btn plan-card-del"
            title="Delete sprint"
            onPointerDown={(e) => e.stopPropagation()}
            onClick={onDelete}
          >
            <Trash2 size={11} strokeWidth={1.75} />
          </button>
        )}
      </div>

      {showTasks && (
        <ul className="plan-card-tasks">
          {sprint.tasks.map((t) => (
            <PlanCardTask
              key={t.id}
              task={t}
              onTick={onTick}
              onRemove={onRemoveTask}
              onOpen={onOpenTask}
              onDropAt={onReorderTask && ((draggedId, before) => {
                // Crossing cards is two facts — "it belongs here now" and
                // "it sits here in the order" — so both ops fire, in that
                // order. Adjacent in the outbox, same as the list's
                // set_section + set_assignee pair.
                if (!sprint.tasks.some((x) => x.id === draggedId)) onDropTask?.(draggedId);
                onReorderTask(draggedId, t.id, before);
              })}
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

function PlanCardTask({ task, onTick, onRemove, onOpen, onDropAt }: {
  task: PlanTask;
  onTick?: (taskId: UUID, done: boolean) => void;
  onRemove?: (taskId: UUID) => void;
  onOpen?: (taskId: UUID) => void;
  onDropAt?: (draggedId: UUID, before: boolean) => void;
}) {
  const [at, setAt] = useState<'before' | 'after' | null>(null);
  // Two zones, not the list's three: there is no merge gesture on the
  // board, so the row splits at its midline.
  const sideOf = (e: React.DragEvent) => {
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    return e.clientY - r.top < r.height / 2 ? 'before' : 'after';
  };
  return (
    <li
      className="plan-task"
      data-done={task.done || undefined}
      data-drop={at ?? undefined}
      draggable={onRemove != null}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData(PLAN_TASK_MIME, task.id);
        // Drag image only, as the calendar rail does.
        e.dataTransfer.setData('text/plain', task.title);
      }}
      onDragOver={(e) => {
        if (!onDropAt || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
        e.preventDefault();
        // The card behind this row is also a drop target; without this
        // the drop would land as a plain "join this sprint" and the
        // position the user aimed at would be discarded.
        e.stopPropagation();
        e.dataTransfer.dropEffect = 'move';
        const side = sideOf(e);
        setAt((cur) => cur === side ? cur : side);
      }}
      onDragLeave={() => setAt(null)}
      onDrop={(e) => {
        setAt(null);
        if (!onDropAt || !e.dataTransfer.types.includes(PLAN_TASK_MIME)) return;
        e.preventDefault();
        e.stopPropagation();
        const draggedId = e.dataTransfer.getData(PLAN_TASK_MIME);
        if (draggedId) onDropAt(draggedId, sideOf(e) === 'before');
      }}
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
      {/* An arrow back toward the rail, not a cross. This does not
          delete anything — it clears `sprint_id`, the task returns to
          the rail on the left, and dragging it back undoes it. A cross
          means "destroy" everywhere else in the app, which is exactly
          the gesture the board deliberately does NOT offer; task
          deletion stays in the task modal behind its own confirm. */}
      {onRemove && (
        <button
          className="plan-task-x"
          title="Unplan — move back to the rail"
          onClick={(e) => { e.stopPropagation(); onRemove(task.id); }}
        >
          <ArrowLeft size={11} strokeWidth={2} />
        </button>
      )}
    </li>
  );
}
