import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Check, MoreVertical, Pencil, Plus, Terminal, Trash2 } from 'lucide-react';
import type { PlanSprint, PlanTask } from '../plan';
import type { UUID } from '../types';
import { createPortal } from 'react-dom';
import { fmtMin } from '../time';
import { ClickTooltip } from './ClickTooltip';

const outsideDate = (ms: number) => new Date(ms).toLocaleString(undefined, {
  day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});

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
  onRename, onEdit, onDelete, onDropTask, onMovePointerDown, onResizePointerDown,
  dragging,
}: Props) {
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState('');
  const [renaming, setRenaming] = useState(false);
  const [titleDraft, setTitleDraft] = useState(sprint.title);
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
  const [menuRect, setMenuRect] = useState<DOMRect | null>(null);
  const menuButton = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!menuRect) return;
    menuRef.current?.querySelector('button')?.focus({ preventScroll: true });
    const outside = (event: Event) => {
      const target = event.target as Node;
      if (!menuRef.current?.contains(target) && !menuButton.current?.contains(target)) setMenuRect(null);
    };
    const close = () => setMenuRect(null);
    document.addEventListener('pointerdown', outside);
    // Safari can blur a tapped button before click without focusing a
    // replacement. Close on a real focus destination outside the menu.
    document.addEventListener('focusin', outside);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => {
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('focusin', outside);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
    };
  }, [menuRect]);
  useEffect(() => { if (!onRename && !onDelete) setMenuRect(null); }, [onRename, onDelete]);
  const info = sprint.information;
  const information = !info ? 'Task estimates and time blocks are unavailable in historical snapshots.' : [
    `Load: ${fmtMin(Math.round(info.estimatedMinutes))} estimated / ${fmtMin(info.capacityMinutes)} capacity (${Math.round(info.estimatedMinutes / info.capacityMinutes * 100)}%)`,
    'Capacity: 40 hours per week, for the full sprint.',
    ...(info.missingEstimates ? [`${info.missingEstimates} task${info.missingEstimates === 1 ? '' : 's'} without estimates.`] : []),
    ...(info.hasPrivateTime ? ['Private time excluded; full sprint time is unavailable.'] : []),
    ...(info.outsideBlocks ? [
      `${info.ownTimeOnly ? 'Visible time: ' : ''}${info.outsideBlocks} block${info.outsideBlocks === 1 ? '' : 's'} outside the sprint across ${info.outsideTasks} task${info.outsideTasks === 1 ? '' : 's'}.`,
      `Logged ${info.ownTimeOnly ? 'visible time ' : ''}outside: ${fmtMin(Math.round(info.loggedOutsideMinutes))}. Scheduled ${info.ownTimeOnly ? 'visible time ' : ''}outside: ${fmtMin(Math.round(info.plannedOutsideMinutes))}.`,
    ] : [info.ownTimeOnly ? 'No visible time blocks outside the sprint.' : 'No time blocks outside the sprint.']),
  ].join('\n');
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
        {<button ref={menuButton} type="button"
          className="plan-card-btn plan-sprint-menu-button" aria-label="Sprint actions" title="Sprint actions"
          aria-haspopup="menu" aria-expanded={!!menuRect}
          onPointerDown={(e) => e.stopPropagation()}
          onClick={() => setMenuRect(menuRect ? null : menuButton.current!.getBoundingClientRect())}>
          <MoreVertical size={13} strokeWidth={1.75} />
        </button>}
        <ClickTooltip className="plan-sprint-info" warning={!!info?.outsideBlocks || !!info?.hasPrivateTime}
          label="Sprint information" trigger="?">
          <div>{information}</div>
          {!!info?.outsidePortions.length && <div className="plan-sprint-outside-list"
            tabIndex={0} role="region" aria-label="Time outside sprint">
          {(['before', 'after'] as const).map(side => {
            const portions = info?.outsidePortions.filter(portion => portion.side === side) ?? [];
            return portions.length > 0 && <section className="plan-sprint-outside" key={side}>
              <strong>{side === 'before' ? 'Before sprint' : 'After sprint'}</strong>
              <ul>{portions.map((portion, index) => <li key={`${portion.blockId}-${index}`}>
                <span className="plan-sprint-outside-task">{portion.taskTitle}</span>
                <span>{portion.state === 'completed' ? 'Logged' : 'Scheduled'} · {fmtMin(Math.round((portion.to - portion.from) / 60_000))}</span>
                <span>{outsideDate(portion.from)} – {outsideDate(portion.to)}</span>
              </li>)}</ul>
            </section>;
          })}
          </div>}
        </ClickTooltip>
      </div>

      {menuRect && createPortal(<div ref={menuRef}
        className="plan-sprint-menu" role="menu" aria-label="Sprint actions"
        style={{ left: Math.max(8, Math.min(menuRect.right - 168, window.innerWidth - 176)),
          top: menuRect.bottom + 104 < window.innerHeight ? menuRect.bottom + 4 : Math.max(8, menuRect.top - 104) }}
        onPointerDown={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === 'Escape') { e.stopPropagation(); setMenuRect(null); menuButton.current?.focus(); }
          if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault(); e.stopPropagation();
            const items = [...e.currentTarget.querySelectorAll<HTMLButtonElement>('button')];
            const index = items.indexOf(document.activeElement as HTMLButtonElement);
            items[(index + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length]?.focus();
          }
        }}>
        {onEdit && <button role="menuitem" onClick={() => { setMenuRect(null); onEdit(); }}>
          <Pencil size={12} /> Edit sprint
        </button>}
        {!onEdit && onRename && <button role="menuitem" onClick={() => { setMenuRect(null); setRenaming(true); }}>
          <Pencil size={12} /> Rename sprint
        </button>}
        {/* The sprint id has no other place in the UI; task-cli needs
            it to bring the sprint into a repository. */}
        <button role="menuitem" onClick={() => {
          setMenuRect(null);
          void navigator.clipboard?.writeText(`task-cli import fira ${sprint.id}`);
        }}>
          <Terminal size={12} /> Copy import command
        </button>
        {onDelete && <button role="menuitem" className="plan-sprint-menu-delete"
          onClick={() => { setMenuRect(null); onDelete(); }}><Trash2 size={12} /> Delete sprint</button>}
      </div>, document.body)}

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
