import { useEffect, useMemo, useRef, useState } from 'react';
import { Check, Copy, PanelRightClose, PanelRightOpen, Pencil, Plus, Trash2, X } from 'lucide-react';
import { useFira } from '../store';
import { ConfirmDelete } from './ConfirmDelete';
import {
  fmtMin, fmtClockShort, parseEstimate,
  taskCompletedMin, taskPlannedMin, taskTimeLeft,
  blockToGrid,
} from '../time';
import type { Status, Task, User, UUID } from '../types';

interface Props { taskId: string }

export function TaskModal({ taskId }: Props) {
  const task = useFira((s) => s.tasks.find((t) => t.id === taskId) ?? null);
  const project = useFira((s) =>
    task ? s.projects.find((p) => p.id === task.project_id) ?? null : null
  );
  const blocks = useFira((s) => s.blocks);
  const users = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const close = useFira((s) => s.openTask);
  const tickSubtask = useFira((s) => s.tickSubtask);
  const addSubtask = useFira((s) => s.addSubtask);
  const setSubtaskTitle = useFira((s) => s.setSubtaskTitle);
  const deleteSubtask = useFira((s) => s.deleteSubtask);
  const reorderSubtasks = useFira((s) => s.reorderSubtasks);
  const setTaskDescription = useFira((s) => s.setTaskDescription);
  const setTaskTitle = useFira((s) => s.setTaskTitle);
  const setTaskEstimate = useFira((s) => s.setTaskEstimate);
  const setTaskStatus = useFira((s) => s.setTaskStatus);
  const setTaskExternalId = useFira((s) => s.setTaskExternalId);
  const setTaskExternalUrl = useFira((s) => s.setTaskExternalUrl);
  const setTaskAssignee = useFira((s) => s.setTaskAssignee);
  const deleteTask = useFira((s) => s.deleteTask);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  // Sidebar collapsible — gives the description / subtasks / time-blocks
  // pane the full modal width, which matters most on phones where the
  // 220 px sidebar otherwise eats two-thirds of the viewport. Default
  // closed on narrow viewports, open on desktop.
  const [sideOpen, setSideOpen] = useState(() =>
    typeof window === 'undefined'
      ? true
      : !window.matchMedia('(max-width: 700px)').matches,
  );

  if (!task || !project) return null;

  const completed = taskCompletedMin(task, blocks);
  const planned = taskPlannedMin(task, blocks);
  const left = taskTimeLeft(task, blocks);
  const total = task.estimate_min ?? (completed + planned);
  const compPct = total ? (completed / total) * 100 : 0;
  const planPct = total ? (planned / total) * 100 : 0;

  const taskBlocks = blocks
    .filter((b) => b.task_id === task.id)
    .map((b) => ({ b, ...blockToGrid(b.start_at, b.end_at) }))
    .sort((a, c) => Date.parse(a.b.start_at) - Date.parse(c.b.start_at));

  // Per-task external_url wins over the project's template — it's the
  // escape hatch for trackers (Notion, GitHub, design docs) where there's
  // no stable {key} pattern. Falls back to template-fill of external_id.
  const resolvedUrl: string | null = task.external_url
    ? task.external_url
    : task.external_id && project.external_url_template
      ? (project.external_url_template.includes('{key}')
          ? project.external_url_template.replace('{key}', encodeURIComponent(task.external_id))
          : project.external_url_template + encodeURIComponent(task.external_id))
      : null;

  return (
    <div className="modal-backdrop" onClick={() => close(null)}>
      <div className="modal" onClick={(e) => e.stopPropagation()}
           style={{ ['--proj-color' as string]: project.color }}>
        <div className="modal-head">
          <span style={{ width: 10, height: 10, background: project.color, display: 'inline-block' }} />
          <span className="ext">{project.title}</span>
          <span className="grow" />
          <button
            className="icon-btn modal-head-danger"
            onClick={() => setConfirmingDelete(true)}
            title="Delete task"
          >
            <Trash2 size={15} strokeWidth={1.75} />
          </button>
          <button
            className="icon-btn"
            onClick={() => setSideOpen((v) => !v)}
            title={sideOpen ? 'Hide details' : 'Show details'}
            aria-label={sideOpen ? 'Hide details' : 'Show details'}
            aria-pressed={sideOpen}
          >
            {sideOpen
              ? <PanelRightClose size={15} strokeWidth={1.75} />
              : <PanelRightOpen size={15} strokeWidth={1.75} />}
          </button>
          <button className="icon-btn" onClick={() => close(null)} title="Close (Esc)" aria-label="Close">
            <X size={15} strokeWidth={1.75} />
          </button>
        </div>
        <div className="modal-body" data-side={sideOpen ? 'open' : 'closed'}>
          <div className="modal-main">
            <TitleEditor key={task.id} value={task.title}
                         onSave={(v) => setTaskTitle(task.id, v)} />

            {task.estimate_min != null && (
              <>
                <div className="est-bar">
                  <div className="seg-spent" style={{ width: `${Math.min(100, compPct)}%` }} />
                  <div className="seg-planned" style={{ width: `${Math.min(100 - compPct, planPct)}%` }} />
                </div>
                <div className="est-meta">
                  <span><strong>{fmtMin(completed)}</strong> done</span>
                  <span><strong>{fmtMin(planned)}</strong> planned</span>
                  <span><strong>{fmtMin(Math.max(0, left ?? 0))}</strong> left</span>
                  <span style={{ marginLeft: 'auto' }}>of {fmtMin(task.estimate_min)} estimate</span>
                </div>
              </>
            )}

            <SectionHeading title="Description" trailing={<CopyMarkdownButton task={task} />} />
            <DescriptionEditor
              taskId={task.id}
              value={task.description_md}
              onSave={(v) => setTaskDescription(task.id, v)}
            />

            <SectionHeading
              title="Subtasks"
              hint={task.subtasks.length > 0
                ? `${task.subtasks.filter((s) => s.done).length}/${task.subtasks.length}`
                : undefined}
            />
            <SubtaskList
              task={task}
              tickSubtask={tickSubtask}
              setSubtaskTitle={setSubtaskTitle}
              deleteSubtask={deleteSubtask}
              reorderSubtasks={reorderSubtasks}
              addSubtask={addSubtask}
            />

            <SectionHeading
              title="Time blocks"
              hint={taskBlocks.length > 0 ? String(taskBlocks.length) : undefined}
            />
            {taskBlocks.length === 0 ? (
              <div className="tm-section-empty">No blocks yet.</div>
            ) : taskBlocks.map(({ b, start_min, dur_min }) => {
                const stale = task.status === 'done' && b.state === 'planned';
                const startDate = new Date(b.start_at);
                const dateLabel = `${MONTH_ABBR[startDate.getMonth()]} ${startDate.getDate()}`;
                const u = users.find((x) => x.id === b.user_id);
                return (
                  <div key={b.id} className="tm-block-row" data-state={b.state}>
                    <span className="avatar tm-block-ava" data-me={b.user_id === meId} title={u?.name ?? '?'}>
                      {u?.initials ?? '?'}
                    </span>
                    <span className="tm-block-date">{dateLabel}</span>
                    <span className="tm-block-time">
                      {fmtClockShort(start_min)} – {fmtClockShort(start_min + dur_min)}
                    </span>
                    <span className="tm-block-dur">{fmtMin(dur_min)}</span>
                    <span className="tm-block-state">
                      {stale && (
                        <span className="tm-block-warn" title="Task is marked done, but this block is still planned.">⚠</span>
                      )}
                      {b.state}
                    </span>
                  </div>
                );
              })}
          </div>
          <div className="modal-side">
            <Field label="Project" value={
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 10, height: 10, background: project.color, display: 'inline-block' }} />
                {project.title}
              </span>
            } />
            <div className="field">
              <h5>Assignee</h5>
              <AssigneeEditor
                key={task.id}
                value={task.assignee_id}
                users={users}
                meId={meId}
                onChange={(uid) => setTaskAssignee(task.id, uid)}
              />
            </div>
            <div className="field">
              <h5>Status</h5>
              <StatusEditor
                key={task.id}
                value={task.status}
                onChange={(v) => setTaskStatus(task.id, v)}
              />
            </div>
            <div className="field">
              <h5>Estimate</h5>
              <EstimateEditor
                key={task.id}
                value={task.estimate_min}
                onSave={(v) => setTaskEstimate(task.id, v)}
              />
            </div>
            <Field label="Time left" mono value={left != null ? fmtMin(left) : '—'} />
            <Field label="Tags" value={
              task.tags.length === 0 ? <span style={{ color: 'var(--ink-4)' }}>—</span> :
              <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {task.tags.map((tg) => <span key={tg} className="chip">{tg}</span>)}
              </span>
            } />
            <div className="field">
              <h5>Issue link</h5>
              <ExternalLinkEditor
                key={task.id}
                label={task.external_id}
                url={task.external_url}
                resolvedUrl={resolvedUrl}
                hasTemplate={!!project.external_url_template}
                onSaveLabel={(v) => setTaskExternalId(task.id, v)}
                onSaveUrl={(v) => setTaskExternalUrl(task.id, v)}
              />
            </div>
            <Field label="Section" mono value={task.section} />
          </div>
        </div>
        {confirmingDelete && (
          <ConfirmDelete
            title="Delete task?"
            body={
              <p>
                <strong>{task.title}</strong> and all its subtasks and time blocks will be removed. This can't be undone.
              </p>
            }
            onCancel={() => setConfirmingDelete(false)}
            onConfirm={() => {
              setConfirmingDelete(false);
              deleteTask(task.id);
              close(null);
            }}
          />
        )}
      </div>
    </div>
  );
}

const MONTH_ABBR = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

function SectionHeading({ title, hint, trailing }: {
  title: string;
  hint?: string;
  trailing?: React.ReactNode;
}) {
  return (
    <h5 className="tm-section-h">
      <span className="tm-section-h-title">{title}</span>
      {hint != null && <span className="tm-section-h-hint">· {hint}</span>}
      {trailing != null && <span className="tm-section-h-trailing">{trailing}</span>}
    </h5>
  );
}


function TitleEditor({ value, onSave }: { value: string; onSave: (v: string) => void }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const ref = useRef<HTMLInputElement>(null);

  useEffect(() => { setDraft(value); setEditing(false); }, [value]);
  useEffect(() => { if (editing) ref.current?.focus(); }, [editing]);

  const commit = () => {
    const v = draft.trim();
    if (v && v !== value) onSave(v);
    else setDraft(value);
    setEditing(false);
  };

  if (!editing) {
    return (
      <h2 className="task-title-big" onClick={() => setEditing(true)} style={{ cursor: 'text' }}>
        {value}
      </h2>
    );
  }
  return (
    <input
      ref={ref}
      className="task-title-big task-title-input"
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === 'Enter') { e.preventDefault(); commit(); }
        else if (e.key === 'Escape') { setDraft(value); setEditing(false); }
      }}
    />
  );
}

function DescriptionEditor({ taskId, value, onSave }: {
  taskId: string;
  value: string;
  onSave: (v: string) => void;
}) {
  const ref = useRef<HTMLTextAreaElement>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);

  useEffect(() => {
    setEditing(false);
    setDraft(value);
  }, [taskId, value]);

  useEffect(() => {
    if (editing && ref.current) {
      ref.current.focus();
      const ta = ref.current;
      ta.setSelectionRange(ta.value.length, ta.value.length);
      autosize(ta);
    }
  }, [editing]);

  const commit = () => {
    if (draft !== value) onSave(draft);
    setEditing(false);
  };

  if (!editing) {
    return (
      <div
        className="desc-md"
        onClick={() => setEditing(true)}
        data-empty={!value}
      >
        {value || 'No description. Click to edit.'}
      </div>
    );
  }
  return (
    <textarea
      ref={ref}
      className="desc-md desc-md-edit"
      value={draft}
      onChange={(e) => { setDraft(e.target.value); autosize(e.currentTarget); }}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === 'Escape') { setDraft(value); setEditing(false); }
        if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); commit(); }
      }}
      placeholder="Add a description…"
    />
  );
}

function autosize(ta: HTMLTextAreaElement) {
  ta.style.height = 'auto';
  ta.style.height = `${ta.scrollHeight}px`;
}

// Build a markdown rendering of the task suitable for pasting into Notion,
// Jira (which accepts markdown-ish), Linear, etc. Keeps title + description
// + subtasks because that's the chunk a person typically wants to share —
// not estimates, blocks, or assignee.
function taskToMarkdown(task: Task): string {
  const lines: string[] = [];
  lines.push(`# ${task.title}`);
  if (task.description_md.trim()) {
    lines.push('');
    lines.push(task.description_md.trim());
  }
  if (task.subtasks.length > 0) {
    lines.push('');
    lines.push('## Subtasks');
    for (const s of task.subtasks) {
      lines.push(`- [${s.done ? 'x' : ' '}] ${s.title}`);
    }
  }
  return lines.join('\n');
}

function CopyMarkdownButton({ task }: { task: Task }) {
  const [copied, setCopied] = useState(false);
  const onClick = async () => {
    try {
      await navigator.clipboard.writeText(taskToMarkdown(task));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable (insecure context, permission denied) — fail
      // silently. Could fall back to a hidden textarea + execCommand, but
      // every browser we care about supports the async clipboard on https.
    }
  };
  return (
    <button
      type="button"
      onClick={onClick}
      title={copied ? 'Copied' : 'Copy title, description, and subtasks as markdown'}
      style={{
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        width: 20, height: 20,
        padding: 0,
        color: copied ? 'var(--done)' : 'var(--ink-2)',
        background: 'transparent',
        border: 0,
        cursor: 'pointer',
        transition: 'color 120ms ease',
      }}
    >
      {copied ? <Check size={13} strokeWidth={2} /> : <Copy size={12} strokeWidth={1.5} />}
    </button>
  );
}

function SubtaskList({
  task, tickSubtask, setSubtaskTitle, deleteSubtask, reorderSubtasks, addSubtask,
}: {
  task: Task;
  tickSubtask: (taskId: string, subId: string) => void;
  setSubtaskTitle: (taskId: string, subId: string, v: string) => void;
  deleteSubtask: (taskId: string, subId: string) => void;
  reorderSubtasks: (taskId: string, orderedIds: string[]) => void;
  addSubtask: (taskId: string, title: string) => void;
}) {
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [dropAt, setDropAt] = useState<{ id: string; pos: 'before' | 'after' } | null>(null);

  const reorderTo = (draggedSubId: string, dropAtVal: { id: string; pos: 'before' | 'after' }) => {
    if (!draggedSubId || draggedSubId === dropAtVal.id) return;
    const ids = task.subtasks.map((s) => s.id);
    const from = ids.indexOf(draggedSubId);
    const targetIdx = ids.indexOf(dropAtVal.id);
    if (from === -1 || targetIdx === -1) return;
    ids.splice(from, 1);
    let insertAt = targetIdx;
    if (from < targetIdx) insertAt -= 1;
    if (dropAtVal.pos === 'after') insertAt += 1;
    ids.splice(insertAt, 0, draggedSubId);
    reorderSubtasks(task.id, ids);
  };

  const commitReorder = () => {
    if (draggedId && dropAt) reorderTo(draggedId, dropAt);
    setDraggedId(null);
    setDropAt(null);
  };

  // Touch-only pointer-events flow on the grip — same shape as the
  // inbox task-grip drag. setPointerCapture so subsequent moves come
  // back to the grip even when the finger leaves the row.
  const touchDraggedRef = useRef<string | null>(null);
  const touchDropAtRef = useRef<{ id: string; pos: 'before' | 'after' } | null>(null);
  const onGripTouchStart = (subId: string) => {
    touchDraggedRef.current = subId;
    touchDropAtRef.current = null;
    setDraggedId(subId);
    setDropAt(null);
  };
  const onGripTouchMove = (clientX: number, clientY: number) => {
    const dragged = touchDraggedRef.current;
    if (!dragged) return;
    const el = document.elementFromPoint(clientX, clientY) as HTMLElement | null;
    const rowEl = el?.closest('[data-subtask-id]') as HTMLElement | null;
    if (rowEl && rowEl.dataset.subtaskId && rowEl.dataset.subtaskId !== dragged) {
      const rect = rowEl.getBoundingClientRect();
      const pos: 'before' | 'after' = clientY < rect.top + rect.height / 2 ? 'before' : 'after';
      const next = { id: rowEl.dataset.subtaskId, pos };
      touchDropAtRef.current = next;
      setDropAt(next);
    }
  };
  const onGripTouchEnd = () => {
    const dragged = touchDraggedRef.current;
    const dropAtVal = touchDropAtRef.current;
    touchDraggedRef.current = null;
    touchDropAtRef.current = null;
    if (dragged && dropAtVal) reorderTo(dragged, dropAtVal);
    setDraggedId(null);
    setDropAt(null);
  };

  return (
    <div className="modal-subtasks">
      {task.subtasks.map((s) => (
        <SubtaskRow
          key={s.id}
          id={s.id}
          title={s.title}
          done={s.done}
          onToggle={() => tickSubtask(task.id, s.id)}
          onSave={(v) => setSubtaskTitle(task.id, s.id, v)}
          onDelete={() => deleteSubtask(task.id, s.id)}
          onDragStart={(id) => setDraggedId(id)}
          onDragOver={(id, pos) => setDropAt((cur) =>
            cur?.id === id && cur.pos === pos ? cur : { id, pos }
          )}
          onDragLeave={() => { /* keep last marker until pointer enters another row */ }}
          onDrop={commitReorder}
          onGripTouchStart={onGripTouchStart}
          onGripTouchMove={onGripTouchMove}
          onGripTouchEnd={onGripTouchEnd}
          dropMark={dropAt?.id === s.id ? dropAt.pos : null}
        />
      ))}
      <AddSubtaskRow
        onAdd={(title) => addSubtask(task.id, title)}
        bare={task.subtasks.length === 0}
      />
    </div>
  );
}

function SubtaskRow({
  id, title, done, onToggle, onSave, onDelete,
  onDragStart, onDragOver, onDragLeave, onDrop,
  onGripTouchStart, onGripTouchMove, onGripTouchEnd,
  dropMark,
}: {
  id: string;
  title: string;
  done: boolean;
  onToggle: () => void;
  onSave: (v: string) => void;
  onDelete: () => void;
  onDragStart: (id: string) => void;
  onDragOver: (id: string, pos: 'before' | 'after') => void;
  onDragLeave: () => void;
  onDrop: () => void;
  onGripTouchStart: (id: string) => void;
  onGripTouchMove: (clientX: number, clientY: number) => void;
  onGripTouchEnd: () => void;
  dropMark: 'before' | 'after' | null;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(title);
  const [dragOnHandle, setDragOnHandle] = useState(false);
  const ref = useRef<HTMLInputElement>(null);

  useEffect(() => { setDraft(title); }, [title]);
  useEffect(() => { if (editing) ref.current?.focus(); }, [editing]);

  const commit = () => {
    const v = draft.trim();
    if (!v) {
      onDelete();
      return;
    }
    if (v !== title) onSave(v);
    setEditing(false);
  };

  // Long-press-to-drag anywhere on the row. Same shape as the inbox
  // version: pointer events drive pre-lock state, but once locked we
  // attach a non-passive document touchmove listener — the only way
  // iOS Safari lets us suppress scroll mid-gesture.
  const rowTouchRef = useRef<{
    startX: number; startY: number;
    timer: number | null;
    locked: boolean;
    suppressClick: boolean;
    cleanup: (() => void) | null;
  } | null>(null);
  const lockRowDrag = () => {
    const t = rowTouchRef.current;
    if (!t) return;
    t.locked = true;
    t.timer = null;
    navigator.vibrate?.(8);
    onGripTouchStart(id);
    const onMove = (ev: TouchEvent) => {
      const touch = ev.touches[0];
      if (!touch) return;
      ev.preventDefault();
      onGripTouchMove(touch.clientX, touch.clientY);
    };
    const onEnd = () => {
      const ref = rowTouchRef.current;
      if (!ref) return;
      ref.cleanup?.();
      ref.cleanup = null;
      onGripTouchEnd();
      ref.suppressClick = true;
      window.setTimeout(() => { rowTouchRef.current = null; }, 50);
    };
    document.addEventListener('touchmove', onMove, { passive: false });
    document.addEventListener('touchend', onEnd);
    document.addEventListener('touchcancel', onEnd);
    t.cleanup = () => {
      document.removeEventListener('touchmove', onMove);
      document.removeEventListener('touchend', onEnd);
      document.removeEventListener('touchcancel', onEnd);
    };
  };
  const onRowPointerDown = (e: React.PointerEvent) => {
    if (e.pointerType !== 'touch') return;
    const targetEl = e.target as HTMLElement;
    if (targetEl.closest('.sc, .subtask-grip, .subtask-del, input')) return;
    if (editing) return;
    rowTouchRef.current = {
      startX: e.clientX, startY: e.clientY,
      timer: null, locked: false, suppressClick: false, cleanup: null,
    };
    rowTouchRef.current.timer = window.setTimeout(lockRowDrag, 220);
  };
  const onRowPointerMove = (e: React.PointerEvent) => {
    if (e.pointerType !== 'touch') return;
    const t = rowTouchRef.current;
    if (!t || t.locked) return;
    const dx = Math.abs(e.clientX - t.startX);
    const dy = Math.abs(e.clientY - t.startY);
    if (dx > 8 || dy > 8) {
      if (t.timer != null) window.clearTimeout(t.timer);
      rowTouchRef.current = null;
    }
  };
  const finishRowTouch = () => {
    const t = rowTouchRef.current;
    if (!t) return;
    if (t.timer != null) window.clearTimeout(t.timer);
    if (t.locked) return;
    t.cleanup?.();
    rowTouchRef.current = null;
  };

  return (
    <div
      className="subtask subtask-edit"
      data-done={done}
      data-drop-mark={dropMark ?? undefined}
      data-subtask-id={id}
      draggable={dragOnHandle}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', id);
        onDragStart(id);
      }}
      onDragEnd={() => setDragOnHandle(false)}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes('text/plain')) return;
        e.preventDefault();
        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
        const pos: 'before' | 'after' = e.clientY < rect.top + rect.height / 2 ? 'before' : 'after';
        onDragOver(id, pos);
      }}
      onDragLeave={onDragLeave}
      onDrop={(e) => { e.preventDefault(); onDrop(); }}
      onPointerDown={onRowPointerDown}
      onPointerMove={onRowPointerMove}
      onPointerUp={(e) => { if (e.pointerType === 'touch') finishRowTouch(); }}
      onPointerCancel={(e) => { if (e.pointerType === 'touch') finishRowTouch(); }}
      onClickCapture={(e) => {
        // After a drag, suppress the click that would otherwise switch
        // the row into edit mode via .sname's onClick.
        if (rowTouchRef.current?.suppressClick) {
          e.stopPropagation();
          e.preventDefault();
        }
      }}
    >
      <span
        className="subtask-grip"
        title="Drag to reorder"
        onMouseDown={() => setDragOnHandle(true)}
        onMouseUp={() => setDragOnHandle(false)}
        onPointerDown={(e) => {
          if (e.pointerType !== 'touch') return;
          e.preventDefault();
          e.stopPropagation();
          e.currentTarget.setPointerCapture(e.pointerId);
          onGripTouchStart(id);
        }}
        onPointerMove={(e) => {
          if (e.pointerType !== 'touch') return;
          onGripTouchMove(e.clientX, e.clientY);
        }}
        onPointerUp={(e) => {
          if (e.pointerType !== 'touch') return;
          onGripTouchEnd();
        }}
        onPointerCancel={(e) => {
          if (e.pointerType !== 'touch') return;
          onGripTouchEnd();
        }}
      >::</span>
      <span className="sc" onClick={onToggle} aria-label={done ? 'Mark not done' : 'Mark done'}>
        {done && <Check size={11} strokeWidth={3} />}
      </span>
      {editing ? (
        <input
          ref={ref}
          className="subtask-edit-input"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
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
      <button className="subtask-del" onClick={onDelete} title="Remove">
        <X size={14} strokeWidth={1.75} />
      </button>
    </div>
  );
}

function AddSubtaskRow({ onAdd, bare }: { onAdd: (title: string) => void; bare: boolean }) {
  const [value, setValue] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const commit = () => {
    const v = value.trim();
    if (v) onAdd(v);
    setValue('');
    inputRef.current?.focus();
  };

  return (
    <div className="subtask-add" data-editing="true" data-bare={bare || undefined}
         onClick={() => inputRef.current?.focus()}>
      {!bare && (
        <>
          <span className="grip-spacer" aria-hidden="true" />
          <span className="sc-spacer" aria-hidden="true">
            <Plus size={11} strokeWidth={2} />
          </span>
        </>
      )}
      <input
        ref={inputRef}
        className="subtask-add-input"
        value={value}
        onChange={(e) => setValue(e.target.value)}
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

function EstimateEditor({ value, onSave }: {
  value: number | null;
  onSave: (v: number | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(value != null ? fmtMin(value) : '');
  const ref = useRef<HTMLInputElement>(null);

  useEffect(() => { setText(value != null ? fmtMin(value) : ''); }, [value]);
  useEffect(() => { if (editing) ref.current?.focus(); }, [editing]);

  const commit = () => {
    if (text.trim() === '') {
      if (value != null) onSave(null);
    } else {
      const parsed = parseEstimate(text);
      if (parsed != null && parsed !== value) onSave(parsed);
      else if (parsed == null) setText(value != null ? fmtMin(value) : '');
    }
    setEditing(false);
  };

  if (!editing) {
    return (
      <div onClick={() => setEditing(true)}
           style={{
             cursor: 'text',
             fontFamily: 'var(--font-sans)',
             fontSize: 'var(--fs-sm)',
             fontVariantNumeric: 'tabular-nums',
             color: value != null ? 'var(--ink)' : 'var(--ink-4)',
           }}>
        {value != null ? fmtMin(value) : 'Click to set'}
      </div>
    );
  }

  return (
    <input
      ref={ref}
      className="side-input"
      value={text}
      onChange={(e) => setText(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === 'Enter') { e.preventDefault(); commit(); }
        else if (e.key === 'Escape') {
          setText(value != null ? fmtMin(value) : '');
          setEditing(false);
        }
      }}
      placeholder="e.g. 1h30 or 90m"
    />
  );
}

const STATUS_OPTIONS: Array<{ id: Status; label: string; tone: string }> = [
  { id: 'backlog', label: 'backlog', tone: 'backlog' },
  { id: 'todo', label: 'todo', tone: 'todo' },
  { id: 'in_progress', label: 'in progress', tone: 'now' },
  { id: 'done', label: 'done', tone: 'done' },
];

function StatusEditor({ value, onChange }: {
  value: Status;
  onChange: (v: Status) => void;
}) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const current = STATUS_OPTIONS.find((o) => o.id === value) ?? STATUS_OPTIONS[1];

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="status-editor" ref={wrapRef}>
      <button className="status-trigger"
              data-tone={current.tone}
              onClick={() => setOpen((v) => !v)}>
        {current.label}
      </button>
      {open && (
        <div className="status-popover">
          {STATUS_OPTIONS.map((o) => (
            <button key={o.id}
                    className="status-option"
                    data-tone={o.tone}
                    data-selected={o.id === value}
                    onClick={() => { onChange(o.id); setOpen(false); }}>
              {o.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ExternalLinkEditor({ label, url, resolvedUrl, hasTemplate, onSaveLabel, onSaveUrl }: {
  label: string | null;
  url: string | null;
  resolvedUrl: string | null;
  hasTemplate: boolean;
  onSaveLabel: (v: string | null) => void;
  onSaveUrl: (v: string | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [labelDraft, setLabelDraft] = useState(label ?? '');
  const [urlDraft, setUrlDraft] = useState(url ?? '');
  const labelRef = useRef<HTMLInputElement>(null);

  useEffect(() => { setLabelDraft(label ?? ''); }, [label]);
  useEffect(() => { setUrlDraft(url ?? ''); }, [url]);
  useEffect(() => { if (editing) labelRef.current?.focus(); }, [editing]);

  const commit = () => {
    const nextLabel = labelDraft.trim() === '' ? null : labelDraft.trim();
    const nextUrl = urlDraft.trim() === '' ? null : urlDraft.trim();
    if (nextLabel !== label) onSaveLabel(nextLabel);
    if (nextUrl !== url) onSaveUrl(nextUrl);
    setEditing(false);
  };
  const cancel = () => {
    setLabelDraft(label ?? '');
    setUrlDraft(url ?? '');
    setEditing(false);
  };

  if (editing) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <input
          ref={labelRef}
          className="side-input"
          value={labelDraft}
          onChange={(e) => setLabelDraft(e.target.value)}
          placeholder={hasTemplate ? 'Label (e.g. BDS-345)' : 'Label (e.g. Design doc)'}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); commit(); }
            else if (e.key === 'Escape') cancel();
          }}
        />
        <input
          className="side-input"
          value={urlDraft}
          onChange={(e) => setUrlDraft(e.target.value)}
          placeholder={hasTemplate ? 'URL (overrides template)' : 'URL (https://…)'}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); commit(); }
            else if (e.key === 'Escape') cancel();
          }}
        />
        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
          <button className="btn" style={{ padding: '2px 8px', fontSize: 'calc(11px * var(--fs-scale))' }} onClick={cancel}>Cancel</button>
          <button className="btn" style={{ padding: '2px 8px', fontSize: 'calc(11px * var(--fs-scale))' }} onClick={commit}>Save</button>
        </div>
      </div>
    );
  }

  if (!label && !url) {
    return (
      <div onClick={() => setEditing(true)}
           style={{ cursor: 'text', color: 'var(--ink-4)', fontFamily: 'var(--font-mono)', fontSize: 'calc(12px * var(--fs-scale))' }}>
        Click to add a link
      </div>
    );
  }

  // Display: prefer label if set, otherwise the URL itself.
  const display = label ? `[${label}]` : url!;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      {resolvedUrl ? (
        <a href={resolvedUrl} target="_blank" rel="noopener noreferrer"
           onClick={(e) => e.stopPropagation()}
           className="ext-link"
           title={resolvedUrl}>
          {display}
        </a>
      ) : (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'calc(12px * var(--fs-scale))', color: 'var(--ink-2)' }}
              title="No URL — add one here or set a template on the project.">
          {display}
        </span>
      )}
      <button className="icon-btn" onClick={() => setEditing(true)} title="Edit">
        <Pencil size={12} strokeWidth={1.75} />
      </button>
    </div>
  );
}

// Click-to-edit assignee picker — same affordance pattern as
// ExternalLinkEditor: read-only display with a pencil affordance,
// click pencil to open a searchable popover. Pressing Esc or clicking
// outside cancels; picking a row commits.
function AssigneeEditor({ value, users, meId, onChange }: {
  value: UUID | null;
  users: User[];
  meId: UUID | null;
  onChange: (id: UUID | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const selected = users.find((u) => u.id === value) ?? null;

  // Float me to the top — assigning to yourself is the common case.
  const sorted = useMemo(() => {
    const q = query.trim().toLowerCase();
    return users
      .filter((u) => !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q))
      .sort((a, b) => {
        if (a.id === meId) return -1;
        if (b.id === meId) return 1;
        return a.name.localeCompare(b.name);
      });
  }, [users, query, meId]);

  useEffect(() => {
    if (!editing) return;
    setQuery('');
    setActiveIdx(0);
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [editing]);

  useEffect(() => { setActiveIdx(0); }, [query]);

  useEffect(() => {
    if (!editing) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setEditing(false);
      }
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setEditing(false); };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [editing]);

  const pick = (id: UUID | null) => {
    if (id !== value) onChange(id);
    setEditing(false);
  };

  if (editing) {
    return (
      <div className="assignee-picker" ref={wrapRef}>
        <div className="user-popover assignee-popover">
          <input
            ref={inputRef}
            className="user-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search people…"
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveIdx((i) => Math.min(sorted.length - 1, i + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIdx((i) => Math.max(0, i - 1));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                const u = sorted[activeIdx];
                if (u) pick(u.id);
              }
            }}
          />
          <div className="user-list">
            <button
              className="user-row"
              data-active={activeIdx === -1}
              onClick={() => pick(null)}
            >
              <div className="avatar" data-empty="true">·</div>
              <span className="user-row-name">Unassigned</span>
            </button>
            {sorted.map((u, i) => (
              <button
                key={u.id}
                className="user-row"
                data-active={i === activeIdx}
                onClick={() => pick(u.id)}
              >
                <div className="avatar" data-me={u.id === meId}>{u.initials}</div>
                <span className="user-row-name">{u.name}{u.id === meId ? ' (you)' : ''}</span>
                <span className="user-row-email">{u.email}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {selected
          ? <>
              <div className="avatar" data-me={selected.id === meId}>{selected.initials}</div>
              <span>{selected.name}{selected.id === meId ? ' (you)' : ''}</span>
            </>
          : <span style={{ color: 'var(--ink-4)' }}>Unassigned</span>}
      </span>
      <button className="icon-btn" onClick={() => setEditing(true)} title="Change assignee">
        <Pencil size={12} strokeWidth={1.75} />
      </button>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="field">
      <h5>{label}</h5>
      <div style={{
        fontSize: 'var(--fs-md)',
        color: 'var(--ink)',
        fontFamily: mono ? 'var(--font-mono)' : 'inherit',
        fontVariantNumeric: mono ? 'tabular-nums' : 'normal',
      }}>{value}</div>
    </div>
  );
}

