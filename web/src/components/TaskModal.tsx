import { useEffect, useRef, useState } from 'react';
import { Pencil } from 'lucide-react';
import { useFira } from '../store';
import {
  fmtMin, fmtClockShort, parseEstimate,
  taskCompletedMin, taskPlannedMin, taskTimeLeft,
  blockToGrid,
} from '../time';
import type { Status } from '../types';

interface Props { taskId: string }

export function TaskModal({ taskId }: Props) {
  const task = useFira((s) => s.tasks.find((t) => t.id === taskId) ?? null);
  const project = useFira((s) =>
    task ? s.projects.find((p) => p.id === task.project_id) ?? null : null
  );
  const assignee = useFira((s) =>
    task ? s.users.find((u) => u.id === task.assignee_id) ?? null : null
  );
  const blocks = useFira((s) => s.blocks);
  const users = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const close = useFira((s) => s.openTask);
  const tickSubtask = useFira((s) => s.tickSubtask);
  const addSubtask = useFira((s) => s.addSubtask);
  const setSubtaskTitle = useFira((s) => s.setSubtaskTitle);
  const deleteSubtask = useFira((s) => s.deleteSubtask);
  const setTaskDescription = useFira((s) => s.setTaskDescription);
  const setTaskTitle = useFira((s) => s.setTaskTitle);
  const setTaskEstimate = useFira((s) => s.setTaskEstimate);
  const setTaskStatus = useFira((s) => s.setTaskStatus);
  const setTaskExternalId = useFira((s) => s.setTaskExternalId);
  const setTaskExternalUrl = useFira((s) => s.setTaskExternalUrl);

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

  const sourceLabel = task.source === 'jira' ? `Jira · ${task.external_id ?? 'unsynced'}`
    : task.source === 'notion' ? `Notion · ${task.external_id ?? 'unsynced'}`
    : 'Local task';
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
          <span style={{ color: 'var(--ink-4)' }}>/</span>
          <span className="ext">{sourceLabel}</span>
          <span className="grow" />
          <button className="icon-btn" onClick={() => close(null)} title="Close (Esc)">×</button>
        </div>
        <div className="modal-body">
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

            <h5 style={modalH5}>Description</h5>
            <DescriptionEditor
              taskId={task.id}
              value={task.description_md}
              onSave={(v) => setTaskDescription(task.id, v)}
            />

            <h5 style={modalH5}>
              Subtasks{task.subtasks.length > 0 && (
                <> · {task.subtasks.filter((s) => s.done).length}/{task.subtasks.length}</>
              )}
            </h5>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {task.subtasks.map((s) => (
                <SubtaskRow
                  key={s.id}
                  title={s.title}
                  done={s.done}
                  onToggle={() => tickSubtask(task.id, s.id)}
                  onSave={(v) => setSubtaskTitle(task.id, s.id, v)}
                  onDelete={() => deleteSubtask(task.id, s.id)}
                />
              ))}
              <AddSubtaskRow onAdd={(title) => addSubtask(task.id, title)} />
            </div>

            <div style={{ marginTop: 16 }}>
              <h5 style={modalH5}>Time blocks · {taskBlocks.length}</h5>
              {taskBlocks.length === 0 ? (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink-4)', padding: '8px 0' }}>
                  No blocks yet.
                </div>
              ) : taskBlocks.map(({ b, start_min, dur_min }) => {
                const stale = task.status === 'done' && b.state === 'planned';
                const startDate = new Date(b.start_at);
                const dateLabel = `${MONTH_ABBR[startDate.getUTCMonth()]} ${startDate.getUTCDate()}`;
                const u = users.find((x) => x.id === b.user_id);
                return (
                  <div key={b.id} style={blockRow}>
                    <span className="avatar" data-me={b.user_id === meId} title={u?.name ?? '?'}>
                      {u?.initials ?? '?'}
                    </span>
                    <span style={{ color: 'var(--ink-2)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      {dateLabel}
                    </span>
                    <span style={{ color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      {fmtClockShort(start_min)} – {fmtClockShort(start_min + dur_min)}
                    </span>
                    <span style={{ color: 'var(--ink-2)', fontFamily: 'var(--font-mono)', fontSize: 11, textAlign: 'right' }}>
                      {fmtMin(dur_min)}
                    </span>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.08em',
                      textTransform: 'uppercase', textAlign: 'right',
                      display: 'inline-flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end',
                      color: b.state === 'completed' ? 'var(--done)' : b.state === 'planned' ? 'var(--accent)' : 'var(--ink-4)',
                    }}>
                      {stale && (
                        <span title="Task is marked done, but this block is still planned."
                              style={{ color: 'var(--warn)', fontSize: 11 }}>⚠</span>
                      )}
                      {b.state}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="modal-side">
            <Field label="Project" value={
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 10, height: 10, background: project.color, display: 'inline-block' }} />
                {project.title}
              </span>
            } />
            <Field label="Assignee" value={
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {assignee && <div className="avatar">{assignee.initials}</div>}
                {assignee?.name ?? 'Unassigned'}
              </span>
            } />
            <div className="field">
              <h5>Status</h5>
              <StatusEditor
                key={task.id}
                value={task.status}
                onChange={(v) => setTaskStatus(task.id, v)}
              />
            </div>
            <Field label="Priority" mono value={task.priority ?? '—'} />
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
            <Field label="Source" mono value={sourceLabel} />
            <Field label="Section" mono value={task.section} />
          </div>
        </div>
      </div>
    </div>
  );
}

const MONTH_ABBR = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

const modalH5: React.CSSProperties = {
  margin: '18px 0 4px',
  fontFamily: 'var(--font-mono)',
  fontSize: 10,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
  color: 'var(--ink-3)',
  fontWeight: 500,
};
const blockRow: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '20px 50px 1fr 60px 80px',
  gap: 10,
  padding: '4px 0',
  borderBottom: '1px solid var(--rule)',
  alignItems: 'center',
};

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

function SubtaskRow({ title, done, onToggle, onSave, onDelete }: {
  title: string;
  done: boolean;
  onToggle: () => void;
  onSave: (v: string) => void;
  onDelete: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(title);
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

  return (
    <div className="subtask subtask-edit" data-done={done}>
      <span className="sc" onClick={onToggle}>{done ? '✓' : ''}</span>
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
      <button className="subtask-del" onClick={onDelete} title="Remove">×</button>
    </div>
  );
}

function AddSubtaskRow({ onAdd }: { onAdd: (title: string) => void }) {
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
         onClick={() => inputRef.current?.focus()}>
      <span className="sc-spacer">+</span>
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
             fontFamily: 'var(--font-mono)',
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
          <button className="btn" style={{ padding: '2px 8px', fontSize: 11 }} onClick={cancel}>Cancel</button>
          <button className="btn" style={{ padding: '2px 8px', fontSize: 11 }} onClick={commit}>Save</button>
        </div>
      </div>
    );
  }

  if (!label && !url) {
    return (
      <div onClick={() => setEditing(true)}
           style={{ cursor: 'text', color: 'var(--ink-4)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
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
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--ink-2)' }}
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
