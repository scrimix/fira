import { useEffect, useRef, useState } from 'react';
import { useFira } from '../store';
import { parseEstimate } from '../time';
import type { UUID } from '../types';

interface DraftSubtask { localId: string; title: string; done: boolean }

interface Props {
  draft: { project_id: UUID | null; section: 'now' | 'later'; assignee_id: UUID | null };
}

export function TaskModalDraft({ draft }: Props) {
  const projects = useFira((s) => s.projects);
  const users = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const closeCreate = useFira((s) => s.closeCreate);
  const addTask = useFira((s) => s.addTask);
  const setTaskDescription = useFira((s) => s.setTaskDescription);
  const setTaskEstimate = useFira((s) => s.setTaskEstimate);
  const addSubtask = useFira((s) => s.addSubtask);

  const [projectId, setProjectId] = useState<UUID | ''>(
    draft.project_id ?? projects[0]?.id ?? ''
  );
  const project = projects.find((p) => p.id === projectId) ?? null;

  const [assigneeId, setAssigneeId] = useState<UUID | ''>(
    draft.assignee_id ?? meId ?? ''
  );
  const [section, setSection] = useState<'now' | 'later'>(draft.section);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [estimateText, setEstimateText] = useState('');
  const [subtasks, setSubtasks] = useState<DraftSubtask[]>([]);

  const sourceLabel = project
    ? (project.source === 'jira' ? 'Jira · new'
       : project.source === 'notion' ? 'Notion · new'
       : 'Local task')
    : 'Local task';

  const estimateMin = parseEstimate(estimateText);
  const estimateInvalid = estimateText.trim() !== '' && estimateMin == null;

  const isValid =
    !!title.trim() &&
    !!projectId &&
    (section === 'later' || !!assigneeId) &&
    !estimateInvalid;

  const submit = () => {
    if (!isValid) return;
    const id = addTask(
      projectId as UUID,
      section,
      title.trim(),
      (assigneeId || null) as UUID | null,
    );
    if (!id) return;
    if (description.trim()) setTaskDescription(id, description);
    if (estimateMin != null && estimateMin > 0) setTaskEstimate(id, estimateMin);
    for (const s of subtasks) {
      const t = s.title.trim();
      if (t) addSubtask(id, t);
    }
    closeCreate();
  };

  return (
    <div className="modal-backdrop" onClick={closeCreate}>
      <div className="modal" onClick={(e) => e.stopPropagation()}
           style={{ ['--proj-color' as string]: project?.color ?? 'var(--ink)' }}>
        <div className="modal-head">
          <span style={{
            width: 10, height: 10,
            background: project?.color ?? 'var(--ink)',
            display: 'inline-block',
          }} />
          <span className="ext">{project?.title ?? 'No project'}</span>
          <span style={{ color: 'var(--ink-4)' }}>/</span>
          <span className="ext">{sourceLabel}</span>
          <span className="grow" />
          <span className="chip" data-tone="now">draft</span>
          <button className="icon-btn" onClick={closeCreate} title="Close (Esc)">×</button>
        </div>
        <div className="modal-body">
          <div className="modal-main">
            <input
              autoFocus
              className="task-title-big task-title-input"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Task title"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); submit(); }
                else if (e.key === 'Escape') closeCreate();
              }}
            />

            <h5 style={modalH5}>Description</h5>
            <textarea
              className="desc-md desc-md-edit"
              value={description}
              onChange={(e) => { setDescription(e.target.value); autosize(e.currentTarget); }}
              placeholder="Add a description…"
            />

            <h5 style={modalH5}>
              Subtasks{subtasks.length > 0 && (
                <> · {subtasks.filter((s) => s.done).length}/{subtasks.length}</>
              )}
            </h5>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {subtasks.map((s) => (
                <DraftSubtaskRow
                  key={s.localId}
                  value={s.title}
                  done={s.done}
                  onToggle={() => setSubtasks((arr) => arr.map((x) =>
                    x.localId === s.localId ? { ...x, done: !x.done } : x
                  ))}
                  onChange={(v) => setSubtasks((arr) => arr.map((x) =>
                    x.localId === s.localId ? { ...x, title: v } : x
                  ))}
                  onDelete={() => setSubtasks((arr) => arr.filter((x) => x.localId !== s.localId))}
                />
              ))}
              <DraftAddSubtask onAdd={(v) => setSubtasks((arr) => [
                ...arr,
                { localId: crypto.randomUUID(), title: v, done: false },
              ])} />
            </div>

            <div className="create-actions">
              <button className="btn create-primary"
                      onClick={submit}
                      disabled={!isValid}
                      title={!isValid && section === 'now' && !assigneeId
                        ? 'Now tasks must have an assignee'
                        : estimateInvalid ? 'Bad estimate'
                        : undefined}>
                Create
              </button>
            </div>
          </div>
          <div className="modal-side">
            <Field label="Project" value={
              <select className="side-select" value={projectId}
                      onChange={(e) => setProjectId(e.target.value)}>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.title}</option>
                ))}
              </select>
            } />
            <Field label="Assignee" value={
              <AssigneePicker
                users={users}
                meId={meId}
                value={assigneeId || null}
                allowUnassigned={section === 'later'}
                onChange={(id) => setAssigneeId(id ?? '')}
              />
            } />
            <Field label="Status" mono value="todo" />
            <Field label="Estimate" value={
              <input
                className="side-input"
                value={estimateText}
                onChange={(e) => setEstimateText(e.target.value)}
                placeholder="1h"
                data-bad={estimateInvalid || undefined}
              />
            } />
            <Field label="Source" mono value={sourceLabel} />
            <Field label="Section" value={
              <div className="create-seg">
                <button data-active={section === 'now'} onClick={() => setSection('now')}>Now</button>
                <button data-active={section === 'later'} onClick={() => setSection('later')}>Later</button>
              </div>
            } />
          </div>
        </div>
      </div>
    </div>
  );
}

const modalH5: React.CSSProperties = {
  margin: '18px 0 4px',
  fontFamily: 'var(--font-mono)',
  fontSize: 10,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
  color: 'var(--ink-3)',
  fontWeight: 500,
};

function autosize(ta: HTMLTextAreaElement) {
  ta.style.height = 'auto';
  ta.style.height = `${ta.scrollHeight}px`;
}

function DraftSubtaskRow({ value, done, onToggle, onChange, onDelete }: {
  value: string;
  done: boolean;
  onToggle: () => void;
  onChange: (v: string) => void;
  onDelete: () => void;
}) {
  return (
    <div className="subtask subtask-edit" data-done={done}>
      <span className="sc" onClick={onToggle}>{done ? '✓' : ''}</span>
      <input
        className="subtask-edit-input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Backspace' && !value) { e.preventDefault(); onDelete(); }
        }}
      />
      <button className="subtask-del" onClick={onDelete} title="Remove">×</button>
    </div>
  );
}

function DraftAddSubtask({ onAdd }: { onAdd: (v: string) => void }) {
  const [v, setV] = useState('');
  const ref = useRef<HTMLInputElement>(null);
  return (
    <div className="subtask-add" data-editing="true"
         onClick={() => ref.current?.focus()}>
      <span style={{ width: 11, textAlign: 'center', color: 'var(--ink-4)' }}>+</span>
      <input
        ref={ref}
        className="subtask-add-input"
        value={v}
        onChange={(e) => setV(e.target.value)}
        placeholder="Add subtask…"
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            const t = v.trim();
            if (t) { onAdd(t); setV(''); }
          }
        }}
      />
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

function AssigneePicker({ users, meId, value, allowUnassigned, onChange }: {
  users: { id: UUID; name: string; initials: string; email: string }[];
  meId: UUID | null;
  value: UUID | null;
  allowUnassigned: boolean;
  onChange: (id: UUID | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const selected = users.find((u) => u.id === value) ?? null;
  const q = query.trim().toLowerCase();
  const filtered = users.filter((u) =>
    !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q)
  );

  useEffect(() => {
    if (!allowUnassigned && value == null && meId) onChange(meId);
  }, [allowUnassigned, value, meId, onChange]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => { setActiveIdx(0); }, [query]);

  const pick = (id: UUID | null) => { onChange(id); setOpen(false); };

  return (
    <div className="assignee-picker" ref={wrapRef}>
      <button className="assignee-trigger" onClick={() => setOpen((v) => !v)}>
        {selected ? (
          <>
            <div className="avatar" data-me={selected.id === meId}>{selected.initials}</div>
            <span className="ap-name">{selected.name}{selected.id === meId ? ' (you)' : ''}</span>
          </>
        ) : (
          <span className="ap-empty">Unassigned</span>
        )}
        <span className="ap-caret">▾</span>
      </button>
      {open && (
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
                setActiveIdx((i) => Math.min(filtered.length - 1, i + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIdx((i) => Math.max(0, i - 1));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                const u = filtered[activeIdx];
                if (u) pick(u.id);
              } else if (e.key === 'Escape') setOpen(false);
            }}
          />
          <div className="user-list">
            {allowUnassigned && (
              <button className="user-row"
                      onClick={() => pick(null)}>
                <span className="avatar">—</span>
                <span className="user-row-name">Unassigned</span>
                <span />
              </button>
            )}
            {filtered.length === 0 ? (
              <div className="user-empty">No matches.</div>
            ) : filtered.map((u, i) => (
              <button key={u.id} className="user-row"
                      data-active={i === activeIdx}
                      data-selected={u.id === value}
                      onMouseEnter={() => setActiveIdx(i)}
                      onClick={() => pick(u.id)}>
                <span className="avatar" data-me={u.id === meId}>{u.initials}</span>
                <span className="user-row-name">
                  {u.name}{u.id === meId && <span className="user-row-you"> (you)</span>}
                </span>
                <span className="user-row-email">{u.email}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
