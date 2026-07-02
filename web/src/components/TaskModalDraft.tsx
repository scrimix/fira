import { useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { useFira } from '../store';
import { fmtMin, parseEstimate } from '../time';
import { Select } from './Select';
import { SectionEditor, SubtaskList } from './TaskModal';
import type { Section, UUID } from '../types';

interface DraftSubtask { id: string; title: string; done: boolean }

interface Props {
  draft: {
    project_id: UUID | null;
    section: 'now' | 'later';
    assignee_id: UUID | null;
    block?: { start_at: string; end_at: string; user_id: UUID } | null;
  };
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
  const upsertBlock = useFira((s) => s.upsertBlock);

  // No default project: defaulting to the first one made it easy to create
  // a task in the wrong project by tapping through the modal. Caller must
  // explicitly pick — the Create button stays disabled until they do.
  const [projectId, setProjectId] = useState<UUID | ''>(draft.project_id ?? '');
  const project = projects.find((p) => p.id === projectId) ?? null;

  const [assigneeId, setAssigneeId] = useState<UUID | ''>(
    draft.assignee_id ?? meId ?? ''
  );
  const [section, setSection] = useState<Section>(draft.section);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [estimateText, setEstimateText] = useState('');
  const [subtasks, setSubtasks] = useState<DraftSubtask[]>([]);

  const estimateMin = parseEstimate(estimateText);
  const estimateInvalid = estimateText.trim() !== '' && estimateMin == null;

  const isValid =
    !!title.trim() &&
    !!projectId &&
    (section !== 'now' || !!assigneeId) &&
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
    // Drag-to-create flow: the calendar handed us a pending block. Persist
    // it now that the task it points at exists. Cancel path never reaches
    // here, so the block is silently discarded — exactly what we want.
    if (draft.block) {
      upsertBlock({
        id: crypto.randomUUID(),
        task_id: id,
        user_id: draft.block.user_id,
        start_at: draft.block.start_at,
        end_at: draft.block.end_at,
        state: 'planned',
      });
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
          <span className="grow" />
          <span className="chip" data-tone="now">draft</span>
          <button className="icon-btn" onClick={closeCreate} title="Close (Esc)" aria-label="Close">
            <X size={15} strokeWidth={1.75} />
          </button>
        </div>
        <div className="modal-body" data-side="closed">
          <div className="modal-main">
            <input
              autoFocus
              className="task-title-big task-title-input"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Task title"
              type="text"
              autoComplete="one-time-code"
              autoCorrect="off"
              autoCapitalize="sentences"
              spellCheck={false}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); submit(); }
                else if (e.key === 'Escape') closeCreate();
              }}
            />

            <h5 style={modalH5}>Project</h5>
            <Select<string>
              value={projectId}
              onChange={(v) => setProjectId(v)}
              options={projects.map((p) => ({ value: p.id, label: p.title }))}
            />

            <h5 style={modalH5}>Assignee</h5>
            <AssigneePicker
              users={users}
              meId={meId}
              value={assigneeId || null}
              allowUnassigned={section !== 'now'}
              onChange={(id) => setAssigneeId(id ?? '')}
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
            <SubtaskList
              subtasks={subtasks}
              onTick={(sid) => setSubtasks((arr) => arr.map((x) =>
                x.id === sid ? { ...x, done: !x.done } : x
              ))}
              onSetTitle={(sid, v) => setSubtasks((arr) => arr.map((x) =>
                x.id === sid ? { ...x, title: v } : x
              ))}
              onDelete={(sid) => setSubtasks((arr) => arr.filter((x) => x.id !== sid))}
              onReorder={(ids) => setSubtasks((arr) => {
                const byId = new Map(arr.map((x) => [x.id, x]));
                return ids.map((i) => byId.get(i)).filter((x): x is DraftSubtask => !!x);
              })}
              onAdd={(t, afterId) => {
                const id = crypto.randomUUID();
                const item: DraftSubtask = { id, title: t, done: false };
                setSubtasks((arr) => {
                  if (!afterId) return [...arr, item];
                  const idx = arr.findIndex((x) => x.id === afterId);
                  if (idx === -1) return [...arr, item];
                  return [...arr.slice(0, idx + 1), item, ...arr.slice(idx + 1)];
                });
                return id;
              }}
            />

            <h5 style={modalH5}>Estimate</h5>
            <DraftEstimateEditor
              text={estimateText}
              onChange={setEstimateText}
              invalid={estimateInvalid}
            />

            <h5 style={modalH5}>Section</h5>
            <SectionEditor value={section} onChange={setSection} />
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={closeCreate}>Cancel</button>
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
    </div>
  );
}

const modalH5: React.CSSProperties = {
  margin: '18px 0 4px',
  fontFamily: 'var(--font-mono)',
  fontSize: 'calc(10px * var(--fs-scale))',
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
  color: 'var(--ink-3)',
  fontWeight: 500,
};

function autosize(ta: HTMLTextAreaElement) {
  const parent = ta.closest('.modal-main') as HTMLElement | null;
  const prevParentScrollTop = parent?.scrollTop ?? 0;
  const prevTextareaScrollTop = ta.scrollTop;

  ta.style.height = 'auto';
  ta.style.height = `${Math.max(ta.scrollHeight, 96)}px`;

  requestAnimationFrame(() => {
    ta.scrollTop = prevTextareaScrollTop;
    if (parent) parent.scrollTop = prevParentScrollTop;
  });
}

function DraftEstimateEditor({ text, onChange, invalid }: {
  text: string;
  onChange: (v: string) => void;
  invalid: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const ref = useRef<HTMLInputElement>(null);

  useEffect(() => { if (editing) ref.current?.focus(); }, [editing]);

  const parsed = parseEstimate(text);
  // Show the canonical formatted form in read mode so what the user sees
  // matches what gets saved (e.g. "90m" → "1h30").
  const display = parsed != null ? fmtMin(parsed) : '';

  if (!editing) {
    // Set value renders as a tabular mono time (e.g. "1h30"); empty state
    // uses the same sans + ink-4 tone as subtask placeholders so the
    // "Click to set" hint reads as a peer of "Add subtask…".
    return (
      <div onClick={() => setEditing(true)}
           style={display ? {
             cursor: 'text',
             fontFamily: 'var(--font-mono)',
             fontVariantNumeric: 'tabular-nums',
             color: 'var(--ink)',
           } : {
             cursor: 'text',
             fontSize: 'var(--fs-sm)',
             color: 'var(--ink-4)',
           }}>
        {display || 'Click to set'}
      </div>
    );
  }

  return (
    <input
      ref={ref}
      className="side-input"
      value={text}
      onChange={(e) => onChange(e.target.value)}
      onBlur={() => setEditing(false)}
      onKeyDown={(e) => {
        if (e.key === 'Enter') { e.preventDefault(); setEditing(false); }
        else if (e.key === 'Escape') { onChange(''); setEditing(false); }
      }}
      placeholder="e.g. 1h30 or 90m"
      data-bad={invalid || undefined}
    />
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
  // Float the caller to the top of the picker — assigning to yourself is the
  // common case and shouldn't require scrolling past teammates alphabetically.
  const filtered = users
    .filter((u) => !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q))
    .sort((a, b) => {
      if (a.id === meId) return -1;
      if (b.id === meId) return 1;
      return a.name.localeCompare(b.name);
    });

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
