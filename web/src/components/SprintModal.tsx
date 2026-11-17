import { useEffect, useRef, useState } from 'react';
import type { Sprint, UUID } from '../types';
import type { PlanSprint } from '../plan';
import { useFira } from '../store';
import { Select } from './Select';
import { TagEditor } from './TaskModal';
import { AlertTriangle, Check, ChevronRight, Play, Terminal, Trash2, X } from 'lucide-react';
import { fmtMin } from '../time';
import { parseDateKey } from '../time';

// Sprint details. Everything a sprint card used to tuck into its menu and
// info tooltip lives here: dates and load, time logged outside the span,
// "move to Now", the CLI import command and delete.
export function SprintModal({ sprint, plan, trackTitle, parkedCount = 0, onMoveToNow, onDelete, onClose }: {
  sprint: Sprint;
  /// Board snapshot of this sprint (load / outside-time information).
  plan?: PlanSprint | null;
  trackTitle?: string | null;
  parkedCount?: number;
  onMoveToNow?: () => void;
  onDelete?: () => void;
  onClose: () => void;
}) {
  const [title, setTitle] = useState(sprint.title);
  const [description, setDescription] = useState(sprint.description_md ?? '');
  const [assignee, setAssignee] = useState<UUID | null>(sprint.default_assignee_id ?? null);
  const [tagIds, setTagIds] = useState(sprint.default_tag_ids ?? []);
  const [copied, setCopied] = useState(false);
  const project = useFira(s => s.projects.find(p => p.id === sprint.project_id));
  const users = useFira(s => s.users);
  const tags = useFira(s => s.tags);
  const setTitleOnSprint = useFira(s => s.setSprintTitle);
  const setDescriptionOnSprint = useFira(s => s.setSprintDescription);
  const setDefaults = useFira(s => s.setSprintDefaults);
  const downOnBackdrop = useRef(false);
  useEffect(() => {
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !document.querySelector('.select-menu, .tag-editor-popover')) onClose();
    };
    document.addEventListener('keydown', escape);
    return () => document.removeEventListener('keydown', escape);
  }, [onClose]);
  const eligible = users.filter(u => project?.members.some(m => m.user_id === u.id && m.role !== 'inactive'));
  const save = () => {
    const name = title.trim();
    if (!name) return;
    if (name !== sprint.title) setTitleOnSprint(sprint.id, name);
    const desc = description.trim();
    if (desc !== (sprint.description_md ?? '').trim()) setDescriptionOnSprint(sprint.id, desc);
    const validTags = tagIds.filter(id => tags.some(t => t.id === id && t.project_id === sprint.project_id));
    if (assignee !== (sprint.default_assignee_id ?? null) ||
      [...validTags].sort().join() !== [...(sprint.default_tag_ids ?? [])].sort().join()) {
      setDefaults(sprint.id, assignee, validTags);
    }
    onClose();
  };
  const copyImport = () => {
    void navigator.clipboard?.writeText(`task-cli import fira ${sprint.id}`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  const info = plan?.information ?? null;
  const loadPct = info && info.capacityMinutes > 0
    ? Math.round(info.estimatedMinutes / info.capacityMinutes * 100) : null;
  const dateRange = (() => {
    if (!sprint.starts_on) return 'No dates';
    const fmt = (ms: number) => new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    if (!sprint.ends_on) return `From ${fmt(parseDateKey(sprint.starts_on))}`;
    // ends_on is exclusive; show the last included day.
    const last = new Date(parseDateKey(sprint.ends_on));
    last.setDate(last.getDate() - 1);
    return `${fmt(parseDateKey(sprint.starts_on))} – ${fmt(last.getTime())}`;
  })();
  const outsideDate = (ms: number) => new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const color = plan?.color;

  return <div className="modal-backdrop"
    onMouseDown={event => { downOnBackdrop.current = event.target === event.currentTarget; }}
    onClick={event => { if (event.target === event.currentTarget && downOnBackdrop.current) onClose(); }}>
    <div className="modal np-modal sprint-modal" role="dialog" aria-modal="true" aria-label="Sprint"
      onClick={event => event.stopPropagation()}>
      <div className="modal-head">
        {project && (
          <span className="modal-proj-chip">
            <span className="proj-dot" style={{ background: project.color }} />
            {project.title}
          </span>
        )}
        {trackTitle && (
          <>
            <ChevronRight size={12} strokeWidth={1.5} className="modal-crumb-sep" aria-hidden />
            <span className="modal-crumb sprint-modal-track">
              {color && <span className="select-dot" style={{ background: color }} />}
              {trackTitle}
            </span>
          </>
        )}
        <span className="grow" />
        <button className="icon-btn" onClick={copyImport}
          title={copied ? 'Copied' : 'Copy task-cli import command'}
          aria-label="Copy task-cli import command">
          {copied ? <Check size={15} strokeWidth={1.75} /> : <Terminal size={15} strokeWidth={1.75} />}
        </button>
        {onDelete && (
          <button className="icon-btn modal-head-danger" onClick={onDelete}
            title="Delete sprint" aria-label="Delete sprint">
            <Trash2 size={15} strokeWidth={1.75} />
          </button>
        )}
        <button className="icon-btn" onClick={onClose} aria-label="Close" title="Close (Esc)">
          <X size={15} strokeWidth={1.75} />
        </button>
      </div>

      <div className="np-body sprint-modal-body">
        <input className="sprint-modal-title" aria-label="Sprint name"
          value={title} onChange={event => setTitle(event.target.value)}
          onKeyDown={event => { if (event.key === 'Enter') save(); }} />

        <div className="sprint-modal-stats">
          <span><strong>{dateRange}</strong></span>
          {plan && plan.totalCount > 0 && (
            <>
              <span className="est-meta-dot" aria-hidden>·</span>
              <span><strong>{plan.doneCount}</strong> of {plan.totalCount} done</span>
            </>
          )}
          {info && loadPct != null && (
            <span className="sprint-modal-load" data-over={loadPct > 100 || undefined}>
              <strong>{fmtMin(Math.round(info.estimatedMinutes))}</strong> of {fmtMin(info.capacityMinutes)} capacity
            </span>
          )}
        </div>
        {info && loadPct != null && (
          <div className="est-bar sprint-modal-bar" style={{ ['--proj-color' as string]: color }}>
            <div className="seg-spent" style={{ width: `${Math.min(100, loadPct)}%` }} />
          </div>
        )}
        {info && (info.missingEstimates > 0 || info.hasPrivateTime) && (
          <div className="sprint-modal-note">
            {info.missingEstimates > 0 && <>{info.missingEstimates} task{info.missingEstimates === 1 ? '' : 's'} without an estimate. </>}
            {info.hasPrivateTime && <>Private time is excluded.</>}
          </div>
        )}

        {/* Collapsed to one line: worth knowing, rarely worth reading. */}
        {info && info.outsideBlocks > 0 && (
          <details className="sprint-modal-warn">
            <summary className="sprint-modal-warn-head">
              <AlertTriangle size={13} strokeWidth={1.75} />
              {info.outsideBlocks} time block{info.outsideBlocks === 1 ? '' : 's'} outside the sprint
              <span className="sprint-modal-warn-meta">· {info.outsideTasks} task{info.outsideTasks === 1 ? '' : 's'}</span>
              <ChevronRight size={13} strokeWidth={1.75} className="sprint-modal-warn-caret" />
            </summary>
            <ul className="sprint-modal-warn-list">
              {info.outsidePortions.map((portion, index) => (
                <li key={`${portion.blockId}-${index}`}>
                  <span className="sprint-modal-warn-task">{portion.taskTitle}</span>
                  <span>{portion.state === 'completed' ? 'Logged' : 'Scheduled'} {fmtMin(Math.round((portion.to - portion.from) / 60_000))}</span>
                  <span>{outsideDate(portion.from)} · {portion.side === 'before' ? 'before' : 'after'}</span>
                </li>
              ))}
            </ul>
          </details>
        )}

        {onMoveToNow && parkedCount > 0 && (
          <div className="sprint-modal-action">
            <span>{parkedCount} {parkedCount === 1 ? 'task is' : 'tasks are'} not in Now yet.</span>
            <button className="btn btn-sm" onClick={onMoveToNow}>
              <Play size={12} strokeWidth={1.75} /> Move to Now
            </button>
          </div>
        )}

        <h5 className="tm-section-h">Description</h5>
        <textarea className="desc-md desc-md-edit sprint-modal-desc" rows={4}
          aria-label="Sprint description" placeholder="Goal, scope, notes… Markdown is supported."
          value={description} onChange={event => setDescription(event.target.value)} />

        <h5 className="tm-section-h">Defaults for new tasks</h5>
        <div className="sprint-modal-fields">
          <div className="sprint-modal-field">
            <span className="sprint-modal-label">Assignee</span>
            <Select value={assignee ?? ''} variant="inline" title="Default assignee" menuMinWidth={240}
              options={[{ value: '', label: 'Task creator' }, ...eligible.map(u => ({ value: u.id, label: u.name }))]}
              onChange={id => setAssignee(id || null)} />
          </div>
          <div className="sprint-modal-field">
            <span className="sprint-modal-label">Tags</span>
            <TagEditor projectId={sprint.project_id} selected={tagIds} allTags={tags}
              onChange={setTagIds} />
          </div>
        </div>
      </div>

      <div className="sprint-modal-foot">
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn np-create" disabled={!title.trim()} onClick={save}>Save</button>
      </div>
    </div>
  </div>;
}
