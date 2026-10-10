import { useEffect, useRef, useState } from 'react';
import type { Sprint, UUID } from '../types';
import { useFira } from '../store';
import { Select } from './Select';
import { TagEditor } from './TaskModal';
import { X } from 'lucide-react';

export function SprintModal({ sprint, onClose }: { sprint: Sprint; onClose: () => void }) {
  const [title, setTitle] = useState(sprint.title);
  const [assignee, setAssignee] = useState<UUID | null>(sprint.default_assignee_id ?? null);
  const [tagIds, setTagIds] = useState(sprint.default_tag_ids ?? []);
  const project = useFira(s => s.projects.find(p => p.id === sprint.project_id));
  const users = useFira(s => s.users);
  const tags = useFira(s => s.tags);
  const setTitleOnSprint = useFira(s => s.setSprintTitle);
  const setDefaults = useFira(s => s.setSprintDefaults);
  const addTag = useFira(s => s.addTag);
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
    const validTags = tagIds.filter(id => tags.some(t => t.id === id && t.project_id === sprint.project_id));
    if (assignee !== (sprint.default_assignee_id ?? null) ||
      [...validTags].sort().join() !== [...(sprint.default_tag_ids ?? [])].sort().join()) {
      setDefaults(sprint.id, assignee, validTags);
    }
    onClose();
  };
  return <div className="modal-backdrop confirm-backdrop"
    onMouseDown={event => { downOnBackdrop.current = event.target === event.currentTarget; }}
    onClick={event => { if (event.target === event.currentTarget && downOnBackdrop.current) onClose(); }}>
    <div className="modal np-modal confirm-modal" role="dialog" aria-modal="true" aria-label="Edit sprint"
      onClick={event => event.stopPropagation()}>
      <div className="modal-head">
        <span className="ext">Edit sprint</span><span className="grow" />
        <button className="icon-btn" onClick={onClose} aria-label="Close" title="Close (Esc)"><X size={16} /></button>
      </div>
      <div className="np-body">
        <label className="np-label" htmlFor="sprint-name">Name</label>
        <input id="sprint-name" className="np-title" autoFocus aria-label="Sprint name"
          value={title} onChange={event => setTitle(event.target.value)} />
        <div className="np-label">Default assignee</div>
          <Select value={assignee ?? ''} variant="inline" title="Default assignee" menuMinWidth={240}
            options={[{ value: '', label: 'Task creator' }, ...eligible.map(u => ({ value: u.id, label: u.name }))]}
            onChange={id => setAssignee(id || null)} />
        <div className="np-label">Default tags</div>
          <TagEditor projectId={sprint.project_id} selected={tagIds} allTags={tags}
            onChange={setTagIds} onCreate={name => addTag(sprint.project_id, name, '#334155')} />
        <div className="np-hint">Defaults apply to new tasks added in this sprint.</div>
        <div className="np-actions">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn np-create" disabled={!title.trim()} onClick={save}>Save</button>
        </div>
      </div>
    </div>
  </div>;
}
