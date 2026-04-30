import { useEffect, useMemo, useRef, useState } from 'react';
import { Plus } from 'lucide-react';
import { useFira } from '../store';
import { PROJECT_ICONS, DEFAULT_ICON, ProjectIcon } from './ProjectIcon';
import type { Project, UUID } from '../types';

// Editorial-utilitarian palette. All Tailwind ~700 shades so each chip sits
// at the same perceived weight on paper — distinguishable by hue, not by
// brightness. Two existing seed projects (teal, amber) live here unchanged.
const COLORS: { hex: string; name: string }[] = [
  { hex: '#0F766E', name: 'Teal' },
  { hex: '#0E7490', name: 'Cyan' },
  { hex: '#1D4ED8', name: 'Blue' },
  { hex: '#6D28D9', name: 'Violet' },
  { hex: '#BE185D', name: 'Pink' },
  { hex: '#B45309', name: 'Amber' },
  { hex: '#15803D', name: 'Green' },
  { hex: '#334155', name: 'Slate' },
];

interface Props {
  // undefined = create new; otherwise edit this project.
  project?: Project;
}

export function ProjectModal({ project }: Props) {
  const isEdit = !!project;
  const close = useFira((s) => s.closeProjectModal);
  const addProject = useFira((s) => s.addProject);
  const updateProject = useFira((s) => s.updateProject);
  const setProjectMembers = useFira((s) => s.setProjectMembers);
  const loadAllUsers = useFira((s) => s.loadAllUsers);
  const allUsers = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);

  const [title, setTitle] = useState(project?.title ?? '');
  const [icon, setIcon] = useState(project?.icon || DEFAULT_ICON);
  const [color, setColor] = useState(project?.color || COLORS[0].hex);
  const [urlTemplate, setUrlTemplate] = useState(project?.external_url_template ?? '');
  // Members are owner-locked: meId (owner) is implicit and not in this set.
  // We only track the *additional* members the user can edit.
  const [members, setMembers] = useState<UUID[]>(
    () => (project?.members ?? []).filter((u) => u !== meId),
  );
  // Two-step remove: clicking × on a chip arms it, clicking again confirms.
  const [armedRemove, setArmedRemove] = useState<UUID | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Pull the full directory once when an edit modal opens — bootstrap only
  // returns co-members of in-scope projects, so without this an owner can't
  // add a teammate they haven't worked with yet.
  useEffect(() => {
    if (isEdit) loadAllUsers().catch(() => { /* non-fatal; picker shows what we have */ });
  }, [isEdit, loadAllUsers]);

  // Disarm any pending remove if the user clicks elsewhere in the modal.
  useEffect(() => {
    if (armedRemove == null) return;
    const onDoc = (e: MouseEvent) => {
      const t = e.target as HTMLElement;
      if (!t.closest(`[data-armed="${armedRemove}"]`)) setArmedRemove(null);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [armedRemove]);

  const trimmed = title.trim();
  const trimmedUrl = urlTemplate.trim();
  const valid = trimmed.length > 0 && trimmed.length <= 80;
  const initialMembers = (project?.members ?? []).filter((u) => u !== meId);
  const membersDirty = isEdit && !setEqual(members, initialMembers);
  const initialUrl = project?.external_url_template ?? '';
  const urlDirty = isEdit && trimmedUrl !== initialUrl;
  const dirty = !isEdit || (
    trimmed !== project!.title
    || icon !== project!.icon
    || color !== project!.color
    || urlDirty
    || membersDirty
  );

  const submit = async () => {
    if (!valid || submitting || !dirty) return;
    setSubmitting(true);
    setError(null);
    try {
      if (isEdit) {
        const visualDirty = trimmed !== project!.title
          || icon !== project!.icon
          || color !== project!.color
          || urlDirty;
        if (visualDirty) {
          await updateProject(project!.id, {
            title: trimmed,
            icon,
            color,
            // Only thread the field if the user touched it; null clears.
            ...(urlDirty ? { external_url_template: trimmedUrl || null } : {}),
          });
        }
        if (membersDirty) {
          await setProjectMembers(project!.id, members);
        }
        close();
      } else {
        await addProject({ title: trimmed, icon, color });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save project');
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={close}>
      <div className="modal np-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="np-preview" style={{ color, borderColor: color }}>
            <ProjectIcon name={icon} size={14} strokeWidth={1.75} />
          </span>
          <span className="ext">{trimmed || (isEdit ? project!.title : 'New project')}</span>
          <span className="grow" />
          <button className="icon-btn" onClick={close} title="Close (Esc)">×</button>
        </div>
        <div className="np-body">
          <label className="np-label">Name</label>
          <input
            autoFocus
            className="np-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Project name"
            maxLength={80}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.metaKey || e.ctrlKey || valid)) {
                e.preventDefault();
                submit();
              }
              if (e.key === 'Escape') close();
            }}
          />

          <label className="np-label">Icon</label>
          <div className="np-icons">
            {PROJECT_ICONS.map(({ name, icon: I }) => (
              <button
                key={name}
                type="button"
                className="np-icon"
                data-active={name === icon}
                onClick={() => setIcon(name)}
                title={name}
                aria-label={name}
              >
                <I size={18} strokeWidth={1.75} />
              </button>
            ))}
          </div>

          <label className="np-label">Color</label>
          <div className="np-colors">
            {COLORS.map((c) => (
              <button
                key={c.hex}
                type="button"
                className="np-color"
                data-active={c.hex === color}
                style={{ ['--swatch' as string]: c.hex }}
                onClick={() => setColor(c.hex)}
                title={c.name}
                aria-label={c.name}
              >
                <span className="np-color-fill" />
              </button>
            ))}
          </div>

          {isEdit && (
            <>
              <label className="np-label">Issue URL template</label>
              <input
                className="np-title"
                value={urlTemplate}
                onChange={(e) => setUrlTemplate(e.target.value)}
                placeholder="https://acme.atlassian.net/browse/{key}"
                spellCheck={false}
              />
              <div className="np-hint">
                {trimmedUrl && !trimmedUrl.includes('{key}')
                  ? 'Tip: include {key} where the issue id should go.'
                  : 'Tasks with an issue id render as a link via this template.'}
              </div>

              <label className="np-label">Members</label>
              <MembersEditor
                allUsers={allUsers}
                ownerId={meId}
                members={members}
                armedRemove={armedRemove}
                setArmedRemove={setArmedRemove}
                onAdd={(uid) => setMembers((m) => (m.includes(uid) ? m : [...m, uid]))}
                onRemove={(uid) => {
                  setMembers((m) => m.filter((x) => x !== uid));
                  setArmedRemove(null);
                }}
              />
            </>
          )}

          {error && <div className="np-error">{error}</div>}

          <div className="np-actions">
            <button className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button
              className="btn np-create"
              onClick={submit}
              disabled={!valid || !dirty || submitting}
            >
              {submitting
                ? (isEdit ? 'Saving…' : 'Creating…')
                : (isEdit ? 'Save changes' : 'Create project')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

interface MembersEditorProps {
  allUsers: { id: UUID; name: string; initials: string; email: string }[];
  ownerId: UUID | null;
  members: UUID[];
  armedRemove: UUID | null;
  setArmedRemove: (id: UUID | null) => void;
  onAdd: (id: UUID) => void;
  onRemove: (id: UUID) => void;
}

function MembersEditor({
  allUsers, ownerId, members, armedRemove, setArmedRemove, onAdd, onRemove,
}: MembersEditorProps) {
  const [picking, setPicking] = useState(false);
  const [query, setQuery] = useState('');
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const memberSet = useMemo(() => new Set(members), [members]);
  const owner = ownerId ? allUsers.find((u) => u.id === ownerId) : null;
  const memberRows = useMemo(
    () => members
      .map((id) => allUsers.find((u) => u.id === id))
      .filter((u): u is MembersEditorProps['allUsers'][number] => !!u),
    [members, allUsers],
  );

  const candidates = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allUsers.filter((u) => {
      if (u.id === ownerId) return false;
      if (memberSet.has(u.id)) return false;
      if (!q) return true;
      return u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
    });
  }, [allUsers, ownerId, memberSet, query]);

  useEffect(() => {
    if (!picking) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setPicking(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [picking]);

  useEffect(() => {
    if (picking) {
      setQuery('');
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [picking]);

  return (
    <div className="np-members" ref={wrapRef}>
      <div className="np-members-list">
        {owner && (
          <div className="np-member np-member-owner" title="Project owner — can't be removed">
            <span className="avatar" data-me="true">{owner.initials}</span>
            <span className="np-member-name">{owner.name}</span>
            <span className="np-member-tag">owner</span>
          </div>
        )}
        {memberRows.map((u) => {
          const armed = armedRemove === u.id;
          return (
            <div key={u.id} className="np-member" data-armed={u.id}>
              <span className="avatar">{u.initials}</span>
              <span className="np-member-name">{u.name}</span>
              {armed ? (
                <button
                  type="button"
                  className="np-member-confirm"
                  onClick={() => onRemove(u.id)}
                  title="Confirm remove"
                >
                  Remove
                </button>
              ) : (
                <button
                  type="button"
                  className="np-member-x"
                  onClick={() => setArmedRemove(u.id)}
                  title="Remove from project"
                  aria-label={`Remove ${u.name}`}
                >
                  ×
                </button>
              )}
            </div>
          );
        })}
        <button
          type="button"
          className="np-member-add"
          onClick={() => setPicking((v) => !v)}
          data-open={picking}
        >
          <Plus size={14} strokeWidth={1.75} />
          <span>Add member</span>
        </button>
        {picking && (
          <div className="np-members-picker">
            <input
              ref={inputRef}
              className="user-search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search people…"
              onKeyDown={(e) => { if (e.key === 'Escape') setPicking(false); }}
            />
            <div className="np-members-candidates">
              {candidates.length === 0 ? (
                <div className="user-empty">No matches.</div>
              ) : candidates.map((u) => (
                <button
                  key={u.id}
                  type="button"
                  className="user-row"
                  onClick={() => { onAdd(u.id); setPicking(false); }}
                >
                  <span className="avatar">{u.initials}</span>
                  <span className="user-row-name">{u.name}</span>
                  <span className="user-row-email">{u.email}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function setEqual(a: UUID[], b: UUID[]): boolean {
  if (a.length !== b.length) return false;
  const s = new Set(a);
  return b.every((x) => s.has(x));
}
