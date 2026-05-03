import { useEffect, useMemo, useRef, useState } from 'react';
import { Plus, Trash2, X } from 'lucide-react';
import { useFira } from '../store';
import { PROJECT_ICONS, DEFAULT_ICON, ProjectIcon } from './ProjectIcon';
import { Select } from './Select';
import { ConfirmDelete } from './ConfirmDelete';
import type { Project, ProjectMember, ProjectRole, UUID } from '../types';

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
  const deleteProject = useFira((s) => s.deleteProject);
  const showToast = useFira((s) => s.showToast);
  const loadAllUsers = useFira((s) => s.loadAllUsers);
  const allUsers = useFira((s) => s.users);
  const meId = useFira((s) => s.meId);
  const myWorkspaceRole = useFira((s) => s.myWorkspaceRole);
  // Only workspace owners may flip a project member's role to/from `lead`.
  // Project leads can edit the membership set but their role choices are
  // server-side ignored — gating in the UI keeps the affordance honest.
  const canEditRoles = myWorkspaceRole === 'owner';

  // Workspace owners edit their own role from this list (so they can
  // up-rank to 'lead' or de-rank to 'member' from the per-project default
  // 'owner'). Non-WS-owners see themselves as a read-only header row, so
  // their meId is filtered out of the editable list.
  const initialMembers: ProjectMember[] = useMemo(
    () => canEditRoles
      ? (project?.members ?? [])
      : (project?.members ?? []).filter((m) => m.user_id !== meId),
    [project, meId, canEditRoles],
  );

  const [title, setTitle] = useState(project?.title ?? '');
  const [icon, setIcon] = useState(project?.icon || DEFAULT_ICON);
  const [color, setColor] = useState(project?.color || COLORS[0].hex);
  const [urlTemplate, setUrlTemplate] = useState(project?.external_url_template ?? '');
  // Members are owner-locked: meId (the project owner / "you" row) is
  // implicit and not in this set. Each row carries (user_id, role).
  const [members, setMembers] = useState<ProjectMember[]>(initialMembers);
  const [armedRemove, setArmedRemove] = useState<UUID | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  // Workspace owners only — leads can edit, but deletion is owner-gated.
  const canDelete = isEdit && canEditRoles;

  useEffect(() => {
    if (isEdit) loadAllUsers().catch(() => { /* non-fatal */ });
  }, [isEdit, loadAllUsers]);

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
  const membersDirty = isEdit && !memberListEqual(members, initialMembers);
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
      const msg = e instanceof Error ? e.message : 'Failed to save project';
      setError(msg);
      showToast(msg);
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
          {canDelete && (
            <button
              className="icon-btn modal-head-danger"
              onClick={() => setConfirmingDelete(true)}
              title="Delete project"
              disabled={submitting}
            >
              <Trash2 size={15} strokeWidth={1.75} />
            </button>
          )}
          <button className="icon-btn" onClick={close} title="Close (Esc)" aria-label="Close">
            <X size={15} strokeWidth={1.75} />
          </button>
        </div>
        <div className="np-body">
          <label className="np-label">Name</label>
          <input
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
                meId={meId}
                members={members}
                canEditRoles={canEditRoles}
                armedRemove={armedRemove}
                setArmedRemove={setArmedRemove}
                onAdd={(uid) => setMembers((m) =>
                  m.some((x) => x.user_id === uid) ? m : [...m, { user_id: uid, role: 'member' }]
                )}
                onRemove={(uid) => {
                  setMembers((m) => m.filter((x) => x.user_id !== uid));
                  setArmedRemove(null);
                }}
                onRoleChange={(uid, role) => setMembers((m) =>
                  m.map((x) => x.user_id === uid ? { ...x, role } : x)
                )}
              />
              {!canEditRoles && (
                <div className="np-hint">
                  Only the workspace owner can change project roles.
                </div>
              )}
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
        {confirmingDelete && project && (
          <ConfirmDelete
            title="Delete project?"
            confirmName={project.title}
            confirmLabel="Delete project"
            body={
              <p>
                <strong>{project.title}</strong> will be deleted along with every task, subtask,
                epic, sprint, and time block it contains. This can't be undone.
              </p>
            }
            onCancel={() => setConfirmingDelete(false)}
            onConfirm={async () => {
              setConfirmingDelete(false);
              setSubmitting(true);
              setError(null);
              try {
                await deleteProject(project.id);
                close();
              } catch (e) {
                const msg = e instanceof Error ? e.message : 'Failed to delete project';
                setError(msg);
                showToast(msg);
                setSubmitting(false);
              }
            }}
          />
        )}
      </div>
    </div>
  );
}

interface MembersEditorProps {
  allUsers: { id: UUID; name: string; initials: string; email: string }[];
  meId: UUID | null;
  members: ProjectMember[];
  canEditRoles: boolean;
  armedRemove: UUID | null;
  setArmedRemove: (id: UUID | null) => void;
  onAdd: (id: UUID) => void;
  onRemove: (id: UUID) => void;
  onRoleChange: (id: UUID, role: ProjectRole) => void;
}

function MembersEditor({
  allUsers, meId, members, canEditRoles, armedRemove, setArmedRemove,
  onAdd, onRemove, onRoleChange,
}: MembersEditorProps) {
  const [picking, setPicking] = useState(false);
  const [query, setQuery] = useState('');
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const memberSet = useMemo(() => new Set(members.map((m) => m.user_id)), [members]);
  // When the caller can edit roles (workspace owner) they appear inline as
  // an editable row, so we don't render a separate read-only header. For
  // everyone else, we surface the caller's actual project role at the top.
  const myMembership = meId ? members.find((m) => m.user_id === meId) ?? null : null;
  const headerSelf = !canEditRoles && meId
    ? allUsers.find((u) => u.id === meId) ?? null
    : null;
  const memberRows = useMemo(
    () => members
      .filter((m) => canEditRoles || m.user_id !== meId)
      .map((m) => {
        const u = allUsers.find((x) => x.id === m.user_id);
        return u ? { user: u, role: m.role } : null;
      })
      .filter((r): r is { user: MembersEditorProps['allUsers'][number]; role: ProjectRole } => !!r),
    [members, allUsers, canEditRoles, meId],
  );

  const candidates = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allUsers.filter((u) => {
      if (memberSet.has(u.id)) return false;
      if (!q) return true;
      return u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
    });
  }, [allUsers, memberSet, query]);

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
        {headerSelf && (
          <div className="np-member np-member-owner" title="You can't remove yourself">
            <span className="avatar" data-me="true">{headerSelf.initials}</span>
            <span className="np-member-name">{headerSelf.name}</span>
            <span className="np-member-tag">{myMembership?.role ?? 'member'} (you)</span>
          </div>
        )}
        {memberRows.map(({ user: u, role }) => {
          const armed = armedRemove === u.id;
          const isSelf = u.id === meId;
          return (
            <div key={u.id} className="np-member" data-armed={u.id} data-me={isSelf || undefined}>
              <span className="avatar" data-me={isSelf || undefined}>{u.initials}</span>
              <span className="np-member-name">{u.name}{isSelf ? ' (you)' : ''}</span>
              {canEditRoles ? (
                <Select<ProjectRole>
                  size="sm"
                  value={role}
                  menuMinWidth={180}
                  onChange={(v) => onRoleChange(u.id, v)}
                  options={[
                    { value: 'owner', label: 'owner', hint: 'hidden from inbox unless tasks assigned' },
                    { value: 'lead', label: 'lead', hint: 'edits project + members' },
                    { value: 'member', label: 'member', hint: 'works tasks' },
                    { value: 'inactive', label: 'inactive', hint: 'hidden from inbox unless tasks assigned' },
                  ]}
                />
              ) : (
                <span className="np-member-tag">{role}</span>
              )}
              {!isSelf && (armed ? (
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
                  <X size={12} strokeWidth={1.75} />
                </button>
              ))}
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

function memberListEqual(a: ProjectMember[], b: ProjectMember[]): boolean {
  if (a.length !== b.length) return false;
  const byA = new Map(a.map((m) => [m.user_id, m.role]));
  return b.every((m) => byA.get(m.user_id) === m.role);
}
