import { useEffect, useMemo, useRef, useState } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { useFira } from '../store';
import { api } from '../api';
import type { User, UUID, Workspace, WorkspaceRole } from '../types';
import { Select } from './Select';
import { ConfirmDelete } from './ConfirmDelete';

// Two modes:
//   - { kind: 'new' }  — title-only create. Caller becomes owner.
//   - { kind: 'edit' } — title rename + members + roles. Owner-only.
//
// Personal workspaces show the title (read-only — could be made editable
// later) and hide the members section since their membership is fixed.

interface Props {
  workspace?: Workspace;
}

export function WorkspaceModal({ workspace }: Props) {
  const isEdit = !!workspace;
  const close = useFira((s) => s.closeWorkspaceModal);
  const createWorkspace = useFira((s) => s.createWorkspace);
  const renameWorkspace = useFira((s) => s.renameWorkspace);
  const setWorkspaceMembers = useFira((s) => s.setWorkspaceMembers);
  const deleteWorkspace = useFira((s) => s.deleteWorkspace);
  const showToast = useFira((s) => s.showToast);
  const meId = useFira((s) => s.meId);
  const allUsers = useFira((s) => s.users);
  // Owner-only and never personal — backend enforces both, the UI hides
  // the affordance when the caller can't act on it.
  const myRole = useMemo(
    () => workspace?.members.find((m) => m.user_id === meId)?.role ?? null,
    [workspace, meId],
  );
  const canDelete = isEdit && !workspace!.is_personal && myRole === 'owner';

  const [title, setTitle] = useState(workspace?.title ?? '');
  const [members, setMembers] = useState<{ user_id: UUID; role: WorkspaceRole }[]>(
    () => (workspace?.members ?? [])
      .filter((m) => m.user_id !== meId)
      .map((m) => ({ user_id: m.user_id, role: m.role })),
  );
  const [armedRemove, setArmedRemove] = useState<UUID | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  // Pull the directory once for this workspace so the picker has more than
  // just the existing members. We pull from the API directly rather than
  // through the store loader because the workspace might not be the active
  // one yet (rare, but happens with create-then-edit).
  const [directory, setDirectory] = useState<User[]>([]);
  useEffect(() => {
    if (!isEdit || workspace?.is_personal) return;
    // Owner-only endpoint: returns every user in the system so the picker
    // can offer people who aren't in this workspace yet (e.g. a teammate
    // who just signed in via Google for the first time).
    api.listAllUsersForWorkspace(workspace!.id).catch(() => null).then((rows) => {
      if (!rows) return;
      const merged = mergeUsers(allUsers, rows);
      setDirectory(merged);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isEdit, workspace?.id]);

  // Disarm pending remove on outside click.
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
  const valid = trimmed.length > 0 && trimmed.length <= 80;
  const initialMembers = (workspace?.members ?? [])
    .filter((m) => m.user_id !== meId)
    .map((m) => ({ user_id: m.user_id, role: m.role }));
  const membersDirty = isEdit && !memberSetEqual(members, initialMembers);
  const titleDirty = !isEdit || trimmed !== workspace!.title;
  const dirty = titleDirty || membersDirty;

  const submit = async () => {
    if (!valid || submitting || !dirty) return;
    setSubmitting(true);
    setError(null);
    try {
      if (isEdit) {
        if (titleDirty) {
          await renameWorkspace(workspace!.id, trimmed);
        }
        if (membersDirty && !workspace!.is_personal) {
          await setWorkspaceMembers(workspace!.id, members);
        }
        close();
      } else {
        await createWorkspace(trimmed);
        close();
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save workspace';
      setError(msg);
      showToast(msg);
      setSubmitting(false);
    }
  };

  const showMembers = isEdit && !workspace!.is_personal;
  const usersForPicker = directory.length > 0 ? directory : allUsers;

  return (
    <div className="modal-backdrop" onClick={close}>
      <div className="modal np-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ext">
            {trimmed || (isEdit ? workspace!.title : 'New workspace')}
          </span>
          <span className="grow" />
          {canDelete && (
            <button
              className="icon-btn modal-head-danger"
              onClick={() => setConfirmingDelete(true)}
              title="Delete workspace"
              disabled={submitting}
            >
              <Trash2 size={15} strokeWidth={1.75} />
            </button>
          )}
          <button className="icon-btn" onClick={close} title="Close (Esc)">×</button>
        </div>
        <div className="np-body">
          <label className="np-label">Name</label>
          <input
            autoFocus
            className="np-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Workspace name"
            maxLength={80}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && valid) {
                e.preventDefault();
                submit();
              }
              if (e.key === 'Escape') close();
            }}
          />

          {showMembers && (
            <>
              <label className="np-label">Members</label>
              <WorkspaceMembersEditor
                allUsers={usersForPicker}
                ownerId={meId}
                members={members}
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
            </>
          )}

          {isEdit && workspace!.is_personal && (
            <p className="np-hint">
              Personal workspace — only you. Add teammates by creating a new workspace.
            </p>
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
                : (isEdit ? 'Save changes' : 'Create workspace')}
            </button>
          </div>
        </div>
        {confirmingDelete && workspace && (
          <ConfirmDelete
            title="Delete workspace?"
            confirmName={workspace.title}
            confirmLabel="Delete workspace"
            body={
              <p>
                <strong>{workspace.title}</strong> will be deleted along with every project,
                task, subtask, time block, and member assignment inside it. This can't be undone.
              </p>
            }
            onCancel={() => setConfirmingDelete(false)}
            onConfirm={async () => {
              setConfirmingDelete(false);
              setSubmitting(true);
              setError(null);
              try {
                await deleteWorkspace(workspace.id);
                close();
              } catch (e) {
                const msg = e instanceof Error ? e.message : 'Failed to delete workspace';
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
  allUsers: User[];
  ownerId: UUID | null;
  members: { user_id: UUID; role: WorkspaceRole }[];
  armedRemove: UUID | null;
  setArmedRemove: (id: UUID | null) => void;
  onAdd: (id: UUID) => void;
  onRemove: (id: UUID) => void;
  onRoleChange: (id: UUID, role: WorkspaceRole) => void;
}

function WorkspaceMembersEditor({
  allUsers, ownerId, members, armedRemove, setArmedRemove, onAdd, onRemove, onRoleChange,
}: MembersEditorProps) {
  const [picking, setPicking] = useState(false);
  const [query, setQuery] = useState('');
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const memberSet = useMemo(() => new Set(members.map((m) => m.user_id)), [members]);
  const owner = ownerId ? allUsers.find((u) => u.id === ownerId) : null;
  const memberRows = useMemo(
    () => members
      .map((m) => {
        const u = allUsers.find((x) => x.id === m.user_id);
        return u ? { user: u, role: m.role } : null;
      })
      .filter((r): r is { user: User; role: WorkspaceRole } => r !== null),
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
          <div className="np-member np-member-owner" title="Workspace creator — owner role">
            <span className="avatar" data-me="true">{owner.initials}</span>
            <span className="np-member-name">{owner.name}</span>
            <span className="np-member-tag">owner (you)</span>
          </div>
        )}
        {memberRows.map(({ user: u, role }) => {
          const armed = armedRemove === u.id;
          return (
            <div key={u.id} className="np-member" data-armed={u.id}>
              <span className="avatar">{u.initials}</span>
              <span className="np-member-name">{u.name}</span>
              <Select<WorkspaceRole>
                size="sm"
                value={role}
                menuMinWidth={140}
                onChange={(v) => onRoleChange(u.id, v)}
                options={[
                  { value: 'owner', label: 'owner', hint: 'manages workspace + roles' },
                  { value: 'member', label: 'member', hint: 'works in projects they belong to' },
                ]}
              />
              {armed ? (
                <button
                  type="button"
                  className="np-member-confirm"
                  onClick={() => onRemove(u.id)}
                >
                  Remove
                </button>
              ) : (
                <button
                  type="button"
                  className="np-member-x"
                  onClick={() => setArmedRemove(u.id)}
                  title="Remove from workspace"
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

function memberSetEqual(
  a: { user_id: UUID; role: WorkspaceRole }[],
  b: { user_id: UUID; role: WorkspaceRole }[],
): boolean {
  if (a.length !== b.length) return false;
  const byA = new Map(a.map((m) => [m.user_id, m.role]));
  return b.every((m) => byA.get(m.user_id) === m.role);
}

function mergeUsers(existing: User[], more: User[]): User[] {
  const byId = new Map(existing.map((u) => [u.id, u]));
  for (const u of more) byId.set(u.id, u);
  return Array.from(byId.values()).sort((a, b) => a.name.localeCompare(b.name));
}
