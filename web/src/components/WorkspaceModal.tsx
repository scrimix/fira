import { useEffect, useMemo, useState } from 'react';
import { Mail, Trash2, X } from 'lucide-react';
import { useFira } from '../store';
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
  const setWorkspaceMemberRole = useFira((s) => s.setWorkspaceMemberRole);
  const removeWorkspaceMember = useFira((s) => s.removeWorkspaceMember);
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
  // Member list is read straight from the workspace prop — no local
  // staging, no bulk-set-on-save. Each membership mutation hits the
  // server immediately:
  //   - Add: never from this modal — invites only.
  //   - Remove: the typed-email confirm calls removeWorkspaceMember.
  //   - Role change: the Select calls setWorkspaceMemberRole.
  // The Save Changes button only renames the workspace; if the title
  // is unchanged the button is disabled.
  const members = useMemo(
    () => (workspace?.members ?? [])
      .filter((m) => m.user_id !== meId)
      .map((m) => ({ user_id: m.user_id, role: m.role })),
    [workspace, meId],
  );
  const [armedRemove, setArmedRemove] = useState<UUID | null>(null);
  const [removingMember, setRemovingMember] = useState<User | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

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
  const titleDirty = !isEdit || trimmed !== workspace!.title;
  const dirty = titleDirty;

  const submit = async () => {
    if (!valid || submitting || !dirty) return;
    setSubmitting(true);
    setError(null);
    try {
      if (isEdit) {
        if (titleDirty) {
          await renameWorkspace(workspace!.id, trimmed);
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

  const onRoleChange = async (uid: UUID, role: WorkspaceRole) => {
    if (!workspace) return;
    try {
      await setWorkspaceMemberRole(workspace.id, uid, role);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to change role';
      showToast(msg);
    }
  };

  const showMembers = isEdit && !workspace!.is_personal;

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
          <button className="icon-btn" onClick={close} title="Close (Esc)" aria-label="Close">
            <X size={15} strokeWidth={1.75} />
          </button>
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
                allUsers={allUsers}
                ownerId={meId}
                members={members}
                armedRemove={armedRemove}
                setArmedRemove={setArmedRemove}
                onRemove={(uid) => {
                  // Open the typed-email confirm instead of removing
                  // immediately — workspace removal cascades into every
                  // project membership in this workspace, so it warrants
                  // the same paranoia as project/workspace delete.
                  const target = allUsers.find((u) => u.id === uid) ?? null;
                  setRemovingMember(target);
                }}
                onRoleChange={onRoleChange}
              />
              <label className="np-label" style={{ marginTop: 18 }}>Invite by email</label>
              <WorkspaceInviteSection workspaceId={workspace!.id} />
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
        {removingMember && workspace && (
          <ConfirmDelete
            title="Remove member?"
            confirmName={removingMember.email}
            confirmLabel="Remove member"
            body={
              <p>
                <strong>{removingMember.name}</strong> ({removingMember.email}) will be
                removed from this workspace and from every project they were a member of
                inside it. Their tasks, subtasks, and time blocks stay as historical
                record.
              </p>
            }
            onCancel={() => {
              setRemovingMember(null);
              setArmedRemove(null);
            }}
            onConfirm={async () => {
              // Single-shot remove — hits the dedicated DELETE endpoint
              // for this one user. The typed-email confirm is the
              // user's intent; no separate Save click required.
              try {
                await removeWorkspaceMember(workspace.id, removingMember.id);
              } catch (e) {
                const msg = e instanceof Error ? e.message : 'Failed to remove member';
                setError(msg);
                showToast(msg);
              }
              setArmedRemove(null);
              setRemovingMember(null);
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
  onRemove: (id: UUID) => void;
  onRoleChange: (id: UUID, role: WorkspaceRole) => void;
}

function WorkspaceMembersEditor({
  allUsers, ownerId, members, armedRemove, setArmedRemove, onRemove, onRoleChange,
}: MembersEditorProps) {
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

  return (
    <div className="np-members">
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
                  <X size={12} strokeWidth={1.75} />
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Email-based invite section. Replaces the global user search picker.
// Owner enters an email, hits Send, the invite goes pending until the
// recipient (matched by email) accepts via the receive-side modal. The
// pending list below the form lets the owner cancel before acceptance.
function WorkspaceInviteSection({ workspaceId }: { workspaceId: UUID }) {
  const inviteToWorkspace = useFira((s) => s.inviteToWorkspace);
  const cancelWorkspaceInvite = useFira((s) => s.cancelWorkspaceInvite);
  const showToast = useFira((s) => s.showToast);
  // Read the full array (stable reference unless the store mutates),
  // then derive the filtered list with useMemo. The previous shape
  // `useFira((s) => s.workspaceInvites.filter(...))` returned a fresh
  // array literal every render — useSyncExternalStore treats that as
  // a store change and infinite-loops.
  const allInvites = useFira((s) => s.workspaceInvites);
  const pending = useMemo(
    () => allInvites.filter(
      (i) => i.workspace_id === workspaceId
        && i.direction === 'sent'
        && i.status === 'pending',
    ),
    [allInvites, workspaceId],
  );
  const [email, setEmail] = useState('');
  const [sending, setSending] = useState(false);

  const send = async () => {
    const v = email.trim().toLowerCase();
    if (!v || sending) return;
    if (!v.includes('@')) {
      showToast('Enter a valid email');
      return;
    }
    setSending(true);
    try {
      await inviteToWorkspace(workspaceId, v);
      setEmail('');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to send invite';
      showToast(msg);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="np-invites">
      <div className="np-invite-row">
        <Mail size={14} strokeWidth={1.75} className="np-invite-icon" />
        <input
          className="np-invite-input"
          type="email"
          placeholder="teammate@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); void send(); }
          }}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          disabled={sending}
        />
        <button
          type="button"
          className="btn np-invite-send"
          onClick={() => void send()}
          disabled={sending || email.trim().length === 0}
        >
          {sending ? 'Sending…' : 'Send invite'}
        </button>
      </div>
      {pending.length > 0 && (
        <div className="np-invites-pending">
          <div className="np-invites-head">Pending invites</div>
          {pending.map((inv) => (
            <div key={inv.id} className="np-invite-item">
              <span className="np-invite-item-email">{inv.email}</span>
              <span className="np-invite-item-meta">
                {inv.role} · sent {fmtRelative(inv.created_at)}
              </span>
              <button
                type="button"
                className="np-invite-cancel"
                onClick={() => { void cancelWorkspaceInvite(inv.id); }}
                title="Cancel invite"
                aria-label={`Cancel invite to ${inv.email}`}
              >
                <X size={12} strokeWidth={1.75} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function fmtRelative(iso: string): string {
  const ms = Date.now() - Date.parse(iso);
  const sec = Math.max(0, Math.floor(ms / 1000));
  if (sec < 60) return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const d = Math.floor(hr / 24);
  return `${d}d ago`;
}
