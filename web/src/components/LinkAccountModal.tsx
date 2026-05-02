import { useEffect, useMemo, useRef, useState } from 'react';
import { Plus } from 'lucide-react';
import { useFira } from '../store';
import type { User, UUID } from '../types';

// One modal serves four states, picked from `links`:
//   - none           → workspace member picker + "Send invite"
//   - sent (pending) → "Waiting for <Name>" + Cancel
//   - received (pending) → "<Name> wants to link" + Accept / Decline
//   - accepted       → "Linked with <Name>" + Unlink
//
// All four share the same shell (header / body / actions) so the modal
// frame doesn't pop between transitions while the user iterates.

export function LinkAccountModal() {
  const close = useFira((s) => s.closeLinkModal);
  const links = useFira((s) => s.links);
  const meId = useFira((s) => s.meId);
  const users = useFira((s) => s.users);
  const requestLink = useFira((s) => s.requestLink);
  const acceptLink = useFira((s) => s.acceptLink);
  const cancelLink = useFira((s) => s.cancelLink);
  const showToast = useFira((s) => s.showToast);
  const activeWorkspace = useFira((s) =>
    s.workspaces.find((w) => w.id === s.activeWorkspaceId) ?? null,
  );

  // Same priority order as the topbar icon — show the most actionable
  // card first if multiple coexist.
  const link = useMemo(() => {
    const received = links.find((l) => l.direction === 'received' && l.status === 'pending');
    if (received) return received;
    const sent = links.find((l) => l.direction === 'sent' && l.status === 'pending');
    if (sent) return sent;
    return links.find((l) => l.status === 'accepted') ?? null;
  }, [links]);

  const partner = link ? users.find((u) => u.id === link.partner_id) ?? null : null;
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const guarded = async (fn: () => Promise<void>) => {
    setSubmitting(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed';
      setError(msg);
      showToast(msg);
    } finally {
      setSubmitting(false);
    }
  };

  let body: React.ReactNode;
  if (!link) {
    body = (
      <PickerView
        users={users}
        meId={meId}
        workspaceMemberIds={
          activeWorkspace
            ? new Set(activeWorkspace.members.map((m) => m.user_id))
            : new Set()
        }
        submitting={submitting}
        onPick={(uid) => guarded(async () => {
          await requestLink(uid);
        })}
      />
    );
  } else if (link.direction === 'received' && link.status === 'pending') {
    body = (
      <div className="np-body link-state-card">
        <p className="link-headline">
          <strong>{partner?.name ?? 'Someone'}</strong> wants to link calendars with you.
        </p>
        <p className="np-hint">
          Linking lets each of you see the other's tasks and time blocks on the
          calendar (read-only). You can unlink any time.
        </p>
        <div className="np-actions">
          <button
            className="btn"
            onClick={() => guarded(async () => { await cancelLink(link.id); close(); })}
            disabled={submitting}
          >
            Decline
          </button>
          <button
            className="btn np-create"
            onClick={() => guarded(async () => { await acceptLink(link.id); close(); })}
            disabled={submitting}
          >
            Accept
          </button>
        </div>
      </div>
    );
  } else if (link.direction === 'sent' && link.status === 'pending') {
    body = (
      <div className="np-body link-state-card">
        <p className="link-headline">
          Waiting for <strong>{partner?.name ?? 'the other account'}</strong> to accept.
        </p>
        <p className="np-hint">
          They'll see a prompt next time they open Fira.
        </p>
        <div className="np-actions">
          <button className="btn" onClick={close} disabled={submitting}>Close</button>
          <button
            className="btn np-danger"
            onClick={() => guarded(async () => { await cancelLink(link.id); close(); })}
            disabled={submitting}
          >
            Cancel request
          </button>
        </div>
      </div>
    );
  } else {
    // accepted
    body = (
      <div className="np-body link-state-card">
        <p className="link-headline">
          Linked with <strong>{partner?.name ?? 'another account'}</strong>.
        </p>
        <p className="np-hint">
          Their tasks and time blocks show on your calendar (read-only) when
          "Show linked" is on. Either of you can unlink at any time.
        </p>
        <div className="np-actions">
          <button className="btn" onClick={close} disabled={submitting}>Close</button>
          <button
            className="btn np-danger"
            onClick={() => guarded(async () => { await cancelLink(link.id); close(); })}
            disabled={submitting}
          >
            Unlink
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="modal-backdrop" onClick={close}>
      <div className="modal np-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ext">Link account</span>
          <span className="grow" />
          <button className="icon-btn" onClick={close} title="Close (Esc)">×</button>
        </div>
        {body}
        {error && <div className="np-error" style={{ margin: '0 16px 12px' }}>{error}</div>}
      </div>
    </div>
  );
}

interface PickerViewProps {
  users: User[];
  meId: UUID | null;
  workspaceMemberIds: Set<UUID>;
  submitting: boolean;
  onPick: (id: UUID) => Promise<void> | void;
}

function PickerView({ users, meId, workspaceMemberIds, submitting, onPick }: PickerViewProps) {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    requestAnimationFrame(() => inputRef.current?.focus());
  }, []);

  // Picker is scoped to the active workspace's members. Email invites
  // land in a future sprint — for now, the workspace owner adds the
  // "personal" account first, then the user requests a link from there.
  const candidates = useMemo(() => {
    const q = query.trim().toLowerCase();
    return users.filter((u) => {
      if (u.id === meId) return false;
      if (!workspaceMemberIds.has(u.id)) return false;
      if (!q) return true;
      return u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
    });
  }, [users, meId, workspaceMemberIds, query]);

  return (
    <div className="np-body">
      <p className="link-headline" style={{ marginTop: 0 }}>
        Pair this account with another one of yours.
      </p>
      <p className="np-hint" style={{ marginBottom: 12 }}>
        Pick someone in this workspace. Once they accept, both of you will see
        the other's tasks and time blocks on the calendar (read-only).
      </p>
      <input
        ref={inputRef}
        className="user-search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search workspace members…"
      />
      <div className="np-members-candidates link-candidates">
        {candidates.length === 0 ? (
          <div className="user-empty">
            {workspaceMemberIds.size <= 1
              ? "You're the only one here. Ask the workspace owner to add the other account."
              : 'No matches.'}
          </div>
        ) : candidates.map((u) => (
          <button
            key={u.id}
            type="button"
            className="user-row"
            onClick={() => { void onPick(u.id); }}
            disabled={submitting}
          >
            <span className="avatar">{u.initials}</span>
            <span className="user-row-name">{u.name}</span>
            <span className="user-row-email">{u.email}</span>
            <Plus size={13} strokeWidth={1.75} className="link-row-send" />
          </button>
        ))}
      </div>
    </div>
  );
}
