import { useState } from 'react';
import { useFira } from '../store';
import type { WorkspaceInvite } from '../types';

// Sticky receive-side modal for a workspace invite. Same shape as the
// account-link modal's "received pending" state but simpler — joining a
// workspace is a clear, low-risk action so there's no privacy warning,
// just Accept / Decline.
//
// The modal is mounted whenever the user has at least one received
// pending invite; closing it requires Accept or Decline (no `Esc`,
// no backdrop dismiss). If multiple pending invites exist they're
// shown one at a time, oldest first.

export function WorkspaceInviteModal({ invite }: { invite: WorkspaceInvite }) {
  const acceptWorkspaceInvite = useFira((s) => s.acceptWorkspaceInvite);
  const declineWorkspaceInvite = useFira((s) => s.declineWorkspaceInvite);
  const showToast = useFira((s) => s.showToast);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const guarded = async (fn: () => Promise<void>, kind: 'accept' | 'decline') => {
    setSubmitting(true);
    setError(null);
    try {
      await fn();
      // showToast's default kind is `error` (red); pass `info` for the
      // success path so a successful Accept / Decline reads as the
      // confirmation it is, not as a failure.
      showToast(
        kind === 'accept'
          ? `Joined ${invite.workspace_title}`
          : `Declined invite to ${invite.workspace_title}`,
        'info',
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed';
      setError(msg);
      showToast(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.stopPropagation()}>
      <div className="modal np-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ext">Workspace invite</span>
          <span className="grow" />
        </div>
        <div className="np-body link-state-card">
          <p className="link-headline">
            <strong>{invite.invited_by_name}</strong> invited you to join{' '}
            <strong>{invite.workspace_title}</strong>.
          </p>
          <p className="np-hint">
            You'll be added as a {invite.role}. You can leave the workspace at
            any time, and {invite.invited_by_name} can remove you from the
            members list.
          </p>
          {error && <div className="np-error">{error}</div>}
          <div className="np-actions">
            <button
              className="btn"
              onClick={() => void guarded(() => declineWorkspaceInvite(invite.id), 'decline')}
              disabled={submitting}
            >
              Decline
            </button>
            <button
              className="btn np-create"
              onClick={() => void guarded(() => acceptWorkspaceInvite(invite.id), 'accept')}
              disabled={submitting}
            >
              Accept
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
