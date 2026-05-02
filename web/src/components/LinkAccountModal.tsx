import { useMemo, useState } from 'react';
import { useFira } from '../store';

// One modal serves four states, picked from `links`:
//   - none           → email input + "Send invite"
//   - sent (pending) → "Waiting for <Name>" + Cancel
//   - received (pending) → "<Name> wants to link" + Accept / Decline
//   - accepted       → "Linked with <Name>" + Unlink
//
// All four share the same shell (header / body / actions) so the modal
// frame doesn't pop between transitions while the user iterates.

export function LinkAccountModal() {
  const close = useFira((s) => s.closeLinkModal);
  const links = useFira((s) => s.links);
  const users = useFira((s) => s.users);
  const requestLink = useFira((s) => s.requestLink);
  const acceptLink = useFira((s) => s.acceptLink);
  const cancelLink = useFira((s) => s.cancelLink);
  const showToast = useFira((s) => s.showToast);

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
      <EmailInviteView
        submitting={submitting}
        onSend={(email) => guarded(async () => {
          await requestLink(email);
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

  // A pending received request is sticky — the modal pops on every tab /
  // refresh until the user accepts or declines, mirroring the server-side
  // row. Disable the dismiss affordances so neither X, Esc, nor the
  // backdrop can sweep it away.
  const sticky = link?.direction === 'received' && link.status === 'pending';
  return (
    <div className="modal-backdrop" onClick={sticky ? undefined : close}>
      <div className="modal np-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ext">Link account</span>
          <span className="grow" />
          {!sticky && (
            <button className="icon-btn" onClick={close} title="Close (Esc)">×</button>
          )}
        </div>
        {body}
        {error && <div className="np-error" style={{ margin: '0 16px 12px' }}>{error}</div>}
      </div>
    </div>
  );
}

interface EmailInviteViewProps {
  submitting: boolean;
  onSend: (email: string) => Promise<void> | void;
}

function EmailInviteView({ submitting, onSend }: EmailInviteViewProps) {
  const [email, setEmail] = useState('');
  const trimmed = email.trim();
  const canSend = trimmed.length > 0 && !submitting;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSend) return;
    void onSend(trimmed);
  };

  return (
    <form className="np-body" onSubmit={submit}>
      <p className="link-headline" style={{ marginTop: 0 }}>
        Pair this account with another one of yours.
      </p>
      <p className="np-hint" style={{ marginBottom: 12 }}>
        Type the email of your other account. Once they accept, both of you
        will see each other's tasks and time blocks on the calendar
        (read-only).
      </p>
      <input
        className="user-search"
        type="email"
        autoFocus
        autoComplete="email"
        spellCheck={false}
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="name@example.com"
      />
      <div className="np-actions" style={{ marginTop: 12 }}>
        <button type="button" className="btn" onClick={() => setEmail('')} disabled={submitting || !email}>
          Clear
        </button>
        <button type="submit" className="btn np-create" disabled={!canSend}>
          Send invite
        </button>
      </div>
    </form>
  );
}
