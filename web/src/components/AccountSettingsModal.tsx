import { useEffect, useState } from 'react';
import { Calendar, Link, X } from 'lucide-react';
import { useFira } from '../store';
import { api, gcalConnectUrl, loginUrl } from '../api';
import type { AccountSummary } from '../types';

// Account settings: container for personal-account stuff that isn't
// workspace-scoped. Replaces the topbar's two-avatar + link-button
// cluster — the user clicks their own avatar in the topbar to open
// this. Today it surfaces the linked-account affordance and a stubbed
// Google Calendar row; future homes for personal preferences land in
// here too.
export function AccountSettingsModal() {
  const close = useFira((s) => s.closeAccountModal);
  const openLink = useFira((s) => s.openLinkModal);
  const logout = useFira((s) => s.logout);
  const switchToAccount = useFira((s) => s.switchToAccount);
  const signOutEverywhere = useFira((s) => s.signOutEverywhere);
  const me = useFira((s) => s.users.find((u) => u.id === s.meId) ?? null);
  const meId = useFira((s) => s.meId);
  const links = useFira((s) => s.links);
  const users = useFira((s) => s.users);
  const gcalConnected = useFira((s) => s.gcalConnected);
  const gcalEmail = useFira((s) => s.gcalEmail);
  const gcalLastSyncError = useFira((s) => s.gcalLastSyncError);
  const disconnectGcal = useFira((s) => s.disconnectGcal);
  const playgroundMode = useFira((s) => s.playgroundMode);
  // The linked partner with a live session in this browser's group, if
  // any. Server-side `/auth/accounts` already requires both gates
  // (accepted link + same session group), so this is at most one user
  // — `user_links` enforces one accepted link per account. Drives the
  // "Switch to {linked}" button next to the Linked account row;
  // absent ⇒ no button (user can still log out and back in via Google).
  const [switchTarget, setSwitchTarget] = useState<AccountSummary | null>(null);
  const [switching, setSwitching] = useState(false);
  // dev_auth enables the local fixture login (Maya). When it's on we
  // also expose an "Add Maya (dev)" button so devs can pair the local
  // fixture with a real Google account without leaving the modal.
  const [devAuth, setDevAuth] = useState(false);
  const [addingDev, setAddingDev] = useState(false);
  useEffect(() => {
    if (playgroundMode) return;
    let cancelled = false;
    api
      .listAccounts()
      .then((rows) => {
        if (cancelled) return;
        setSwitchTarget(rows.find((a) => a.user_id !== meId) ?? null);
      })
      .catch(() => {
        // Switching is an optimization on top of the link feature —
        // silently degrade if the lookup fails. The link itself
        // still works (calendars overlay) regardless.
      });
    api
      .authConfig()
      .then((c) => {
        if (!cancelled) setDevAuth(c.dev_auth);
      })
      .catch(() => { /* prod posture if config fails */ });
    return () => { cancelled = true; };
  }, [playgroundMode, meId]);
  const onSwitch = async () => {
    if (!switchTarget || switching) return;
    setSwitching(true);
    try {
      await switchToAccount(switchTarget.user_id);
      // Hard-reloads on success — no need to clear `switching`.
    } catch {
      // Sibling session was revoked from another device between the
      // picker load and the click. Fall back to a full logout so the
      // user lands on the login screen and can re-auth normally.
      setSwitching(false);
      setSwitchTarget(null);
      void logout();
    }
  };
  const onAddMaya = async () => {
    if (addingDev) return;
    setAddingDev(true);
    try {
      // Same opaque-redirect pattern as the login screen: dev-login
      // sets a fresh `sid` (overwriting the current one) and 302s to
      // the app root. The previous user's session row is preserved
      // and joined to the same `sg` group, so the picker on the next
      // load sees both. Hard-reload after to re-hydrate as Maya.
      const res = await api.devLogin('maya@fira.dev');
      if (!res.ok && res.type !== 'opaqueredirect') {
        throw new Error(`dev-login failed (${res.status})`);
      }
      window.location.assign('/');
    } catch {
      setAddingDev(false);
    }
  };
  // Server stores the error with a kind prefix; the UI only branches
  // on `invalid_grant:` (Reconnect needed) vs anything else (transient,
  // muted retry hint).
  const reconnectNeeded =
    gcalConnected && (gcalLastSyncError ?? '').startsWith('invalid_grant');
  const transientError =
    gcalConnected && !!gcalLastSyncError && !reconnectNeeded;

  // Same priority order as the (former) topbar icon: most actionable first.
  const linkState = (() => {
    const received = links.find((l) => l.direction === 'received' && l.status === 'pending');
    if (received) return { kind: 'received' as const, link: received };
    const sent = links.find((l) => l.direction === 'sent' && l.status === 'pending');
    if (sent) return { kind: 'sent' as const, link: sent };
    const accepted = links.find((l) => l.status === 'accepted');
    if (accepted) return { kind: 'accepted' as const, link: accepted };
    return { kind: 'none' as const };
  })();
  const partner = linkState.kind === 'none'
    ? null
    : users.find((u) => u.id === linkState.link.partner_id) ?? null;

  const linkBody = (() => {
    switch (linkState.kind) {
      case 'received':
        return (
          <>
            <strong>{partner?.name ?? 'Someone'}</strong> wants to link calendars with you.
            Open the prompt to accept or decline.
          </>
        );
      case 'sent':
        return (
          <>
            Waiting for <strong>{partner?.name ?? 'the other account'}</strong> to accept the link
            request. They'll see a prompt next time they open Fira.
          </>
        );
      case 'accepted':
        return (
          <>
            Linked with <strong>{partner?.name ?? 'another account'}</strong>. Their tasks and
            time blocks show on your calendar (read-only) when "Show linked" is on.
          </>
        );
      case 'none':
      default:
        return (
          <>
            Pair this account with another so you each see the other's tasks and time blocks
            on the calendar (read-only). Either side can unlink at any time.
          </>
        );
    }
  })();

  const linkBtnTitle = linkState.kind === 'received'
    ? 'Someone wants to link calendars with you'
    : linkState.kind === 'sent'
      ? 'Waiting for the other account to accept'
      : linkState.kind === 'accepted'
        ? `Linked${partner ? ` with ${partner.name}` : ''}`
        : 'Link another account';

  return (
    <div className="modal-backdrop" onClick={close}>
      <div className="modal np-modal account-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ext">Account</span>
          <span className="grow" />
          <button className="icon-btn" onClick={close} title="Close (Esc)" aria-label="Close">
            <X size={15} strokeWidth={1.75} />
          </button>
        </div>
        <div className="np-body account-body">
          {me && (
            <div className="account-identity">
              <span className="avatar account-identity-ava" data-me="true">{me.initials}</span>
              <div className="account-identity-text">
                <div className="account-identity-name">{me.name}</div>
                <div className="account-identity-email">{me.email}</div>
              </div>
            </div>
          )}

          <Section title="Linked account">
            <div className="account-row">
              <button
                className="link-pair account-link-btn"
                data-state={linkState.kind}
                onClick={() => { close(); openLink(); }}
                title={linkBtnTitle}
                aria-label={linkBtnTitle}
              >
                <Link size={14} strokeWidth={1.75} className="link-pair-icon" />
                {partner && (
                  <span className="account-link-partner" title={partner.name}>
                    {partner.initials}
                  </span>
                )}
              </button>
              <p className="account-row-text">{linkBody}</p>
              {switchTarget && linkState.kind === 'accepted' && (
                <button
                  type="button"
                  className="btn account-switch-btn"
                  onClick={onSwitch}
                  disabled={switching}
                  title={`Switch to ${switchTarget.email}`}
                >
                  {switching ? 'Switching…' : `Switch to ${switchTargetLabel(switchTarget)}`}
                </button>
              )}
            </div>
            {/* When the link is accepted but the partner has no live
                session in this browser's group, the Switch button can't
                appear (the server-side gate fails). Surface a primer
                that points the user at "Add another account" so they
                can enroll the partner's session without logging out. */}
            {linkState.kind === 'accepted' && !switchTarget && !playgroundMode && (
              <p className="account-row-text account-row-muted account-row-hint">
                Sign in to your linked account from here (without logging out
                first) to enable instant switching.
              </p>
            )}
            {!playgroundMode && (
              <div className="account-add-row">
                <a
                  className="btn account-add-account"
                  href={loginUrl}
                  title="Sign in to another Google account on this device — keeps the current session alive so you can switch between them"
                >
                  Add Google account
                </a>
                {devAuth && me?.email !== 'maya@fira.dev' && (
                  <button
                    type="button"
                    className="btn account-add-account"
                    onClick={onAddMaya}
                    disabled={addingDev}
                    title="Sign in as the Maya fixture on this device (dev only)"
                  >
                    {addingDev ? 'Adding…' : 'Add Maya (dev)'}
                  </button>
                )}
              </div>
            )}
          </Section>

          <Section title="Google Calendar">
            <div className="account-row">
              {reconnectNeeded ? (
                <a
                  className="btn account-stub-btn"
                  href={playgroundMode ? undefined : gcalConnectUrl}
                  aria-disabled={playgroundMode || undefined}
                  data-disabled={playgroundMode || undefined}
                  title={playgroundMode ? 'Not available in playground' : 'Reconnect Google Calendar'}
                  onClick={(e) => { if (playgroundMode) e.preventDefault(); }}
                >
                  <Calendar size={13} strokeWidth={1.75} /> Reconnect
                </a>
              ) : gcalConnected ? (
                <button
                  className="btn account-stub-btn"
                  onClick={() => { void disconnectGcal(); }}
                  disabled={playgroundMode}
                  title={playgroundMode ? 'Not available in playground' : 'Disconnect Google Calendar'}
                >
                  <Calendar size={13} strokeWidth={1.75} /> Disconnect
                </button>
              ) : (
                <a
                  className="btn account-stub-btn"
                  href={playgroundMode ? undefined : gcalConnectUrl}
                  aria-disabled={playgroundMode || undefined}
                  data-disabled={playgroundMode || undefined}
                  title={playgroundMode ? 'Not available in playground' : 'Connect Google Calendar'}
                  onClick={(e) => { if (playgroundMode) e.preventDefault(); }}
                >
                  <Calendar size={13} strokeWidth={1.75} /> Connect
                </a>
              )}
              <div className="account-row-text-stack">
                {reconnectNeeded ? (
                  <p className="account-row-text account-row-warn">
                    Reconnect needed — your Google session expired
                    {gcalEmail ? <> ({gcalEmail})</> : null}. Click Reconnect to grant access again.
                  </p>
                ) : transientError ? (
                  <p className="account-row-text account-row-muted">
                    Connected{gcalEmail ? <> as <strong>{gcalEmail}</strong></> : null}. Last sync
                    didn't go through — we'll retry on the next refresh.
                  </p>
                ) : gcalConnected ? (
                  <p className="account-row-text account-row-muted">
                    Connected{gcalEmail ? <> as <strong>{gcalEmail}</strong></> : null}. Events
                    show on the calendar alongside your time blocks. Click an event for details.
                  </p>
                ) : (
                  <>
                    <p className="account-row-text account-row-muted">
                      Show your Google Calendar events alongside Fira time blocks (read-only).
                    </p>
                    <p className="account-row-text account-row-muted account-row-hint">
                      Heads up: while we're in Google's review queue, you may need to reconnect
                      every 7 days.
                    </p>
                  </>
                )}
              </div>
            </div>
          </Section>

          <Section title="Mode badge">
            <div className="account-row">
              <BadgePicker />
              <p className="account-row-text account-row-muted">
                Shown next to your avatar in the top bar.
              </p>
            </div>
          </Section>

          <div className="np-actions account-actions">
            <button className="btn np-danger" onClick={() => { close(); logout(); }}>
              Log out
            </button>
            {switchTarget && !playgroundMode && (
              <button
                type="button"
                className="btn account-signout-all"
                onClick={() => { close(); void signOutEverywhere(); }}
                title="Sign out of every linked account on this device"
              >
                Sign out everywhere
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Same vocabulary the Login picker uses: prefer the personal/work
// badge over the user's name when present, so "Switch to Personal" /
// "Switch to Work" reads consistently in both places. Falls back to
// the human name for accounts that haven't picked a badge.
function switchTargetLabel(a: AccountSummary): string {
  if (a.account_badge === 'personal') return 'Personal';
  if (a.account_badge === 'work') return 'Work';
  return a.name;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="account-section">
      <h5 className="account-section-h">{title}</h5>
      {children}
    </div>
  );
}

// Segmented picker for the personal/work badge. Same visual idiom as
// the inbox `or/and` and `me/all` pills, scoped to the account modal.
// Three states — none (clear), personal, work — so the user can opt
// out entirely without hiding the control.
function BadgePicker() {
  const value = useFira((s) => s.accountBadge);
  const setBadge = useFira((s) => s.setAccountBadge);
  return (
    <div
      className="inbox-tag-filter-mode account-badge-picker"
      role="group"
      aria-label="Mode badge"
    >
      <button
        type="button"
        className="inbox-tag-filter-mode-seg"
        data-active={value === null || undefined}
        onClick={() => setBadge(null)}
        title="No badge"
      >
        none
      </button>
      <button
        type="button"
        className="inbox-tag-filter-mode-seg"
        data-active={value === 'personal' || undefined}
        onClick={() => setBadge('personal')}
        title="Personal mode"
      >
        personal
      </button>
      <button
        type="button"
        className="inbox-tag-filter-mode-seg"
        data-active={value === 'work' || undefined}
        onClick={() => setBadge('work')}
        title="Work mode"
      >
        work
      </button>
    </div>
  );
}
