import { useEffect, useState } from 'react';
import { Calendar, Link, Ticket, X } from 'lucide-react';
import { useFira } from '../store';
import { api, gcalConnectUrl, loginUrl } from '../api';
import type { AccountSummary, Theme, UiStyle } from '../types';

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
  const jiraConnected = useFira((s) => s.jiraConnected);
  const jiraEmail = useFira((s) => s.jiraEmail);
  const jiraAutoSyncNewBlocks = useFira((s) => s.jiraAutoSyncNewBlocks);
  const connectJira = useFira((s) => s.connectJira);
  const disconnectJira = useFira((s) => s.disconnectJira);
  const setJiraAutoSync = useFira((s) => s.setJiraAutoSync);
  // Jira is scoped to the active workspace (site URL lives on the
  // workspace, not the account) — the section title and gating below key
  // off whichever workspace the user is currently in.
  const activeWorkspace = useFira((s) => s.workspaces.find((w) => w.id === s.activeWorkspaceId));
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
            time blocks show on your calendar (read-only) when it's set to "Everywhere".
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

          <Section title={`Jira${activeWorkspace ? ` — ${activeWorkspace.title}` : ''}`}>
            <JiraSection
              siteConfigured={!!activeWorkspace?.jira_site_url}
              connected={jiraConnected}
              email={jiraEmail}
              autoSyncNewBlocks={jiraAutoSyncNewBlocks}
              playgroundMode={playgroundMode}
              onConnect={connectJira}
              onDisconnect={disconnectJira}
              onSetAutoSync={setJiraAutoSync}
            />
          </Section>

          <Section title="Mode badge">
            <div className="account-row">
              <BadgePicker />
              <p className="account-row-text account-row-muted">
                Shown next to your avatar in the top bar.
              </p>
            </div>
          </Section>

          <Section title="Appearance">
            <div className="account-row">
              <ThemePicker />
              <p className="account-row-text account-row-muted">
                Color palette.
              </p>
            </div>
            <div className="account-row">
              <StylePicker />
              <p className="account-row-text account-row-muted">
                Modern rounds the corners, softens the shadows and gives
                everything more room.
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

// Jira connect/disconnect. Unlike the gcal section this is a plain form,
// not a redirect — Jira Cloud's REST API takes a per-user email + API
// token (Basic Auth), so "connecting" is just validating and storing that
// pair server-side (see docs/sprints/28-jira-integration-base.md).
interface JiraSectionProps {
  siteConfigured: boolean;
  connected: boolean;
  email: string | null;
  autoSyncNewBlocks: boolean;
  playgroundMode: boolean;
  onConnect: (email: string, apiToken: string) => Promise<void>;
  onDisconnect: () => Promise<void>;
  onSetAutoSync: (enabled: boolean) => Promise<void>;
}

function JiraSection({
  siteConfigured, connected, email, autoSyncNewBlocks, playgroundMode, onConnect, onDisconnect, onSetAutoSync,
}: JiraSectionProps) {
  const [formEmail, setFormEmail] = useState('');
  const [apiToken, setApiToken] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!siteConfigured) {
    return (
      <p className="account-row-text account-row-muted">
        This workspace hasn't configured a Jira site yet. Ask the workspace owner to
        set one in workspace settings.
      </p>
    );
  }

  if (connected) {
    return (
      <div className="account-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
        <div className="account-row" style={{ padding: 0 }}>
          <button
            className="btn account-stub-btn"
            onClick={() => { void onDisconnect(); }}
            disabled={playgroundMode}
            title={playgroundMode ? 'Not available in playground' : 'Disconnect Jira'}
          >
            <Ticket size={13} strokeWidth={1.75} /> Disconnect
          </button>
          <p className="account-row-text account-row-muted">
            Connected{email ? <> as <strong>{email}</strong></> : null}. Time you log against a
            Jira-linked task can be pushed there once that lands.
          </p>
        </div>
        <div className="account-toggle-row">
          <span className="account-section-h">Auto Sync New Blocks</span>
          <div
            className="list-tag-filter-mode"
            role="group"
            aria-label="Auto sync new blocks"
            title={playgroundMode
              ? 'Not available in playground'
              : 'Automatically log new time blocks on Jira-linked tasks, instead of waiting for the manual "Log to Jira" click'}
          >
            <button
              type="button"
              className="list-tag-filter-mode-seg"
              data-active={autoSyncNewBlocks || undefined}
              onClick={() => { void onSetAutoSync(true); }}
              disabled={playgroundMode}
            >
              on
            </button>
            <button
              type="button"
              className="list-tag-filter-mode-seg"
              data-active={!autoSyncNewBlocks || undefined}
              onClick={() => { void onSetAutoSync(false); }}
              disabled={playgroundMode}
            >
              off
            </button>
          </div>
        </div>
      </div>
    );
  }

  const trimmedEmail = formEmail.trim();
  const trimmedToken = apiToken.trim();
  // Only submitting/playground blocks the button itself — a missing
  // email or token is instead caught in `submit` with a visible error,
  // rather than leaving the button silently disabled with no explanation.
  const submitDisabled = submitting || playgroundMode;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitDisabled) return;
    if (!trimmedEmail || !trimmedToken) {
      setError('Enter both your email and API token to connect.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onConnect(trimmedEmail, trimmedToken);
      setApiToken('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="account-row" onSubmit={submit} style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
      <p className="account-row-text account-row-muted" style={{ margin: 0 }}>
        Connect your own Jira account with an API token from{' '}
        <strong>id.atlassian.com/manage-profile/security/api-tokens</strong>. Per-user, on
        purpose — Jira attributes logged time to whoever's token made the call.
      </p>
      <input
        className="user-search"
        type="email"
        autoComplete="email"
        spellCheck={false}
        value={formEmail}
        onChange={(e) => setFormEmail(e.target.value)}
        placeholder="you@example.com"
        disabled={playgroundMode || submitting}
      />
      <input
        className="user-search"
        type="password"
        autoComplete="off"
        spellCheck={false}
        value={apiToken}
        onChange={(e) => setApiToken(e.target.value)}
        placeholder="API token"
        disabled={playgroundMode || submitting}
      />
      <button
        type="submit"
        className="btn account-stub-btn"
        disabled={submitDisabled}
        title={playgroundMode ? 'Not available in playground' : 'Connect Jira'}
      >
        <Ticket size={13} strokeWidth={1.75} /> {submitting ? 'Connecting…' : 'Connect'}
      </button>
      {error && <p className="account-row-text account-row-warn" style={{ margin: 0 }}>{error}</p>}
    </form>
  );
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
// the list `or/and` and `me/all` pills, scoped to the account modal.
// Three states — none (clear), personal, work — so the user can opt
// out entirely without hiding the control.
function BadgePicker() {
  const value = useFira((s) => s.accountBadge);
  const setBadge = useFira((s) => s.setAccountBadge);
  return (
    <div
      className="list-tag-filter-mode account-badge-picker"
      role="group"
      aria-label="Mode badge"
    >
      <button
        type="button"
        className="list-tag-filter-mode-seg"
        data-active={value === null || undefined}
        onClick={() => setBadge(null)}
        title="No badge"
      >
        none
      </button>
      <button
        type="button"
        className="list-tag-filter-mode-seg"
        data-active={value === 'personal' || undefined}
        onClick={() => setBadge('personal')}
        title="Personal mode"
      >
        personal
      </button>
      <button
        type="button"
        className="list-tag-filter-mode-seg"
        data-active={value === 'work' || undefined}
        onClick={() => setBadge('work')}
        title="Work mode"
      >
        work
      </button>
    </div>
  );
}

// Generic segmented-choice control. Same visual idiom as BadgePicker
// above, reused here for any small enumerated account preference.
// `options` order is render order.
function SegmentedPicker<T extends string>({
  value, options, onChange, ariaLabel, className,
}: {
  value: T;
  options: { value: T; label: string; title?: string }[];
  onChange: (v: T) => void;
  ariaLabel: string;
  className?: string;
}) {
  return (
    <div
      className={`list-tag-filter-mode${className ? ` ${className}` : ''}`}
      role="group"
      aria-label={ariaLabel}
    >
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          className="list-tag-filter-mode-seg"
          data-active={value === opt.value || undefined}
          onClick={() => onChange(opt.value)}
          title={opt.title ?? opt.label}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

// Theme picker — the *palette* axis. Pairs with StylePicker below, which
// owns the orthogonal shape/density axis; the two combine freely.
function ThemePicker() {
  const value = useFira((s) => s.theme);
  const setTheme = useFira((s) => s.setTheme);
  return (
    <SegmentedPicker<Theme>
      className="account-theme-picker"
      ariaLabel="Theme"
      value={value}
      onChange={setTheme}
      options={[
        { value: 'classic', label: 'classic', title: 'Classic (paper white)' },
        { value: 'dark', label: 'dark', title: 'Dark' },
      ]}
    />
  );
}

// Style picker — the shape/density axis: square + compact (classic) vs
// rounded + soft-shadowed + roomier (modern). Independent of the theme,
// so e.g. dark + modern is a valid combination.
function StylePicker() {
  const value = useFira((s) => s.uiStyle);
  const setUiStyle = useFira((s) => s.setUiStyle);
  return (
    <SegmentedPicker<UiStyle>
      className="account-theme-picker"
      ariaLabel="Style"
      value={value}
      onChange={setUiStyle}
      options={[
        { value: 'classic', label: 'classic', title: 'Classic (square, compact)' },
        { value: 'modern', label: 'modern', title: 'Modern (rounded, soft, roomy)' },
      ]}
    />
  );
}
