import { Link2 } from 'lucide-react';
import { useFira } from '../store';
import { weekStartFor, fmtWeekRange } from '../time';
import { ProjectIcon } from './ProjectIcon';
import { SyncPill } from './SyncPill';
import { WorkspaceSwitcher } from './WorkspaceSwitcher';

export function TopBar() {
  const view = useFira((s) => s.view);
  const project = useFira((s) =>
    s.projects.find((p) => p.id === s.inboxFilter.project_id) ?? null
  );
  const weekOffset = useFira((s) => s.weekOffset);
  const logout = useFira((s) => s.logout);
  const me = useFira((s) => s.users.find((u) => u.id === s.meId) ?? null);
  const playgroundMode = useFira((s) => s.playgroundMode);
  // Pick the most "actionable" link to drive the icon's state. Order:
  // received (call to action) > sent (waiting) > accepted (settled) > none.
  const linkState = useFira((s) => {
    const received = s.links.find((l) => l.direction === 'received' && l.status === 'pending');
    if (received) return { kind: 'received' as const, link: received };
    const sent = s.links.find((l) => l.direction === 'sent' && l.status === 'pending');
    if (sent) return { kind: 'sent' as const, link: sent };
    const accepted = s.links.find((l) => l.status === 'accepted');
    if (accepted) return { kind: 'accepted' as const, link: accepted };
    return { kind: 'none' as const };
  });
  const partner = useFira((s) => {
    const accepted = s.links.find((l) => l.status === 'accepted');
    return accepted ? s.users.find((u) => u.id === accepted.partner_id) ?? null : null;
  });
  const openLinkModal = useFira((s) => s.openLinkModal);

  const title = view === 'calendar'
    ? `Week of ${fmtWeekRange(weekStartFor(weekOffset))}`
    : project?.title ?? 'Inbox';

  const linkTitle = linkState.kind === 'received'
    ? 'Someone wants to link calendars with you'
    : linkState.kind === 'sent'
      ? 'Waiting for the other account to accept'
      : linkState.kind === 'accepted'
        ? `Linked${partner ? ` with ${partner.name}` : ''}`
        : 'Link another account';

  return (
    <div className="topbar">
      <span className="crumb">Fira</span>
      <span className="crumb-sep">/</span>
      <WorkspaceSwitcher />
      <span className="crumb-sep">/</span>
      {view === 'inbox' && project && (
        <ProjectIcon
          name={project.icon}
          color={project.color}
          size={13}
          className="title-icon"
        />
      )}
      <span className="title">{title}</span>
      <div className="grow" />
      {playgroundMode && (
        <span
          className="playground-pill"
          title="Playground mode — changes saved only in this browser"
        >
          Playground
        </span>
      )}
      <SyncPill />
      <button
        className="link-btn"
        data-state={linkState.kind}
        onClick={() => openLinkModal()}
        title={linkTitle}
        aria-label={linkTitle}
      >
        <Link2 size={13} strokeWidth={1.75} />
        {linkState.kind === 'accepted' && partner && (
          <span className="link-btn-initials">{partner.initials}</span>
        )}
      </button>
      <button className="logout-btn" onClick={() => logout()} title="Sign out">
        Log out
      </button>
      <div className="topbar-me" title={me?.name ?? ''}>{me?.initials ?? '?'}</div>
    </div>
  );
}
