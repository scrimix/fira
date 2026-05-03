import { Link, Menu } from 'lucide-react';
import { useFira } from '../store';
import { weekStartFor, fmtWeekRange } from '../time';
import { useIsMobile } from '../hooks';
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
  // Derived outside the selector so the result identity is stable across
  // unrelated store updates — useSyncExternalStore otherwise treats a fresh
  // object literal as a store change and infinite-loops.
  const links = useFira((s) => s.links);
  const users = useFira((s) => s.users);
  const linkState = (() => {
    const received = links.find((l) => l.direction === 'received' && l.status === 'pending');
    if (received) return { kind: 'received' as const, link: received };
    const sent = links.find((l) => l.direction === 'sent' && l.status === 'pending');
    if (sent) return { kind: 'sent' as const, link: sent };
    const accepted = links.find((l) => l.status === 'accepted');
    if (accepted) return { kind: 'accepted' as const, link: accepted };
    return { kind: 'none' as const };
  })();
  const partner = linkState.kind === 'accepted'
    ? users.find((u) => u.id === linkState.link.partner_id) ?? null
    : null;
  const openLinkModal = useFira((s) => s.openLinkModal);
  const setSidebarOpen = useFira((s) => s.setSidebarOpen);
  const sidebarOpen = useFira((s) => s.sidebarOpen);

  const isMobile = useIsMobile();

  // The calendar's own toolbar (prev / today / next + day-of-month numbers)
  // already tells the user what range they're looking at. On phones we
  // suppress the topbar week title to claw back horizontal room — only the
  // inbox title still appears.
  const title = view === 'calendar'
    ? isMobile
      ? ''
      : `Week of ${fmtWeekRange(weekStartFor(weekOffset))}`
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
      {isMobile ? (
        <button
          className="topbar-menu"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          title="Menu"
          aria-label="Menu"
        >
          <Menu size={18} strokeWidth={1.75} />
        </button>
      ) : (
        <>
          <span className="crumb">Fira</span>
          <span className="crumb-sep">/</span>
        </>
      )}
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
      {title && <span className="title">{title}</span>}
      <div className="grow" />
      {playgroundMode && !isMobile && (
        <span
          className="playground-pill"
          title="Playground mode — changes saved only in this browser"
        >
          Playground
        </span>
      )}
      <SyncPill />
      <button className="logout-btn" onClick={() => logout()} title="Sign out">
        Log out
      </button>

      {!isMobile && (
        <>
          {linkState.kind === 'accepted' && partner ?
            (<span className="topbar-me" title={partner.name}>{partner.initials}</span>) : null
          }
          <button
              className="link-pair"
              onClick={() => openLinkModal()}
              title={linkTitle}
              aria-label={linkTitle}
            >
              <Link size={12} strokeWidth={1.75} className="link-pair-icon" />
          </button>
          <span className="topbar-me" title={me?.name ?? ''}>{me?.initials ?? '?'}</span>
        </>
      )}
    </div>
  );
}
