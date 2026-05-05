import { Menu } from 'lucide-react';
import { useFira } from '../store';
import { weekStartFor, fmtWeekRange } from '../time';
import { useIsMobile } from '../hooks';
import { ProjectIcon } from './ProjectIcon';
import { SyncPill, RefreshButton } from './SyncPill';
import { WorkspaceSwitcher } from './WorkspaceSwitcher';

export function TopBar() {
  const view = useFira((s) => s.view);
  const project = useFira((s) =>
    s.projects.find((p) => p.id === s.inboxFilter.project_id) ?? null
  );
  const weekOffset = useFira((s) => s.weekOffset);
  const me = useFira((s) => s.users.find((u) => u.id === s.meId) ?? null);
  const playgroundMode = useFira((s) => s.playgroundMode);
  const accountBadge = useFira((s) => s.accountBadge);
  const openAccountModal = useFira((s) => s.openAccountModal);
  const setSidebarOpen = useFira((s) => s.setSidebarOpen);
  const sidebarOpen = useFira((s) => s.sidebarOpen);

  const isMobile = useIsMobile();

  // The calendar's own toolbar (prev / today / next + day-of-month numbers)
  // already tells the user what range they're looking at, and the inbox's
  // own page header repeats the project title above the task list. On
  // phones we suppress the topbar title in both views to claw back
  // horizontal room — without it the Log out button was getting pushed
  // off-screen on narrow widths.
  const title = isMobile
    ? ''
    : view === 'calendar'
      ? `Week of ${fmtWeekRange(weekStartFor(weekOffset))}`
      : project?.title ?? 'Inbox';

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
      {view === 'inbox' && project && !isMobile && (
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
      <RefreshButton />
      <SyncPill />
      {/* Own-user chip is the entry point to the account settings modal,
       * which now hosts the link affordance, gcal connection (stubbed),
       * preferences, and Log out. Replaces the previous two-avatar +
       * link button cluster. The mode badge (personal/work, optional)
       * sits ahead of the avatar as a compact one-letter chip. */}
      {/* Badge + avatar live in one wrapper so the topbar's flex `gap`
       * doesn't pry them apart — they should read as one paired chip
       * the way the link-pair used to. */}
      <div className="topbar-account">
        {accountBadge && (
          <span
            className="topbar-badge"
            data-mode={accountBadge}
            title={accountBadge === 'personal' ? 'Personal mode' : 'Work mode'}
            aria-label={accountBadge === 'personal' ? 'Personal mode' : 'Work mode'}
          >
            {accountBadge === 'personal' ? 'P' : 'W'}
          </span>
        )}
        <button
          className="topbar-me topbar-me-btn"
          onClick={() => openAccountModal()}
          title={me?.name ? `Account · ${me.name}` : 'Account'}
          aria-label="Account settings"
        >
          {me?.initials ?? '?'}
        </button>
      </div>
    </div>
  );
}
