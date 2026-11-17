import { Menu } from 'lucide-react';
import { useFira } from '../store';
import { weekStartFor, fmtWeekRange, fmtWeekSpan, fmtMonth } from '../time';
import { useIsMobile } from '../hooks';
import { SyncPill, RefreshButton } from './SyncPill';
import { WorkspaceSwitcher } from './WorkspaceSwitcher';

export function TopBar() {
  const view = useFira((s) => s.view);
  const weekOffset = useFira((s) => s.weekOffset);
  const monthOffset = useFira((s) => s.monthOffset);
  const planWeekOffset = useFira((s) => s.planWeekOffset);
  const planWeekCount = useFira((s) => s.planWeekCount);
  const me = useFira((s) => s.users.find((u) => u.id === s.meId) ?? null);
  const playgroundMode = useFira((s) => s.playgroundMode);
  const accountBadge = useFira((s) => s.accountBadge);
  const openAccountModal = useFira((s) => s.openAccountModal);
  const setSidebarOpen = useFira((s) => s.setSidebarOpen);
  const sidebarOpen = useFira((s) => s.sidebarOpen);

  const isMobile = useIsMobile();

  // Every page: its name, then (in grey) what it's showing.
  const page = { calendar: 'Calendar', list: 'List', plan: 'Plan', dashboard: 'Dashboard' }[view] ?? '';
  const detail = isMobile ? ''
    : view === 'calendar' ? fmtWeekRange(weekStartFor(weekOffset))
    : view === 'dashboard' ? fmtMonth(monthOffset)
    : view === 'plan' ? fmtWeekSpan(planWeekOffset, planWeekCount, { compact: true })
    : '';

  return (
    <div className="topbar" data-view={view}>
      {isMobile ? (
        <button
          className="topbar-menu"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          title="Menu"
          aria-label="Menu"
        >
          <Menu size={18} strokeWidth={1.75} />
        </button>
      ) : null}
      {!isMobile && (
        <span className="title topbar-period">
          {page}
          {detail && <span className="topbar-detail">{detail}</span>}
        </span>
      )}
      <div className="grow" />
      {/* Workspace lives with the other "where am I / who am I" controls
          on the right, not in a breadcrumb. */}
      <WorkspaceSwitcher />
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
