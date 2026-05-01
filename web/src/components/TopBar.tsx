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

  const title = view === 'calendar'
    ? `Week of ${fmtWeekRange(weekStartFor(weekOffset))}`
    : project?.title ?? 'Inbox';

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
      <button className="logout-btn" onClick={() => logout()} title="Sign out">
        Log out
      </button>
      <div className="topbar-me" title={me?.name ?? ''}>{me?.initials ?? '?'}</div>
    </div>
  );
}
