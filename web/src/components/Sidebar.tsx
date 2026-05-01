import { CalendarDays, Inbox, Settings } from 'lucide-react';
import { useFira } from '../store';
import { ProjectIcon } from './ProjectIcon';
import { BrandMark } from './BrandMark';

export function Sidebar() {
  const view = useFira((s) => s.view);
  const projects = useFira((s) => s.projects);
  const setView = useFira((s) => s.setView);
  const openCreateProject = useFira((s) => s.openCreateProject);
  const role = useFira((s) => s.myWorkspaceRole);
  const activeWorkspaceId = useFira((s) => s.activeWorkspaceId);
  const openEditWorkspace = useFira((s) => s.openEditWorkspace);
  // The "active project" is whichever one the inbox is filtered to. We only
  // surface the highlight while the inbox view is open — on the calendar,
  // every project is in scope simultaneously so a single-project highlight
  // would lie about the visible content.
  const activeProjectId = useFira((s) => s.inboxFilter.project_id);
  const showProjectActive = view === 'inbox';
  // Project create is owner-only. Leads administer existing projects
  // (rename, set members) but resource allocation — adding new projects
  // to a workspace — stays with the workspace owner.
  const canCreateProject = role === 'owner';
  const canEditWorkspace = role === 'owner';

  return (
    <div className="sidebar">
      <BrandMark className="brand" size={22} title="Fira" />
      <button className="nav-btn" data-active={view === 'calendar'}
              onClick={() => setView('calendar')} title="Calendar (G)">
        <CalendarDays size={16} strokeWidth={1.75} />
      </button>
      <button className="nav-btn" data-active={view === 'inbox'}
              onClick={() => setView('inbox')} title="Inbox (I)">
        <Inbox size={16} strokeWidth={1.75} />
      </button>
      <div style={{ height: 16 }} />
      {projects.map((p) => {
        const active = showProjectActive && p.id === activeProjectId;
        return (
          <button
            key={p.id}
            className="nav-btn nav-proj"
            data-proj-active={active}
            style={active ? { ['--proj-color' as string]: p.color } : undefined}
            title={p.title}
            onClick={() => setView('inbox', p.id)}
          >
            <ProjectIcon name={p.icon} color={p.color} size={16} />
          </button>
        );
      })}
      {canCreateProject && (
        <button className="nav-btn nav-add" onClick={openCreateProject} title="New project">
          +
        </button>
      )}
      <div className="spacer" />
      {canEditWorkspace && activeWorkspaceId && (
        <button
          className="nav-btn"
          onClick={() => openEditWorkspace(activeWorkspaceId)}
          title="Workspace settings"
        >
          <Settings size={14} strokeWidth={1.75} />
        </button>
      )}
    </div>
  );
}
