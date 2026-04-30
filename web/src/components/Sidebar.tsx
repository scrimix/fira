import { Settings } from 'lucide-react';
import { useFira } from '../store';
import { ProjectIcon } from './ProjectIcon';

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
      <div className="brand">F</div>
      <button className="nav-btn" data-active={view === 'calendar'}
              onClick={() => setView('calendar')} title="Calendar (G)">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
          <rect x="1.5" y="3" width="13" height="11" stroke="currentColor"/>
          <line x1="1.5" y1="6" x2="14.5" y2="6" stroke="currentColor"/>
          <line x1="5" y1="3" x2="5" y2="14" stroke="currentColor" strokeOpacity="0.5"/>
          <line x1="8" y1="3" x2="8" y2="14" stroke="currentColor" strokeOpacity="0.5"/>
          <line x1="11" y1="3" x2="11" y2="14" stroke="currentColor" strokeOpacity="0.5"/>
        </svg>
      </button>
      <button className="nav-btn" data-active={view === 'inbox'}
              onClick={() => setView('inbox')} title="Inbox (I)">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
          <line x1="2" y1="3" x2="14" y2="3" stroke="currentColor"/>
          <line x1="2" y1="6" x2="14" y2="6" stroke="currentColor"/>
          <line x1="2" y1="9" x2="11" y2="9" stroke="currentColor"/>
          <line x1="2" y1="12" x2="9" y2="12" stroke="currentColor"/>
        </svg>
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
