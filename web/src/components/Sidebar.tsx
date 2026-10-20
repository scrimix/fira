import { CalendarDays, Layers, GanttChartSquare, LayoutDashboard, List, Settings } from 'lucide-react';
import { useFira } from '../store';
import { useIsMobile } from '../hooks';
import { ProjectIcon } from './ProjectIcon';
import { BrandMark } from './BrandMark';

export function Sidebar() {
  const view = useFira((s) => s.view);
  const projects = useFira((s) => s.projects);
  const meId = useFira((s) => s.meId);
  const setView = useFira((s) => s.setView);
  const openCreateProject = useFira((s) => s.openCreateProject);
  const role = useFira((s) => s.myWorkspaceRole);
  const activeWorkspaceId = useFira((s) => s.activeWorkspaceId);
  const openEditWorkspace = useFira((s) => s.openEditWorkspace);
  const sidebarOpen = useFira((s) => s.sidebarOpen);
  const setSidebarOpen = useFira((s) => s.setSidebarOpen);
  const isMobile = useIsMobile();
  // On mobile, every nav action should also close the slide-over so the
  // user lands on the destination view without an extra tap-outside step.
  const close = () => { if (isMobile) setSidebarOpen(false); };
  const setProjectScope = useFira((s) => s.setProjectScope);
  const listProjectId = useFira((s) => s.listFilter.project_id);
  const projectScopeId = useFira((s) => s.projectScopeId);
  const activeProjectId = view === 'list' ? listProjectId : projectScopeId;
  const pickProject = (id: string) => {
    setProjectScope(id);
    close();
  };
  // Project create is owner-only. Leads administer existing projects
  // (rename, set members) but resource allocation — adding new projects
  // to a workspace — stays with the workspace owner.
  const canCreateProject = role === 'owner';
  const canEditWorkspace = role === 'owner';
  const isInactiveForMe = (p: (typeof projects)[number]) =>
    p.members.find((m) => m.user_id === meId)?.role === 'inactive';
  // Inactive projects go to the bottom
  const orderedProjects = [...projects].sort((a, b) =>
    Number(isInactiveForMe(a)) - Number(isInactiveForMe(b)),
  );

  return (
    <>
      {isMobile && sidebarOpen && (
        <div className="sidebar-scrim" onClick={() => setSidebarOpen(false)} />
      )}
      <div className="sidebar" data-open={isMobile ? (sidebarOpen ? 'true' : 'false') : undefined}>
        <BrandMark className="brand" size={22} title="Fira" />
        <button className="nav-btn" data-active={view === 'calendar'}
                onClick={() => { setView('calendar'); close(); }} title="Calendar (G)">
          <CalendarDays size={16} strokeWidth={1.75} />
        </button>
        <button className="nav-btn" data-active={view === 'list'}
                onClick={() => { setView('list'); close(); }} title="List (I)">
          <List size={16} strokeWidth={1.75} />
        </button>
        {/* Plan sits between List and Dashboard: the three are a
            widening sequence over the same tasks — one project's
            document, the workspace plan, then the aggregate. The
            dashboard is the roll-up and belongs last.

            Plan is available on desktop in production too. */}
        {!isMobile && (
          <button className="nav-btn" data-active={view === 'plan'}
                  onClick={() => { setView('plan'); close(); }} title="Plan (P)">
            <GanttChartSquare size={16} strokeWidth={1.75} />
          </button>
        )}
        <button className="nav-btn" data-active={view === 'dashboard'}
                onClick={() => { setView('dashboard'); close(); }} title="Dashboard (D)">
          <LayoutDashboard size={16} strokeWidth={1.75} />
        </button>
        <div style={{ height: 16 }} />
        <button
          className="nav-btn nav-proj"
          data-proj-active={view !== 'list' && projectScopeId === null}
          aria-pressed={view !== 'list' && projectScopeId === null}
          disabled={view === 'list'}
          title="All projects"
          onClick={() => { setProjectScope(null); close(); }}
        >
          <Layers size={16} strokeWidth={1.75} />
        </button>
        {orderedProjects.map((p) => {
          const active = p.id === activeProjectId;
          const inactive = isInactiveForMe(p);
          return (
            <button
              key={p.id}
              className="nav-btn nav-proj"
              data-proj-active={active}
              aria-pressed={active}
              data-proj-inactive={inactive}
              style={active ? { ['--proj-color' as string]: p.color } : undefined}
              title={inactive ? `${p.title} (inactive)` : p.title}
              onClick={() => pickProject(p.id)}
            >
              <ProjectIcon name={p.icon} color={inactive ? 'var(--ink-4)' : p.color} size={16} />
            </button>
          );
        })}
        {canCreateProject && (
          <button className="nav-btn nav-add" onClick={() => { openCreateProject(); close(); }} title="New project">
            +
          </button>
        )}
        <div className="spacer" />
        {canEditWorkspace && activeWorkspaceId && (
          <button
            className="nav-btn"
            onClick={() => { openEditWorkspace(activeWorkspaceId); close(); }}
            title="Workspace settings"
          >
            <Settings size={14} strokeWidth={1.75} />
          </button>
        )}
      </div>
    </>
  );
}
