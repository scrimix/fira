import { CalendarDays, GanttChartSquare, LayoutDashboard, List, Settings } from 'lucide-react';
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
  // Every surface here is project-scopable, so picking a project scopes
  // the view you are in rather than throwing it away for the list.
  // Each view already owns its own cursor; this just routes to it.
  const setPlanProject = useFira((s) => s.setPlanProject);
  const setDashboardProject = useFira((s) => s.setDashboardProject);
  const soloProjectFilter = useFira((s) => s.soloProjectFilter);
  const listProjectId = useFira((s) => s.listFilter.project_id);
  const planProjectId = useFira((s) => s.planProjectId);
  const dashboardProjectId = useFira((s) => s.dashboardProjectId);
  const projectFilter = useFira((s) => s.projectFilter);

  const pickProject = (id: string) => {
    if (view === 'plan') setPlanProject(id);
    else if (view === 'dashboard') setDashboardProject(id);
    // The calendar is a time surface across every project, so its
    // scoping gesture is its own visibility filter — the same solo a
    // double-click on the rail's project row performs.
    else if (view === 'calendar') soloProjectFilter(id);
    else setView('list', id);
    close();
  };

  // The highlight follows whatever the current view is actually scoped
  // to. On the calendar that's only truthful when exactly one project
  // is visible — otherwise a single-project highlight would lie about
  // what's on screen, which is why this used to be list-only.
  const soloedOnCalendar = () => {
    const visible = projects.filter((p) => projectFilter[p.id] !== false);
    return visible.length === 1 ? visible[0].id : null;
  };
  const activeProjectId =
    view === 'plan' ? planProjectId
      : view === 'dashboard' ? dashboardProjectId
        : view === 'calendar' ? soloedOnCalendar()
          : listProjectId;
  const showProjectActive = activeProjectId != null;
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
            document, one project's quarter, then the aggregate. The
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
        {orderedProjects.map((p) => {
          const active = showProjectActive && p.id === activeProjectId;
          const inactive = isInactiveForMe(p);
          return (
            <button
              key={p.id}
              className="nav-btn nav-proj"
              data-proj-active={active}
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
