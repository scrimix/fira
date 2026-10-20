import { useFira } from '../store';
import { Select } from './Select';

// Same location in every view. List shows a read-only name for one
// project, including when the other views are showing All projects.
export function ProjectScope() {
  const view = useFira((s) => s.view);
  const projects = useFira((s) => s.projects);
  const scopeId = useFira((s) => s.projectScopeId);
  const listProjectId = useFira((s) => s.listFilter.project_id);
  const setProjectScope = useFira((s) => s.setProjectScope);
  const selectedId = view === 'list' ? listProjectId : scopeId;
  const project = projects.find((p) => p.id === selectedId);
  const options = projects.length === 0 ? [{ value: 'all', label: 'No projects' }] : [
    ...(view === 'list' ? [] : [{ value: 'all', label: 'All projects' }]),
    ...projects.map((p) => ({ value: p.id, label: p.title })),
  ];

  return (
    <div className="project-scope" data-scope={project ? 'project' : 'all'} data-readonly={view === 'list' || undefined}
         role="group" aria-label="Project scope">
      <Select
        className="project-scope-select"
        size="sm"
        value={project?.id ?? 'all'}
        options={options}
        disabled={view === 'list' || projects.length === 0}
        menuMinWidth={240}
        title={view === 'list' ? 'List shows one project at a time · Choose a project in the sidebar' : 'Choose a project or All projects'}
        onChange={(id) => setProjectScope(id === 'all' ? null : id)}
      />
    </div>
  );
}
