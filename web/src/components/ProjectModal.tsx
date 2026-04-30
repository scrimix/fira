import { useState } from 'react';
import { useFira } from '../store';
import { PROJECT_ICONS, DEFAULT_ICON, ProjectIcon } from './ProjectIcon';
import type { Project } from '../types';

// Editorial-utilitarian palette. All Tailwind ~700 shades so each chip sits
// at the same perceived weight on paper — distinguishable by hue, not by
// brightness. Two existing seed projects (teal, amber) live here unchanged.
const COLORS: { hex: string; name: string }[] = [
  { hex: '#0F766E', name: 'Teal' },
  { hex: '#0E7490', name: 'Cyan' },
  { hex: '#1D4ED8', name: 'Blue' },
  { hex: '#6D28D9', name: 'Violet' },
  { hex: '#BE185D', name: 'Pink' },
  { hex: '#B45309', name: 'Amber' },
  { hex: '#15803D', name: 'Green' },
  { hex: '#334155', name: 'Slate' },
];

interface Props {
  // undefined = create new; otherwise edit this project.
  project?: Project;
}

export function ProjectModal({ project }: Props) {
  const isEdit = !!project;
  const close = useFira((s) => s.closeProjectModal);
  const addProject = useFira((s) => s.addProject);
  const updateProject = useFira((s) => s.updateProject);

  const [title, setTitle] = useState(project?.title ?? '');
  const [icon, setIcon] = useState(project?.icon || DEFAULT_ICON);
  const [color, setColor] = useState(project?.color || COLORS[0].hex);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trimmed = title.trim();
  const valid = trimmed.length > 0 && trimmed.length <= 80;
  const dirty = !isEdit || (
    trimmed !== project!.title || icon !== project!.icon || color !== project!.color
  );

  const submit = async () => {
    if (!valid || submitting || !dirty) return;
    setSubmitting(true);
    setError(null);
    try {
      if (isEdit) {
        await updateProject(project!.id, { title: trimmed, icon, color });
      } else {
        await addProject({ title: trimmed, icon, color });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save project');
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={close}>
      <div className="modal np-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="np-preview" style={{ color, borderColor: color }}>
            <ProjectIcon name={icon} size={14} strokeWidth={1.75} />
          </span>
          <span className="ext">{trimmed || (isEdit ? project!.title : 'New project')}</span>
          <span className="grow" />
          <button className="icon-btn" onClick={close} title="Close (Esc)">×</button>
        </div>
        <div className="np-body">
          <label className="np-label">Name</label>
          <input
            autoFocus
            className="np-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Project name"
            maxLength={80}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.metaKey || e.ctrlKey || valid)) {
                e.preventDefault();
                submit();
              }
              if (e.key === 'Escape') close();
            }}
          />

          <label className="np-label">Icon</label>
          <div className="np-icons">
            {PROJECT_ICONS.map(({ name, icon: I }) => (
              <button
                key={name}
                type="button"
                className="np-icon"
                data-active={name === icon}
                onClick={() => setIcon(name)}
                title={name}
                aria-label={name}
              >
                <I size={18} strokeWidth={1.75} />
              </button>
            ))}
          </div>

          <label className="np-label">Color</label>
          <div className="np-colors">
            {COLORS.map((c) => (
              <button
                key={c.hex}
                type="button"
                className="np-color"
                data-active={c.hex === color}
                style={{ ['--swatch' as string]: c.hex }}
                onClick={() => setColor(c.hex)}
                title={c.name}
                aria-label={c.name}
              >
                <span className="np-color-fill" />
              </button>
            ))}
          </div>

          {error && <div className="np-error">{error}</div>}

          <div className="np-actions">
            <button className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button
              className="btn np-create"
              onClick={submit}
              disabled={!valid || !dirty || submitting}
            >
              {submitting
                ? (isEdit ? 'Saving…' : 'Creating…')
                : (isEdit ? 'Save changes' : 'Create project')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
