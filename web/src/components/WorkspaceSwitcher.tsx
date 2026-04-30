import { useEffect, useRef, useState } from 'react';
import { Check, ChevronDown, Plus } from 'lucide-react';
import { useFira } from '../store';

// Breadcrumb-style dropdown in the TopBar. Renders the active workspace
// title; clicking opens a popover that lists all workspaces the user
// belongs to and offers a create action. Workspace settings live in the
// sidebar (cog at the bottom), accessible to owners only.
export function WorkspaceSwitcher() {
  const workspaces = useFira((s) => s.workspaces);
  const activeId = useFira((s) => s.activeWorkspaceId);
  const switchWorkspace = useFira((s) => s.switchWorkspace);
  const openCreate = useFira((s) => s.openCreateWorkspace);

  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const active = workspaces.find((w) => w.id === activeId);
  if (!active) return null;

  return (
    <div className="ws-switcher" ref={ref}>
      <button
        type="button"
        className="ws-trigger"
        onClick={() => setOpen((v) => !v)}
        title={active.title}
      >
        <span className="ws-title">{active.title}</span>
        <ChevronDown size={11} strokeWidth={1.75} />
      </button>
      {open && (
        <div className="ws-menu">
          <div className="ws-menu-section">Workspaces</div>
          {workspaces.map((w) => (
            <button
              key={w.id}
              type="button"
              className="ws-menu-row"
              data-active={w.id === activeId}
              onClick={async () => {
                setOpen(false);
                if (w.id !== activeId) await switchWorkspace(w.id);
              }}
            >
              <span className="ws-menu-title">{w.title}</span>
              {w.is_personal && <span className="ws-menu-tag">personal</span>}
              {w.id === activeId && <Check size={12} strokeWidth={2} />}
            </button>
          ))}
          <button
            type="button"
            className="ws-menu-add"
            onClick={() => { setOpen(false); openCreate(); }}
          >
            <Plus size={12} strokeWidth={1.75} />
            <span>New workspace</span>
          </button>
        </div>
      )}
    </div>
  );
}
