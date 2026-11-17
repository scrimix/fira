import { useEffect, useRef, useState } from 'react';
import { Check, ChevronDown, X } from 'lucide-react';
import type { Tag, UUID } from '../types';

/// The list's tag filter, in two parts:
///
/// - `TagMenu`: one toolbar button ("Tags", or "Tags · 2") that opens a
///   checklist of the project's tags. A dropdown rather than a row of
///   chips, so the filter costs one control however many tags there are.
/// - `TagFilterChips`: the picked tags as removable chips under the
///   toolbar, with the any/all switch — shown only once two or more are
///   picked, the only time it changes anything.
export function TagMenu({ projectId, allTags, tagIds, onChange }: {
  projectId: UUID;
  allTags: Tag[];
  tagIds: UUID[];
  onChange: (ids: UUID[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const projectTags = allTags
    .filter((t) => t.project_id === projectId)
    .sort((a, b) => a.title.localeCompare(b.title));
  const selected = new Set(tagIds);
  const toggle = (id: UUID) => {
    if (selected.has(id)) onChange(tagIds.filter((x) => x !== id));
    else onChange([...tagIds, id]);
  };

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (projectTags.length === 0) return null;
  const count = tagIds.filter((id) => projectTags.some((t) => t.id === id)).length;

  return (
    <div className="tag-menu" ref={wrapRef}>
      <button
        type="button"
        className="tag-menu-trigger"
        data-set={count > 0 || undefined}
        data-open={open || undefined}
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        Tags{count > 0 && <span className="tag-menu-count">{count}</span>}
        <ChevronDown size={12} strokeWidth={1.75} className="tag-menu-chevron" />
      </button>
      {open && (
        <div className="tag-editor-popover tag-menu-popover" role="menu">
          <div className="tag-editor-list">
            {projectTags.map((t) => {
              const on = selected.has(t.id);
              return (
                <button
                  key={t.id}
                  type="button"
                  role="menuitemcheckbox"
                  aria-checked={on}
                  className="tag-editor-row-btn"
                  data-on={on || undefined}
                  style={{ ['--tag-color' as string]: t.color }}
                  onClick={() => toggle(t.id)}
                >
                  <span className="tag-editor-row-title">{t.title}</span>
                  {on && <Check size={12} strokeWidth={2} />}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export function TagFilterChips({ allTags, tagIds, mode, onChange, onModeChange }: {
  allTags: Tag[];
  tagIds: UUID[];
  mode: 'and' | 'or';
  onChange: (ids: UUID[]) => void;
  onModeChange: (mode: 'and' | 'or') => void;
}) {
  const picked = tagIds
    .map((id) => allTags.find((t) => t.id === id))
    .filter((t): t is Tag => !!t);
  if (picked.length === 0) return null;
  return (
    <div className="tag-filter-chips">
      {picked.map((t) => (
        <span key={t.id} className="tag-chip tag-filter-chip" style={{ ['--tag-color' as string]: t.color }}>
          <span className="tag-chip-title">{t.title}</span>
          <button
            type="button"
            className="tag-chip-x"
            onClick={() => onChange(tagIds.filter((x) => x !== t.id))}
            title={`Remove ${t.title}`}
            aria-label={`Remove ${t.title} filter`}
          >
            <X size={10} strokeWidth={2} />
          </button>
        </span>
      ))}
      {picked.length >= 2 && (
        <div className="seg tag-filter-mode" role="group" aria-label="Tag match">
          <button type="button" data-on={mode === 'or' || undefined} aria-pressed={mode === 'or'}
                  onClick={() => onModeChange('or')}
                  title="Tasks with any of these tags">Any</button>
          <button type="button" data-on={mode === 'and' || undefined} aria-pressed={mode === 'and'}
                  onClick={() => onModeChange('and')}
                  title="Tasks with all of these tags">All</button>
        </div>
      )}
    </div>
  );
}
