import type { Tag, UUID } from '../types';

/// The project tag filter: a row of selectable tag chips plus the
/// any/all mode toggle, and optionally the me/all assignee scope.
///
/// Lifted out of ListView unchanged so the plan board's rail can use
/// the same control rather than growing a second, worse one. The list
/// passes `showAssigneeScope`; the board doesn't, because it has no
/// assignee subsections to scope.
export function ListTagFilter({
  projectId, allTags, tagIds, mode, scope, showAssigneeScope,
  onChange, onModeChange, onScopeChange,
}: {
  projectId: UUID;
  allTags: Tag[];
  tagIds: UUID[];
  mode: 'and' | 'or';
  scope: 'me' | 'all';
  showAssigneeScope: boolean;
  onChange: (ids: UUID[]) => void;
  onModeChange: (mode: 'and' | 'or') => void;
  onScopeChange: (scope: 'me' | 'all') => void;
}) {
  // Sort by title length descending so longer chips lead each row.
  // flex-wrap places left-to-right in source order, and seeding rows
  // with long chips lets shorter ones slot into the trailing space —
  // fewer ragged half-empty rows than alphabetical order, especially
  // on narrow widths. Alphabetical secondary sort keeps the order
  // stable for chips of equal length.
  const projectTags = allTags
    .filter((t) => t.project_id === projectId)
    .sort((a, b) => b.title.length - a.title.length || a.title.localeCompare(b.title));

  const selected = new Set(tagIds);
  const toggle = (id: UUID) => {
    if (selected.has(id)) onChange(tagIds.filter((x) => x !== id));
    else onChange([...tagIds, id]);
  };
  const hasTags = projectTags.length > 0;

  return (
    <div className="list-tag-filter">
      {hasTags && (
        <div className="list-tag-filter-chips">
          {projectTags.map((t) => {
            const on = selected.has(t.id);
            return (
              <button
                key={t.id}
                type="button"
                className="chip tag-chip list-tag-filter-chip"
                data-on={on || undefined}
                style={{ ['--tag-color' as string]: t.color }}
                onClick={() => toggle(t.id)}
                title={t.title}
              >
                {t.title}
              </button>
            );
          })}
        </div>
      )}
      {/* Controls are always rendered, even with 0 / 1 tag selected, so
       * the layout doesn't shift as the user toggles chips. With one
       * tag, OR/AND yields the same set — the toggle still works, just
       * has no visible effect until a second tag is added. Clear is a
       * safe no-op when nothing is selected. */}
      <div className="list-tag-filter-controls">
        {showAssigneeScope && <div className="list-tag-filter-mode" role="group" aria-label="Assignee scope">
          <button
            type="button"
            className="list-tag-filter-mode-seg"
            data-active={scope === 'all' || undefined}
            onClick={() => onScopeChange('all')}
            title="Show every task in this project"
          >
            all
          </button>
          <button
            type="button"
            className="list-tag-filter-mode-seg"
            data-active={scope === 'me' || undefined}
            onClick={() => onScopeChange('me')}
            title="Show only tasks assigned to me"
          >
            me
          </button>
        </div>}
        {hasTags && (
            <div className="list-tag-filter-mode" role="group" aria-label="Tag match mode">
              <button
                type="button"
                className="list-tag-filter-mode-seg"
                data-active={mode === 'or' || undefined}
                onClick={() => onModeChange('or')}
                title="Match tasks with any selected tag"
              >
                or
              </button>
              <button
                type="button"
                className="list-tag-filter-mode-seg"
                data-active={mode === 'and' || undefined}
                onClick={() => onModeChange('and')}
                title="Match tasks with every selected tag"
              >
                and
              </button>
            </div>
        )}
      </div>
    </div>
  );
}
