import { useEffect, useRef, useState } from 'react';
import { Check, ChevronDown, Users } from 'lucide-react';
import type { UUID } from '../types';

type PickerUser = { id: UUID; name: string; initials: string; email: string };

/// Searchable person dropdown shared by the calendar and list toolbars.
/// Pass `everyoneLabel` to add an "everyone" row at the top; picking it
/// calls `onSelect(null)`, and `activeId === null` shows that label.
export function UserPicker({ users, meId, activeId, onSelect, everyoneLabel, align = 'left', ariaLabel }: {
  users: PickerUser[];
  meId: UUID | null;
  activeId: UUID | null;
  onSelect: (id: UUID | null) => void;
  everyoneLabel?: string;
  align?: 'left' | 'right';
  ariaLabel: string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const active = users.find((u) => u.id === activeId) ?? null;
  const q = query.trim().toLowerCase();
  // Me first, then everyone else by name.
  const ordered = [...users].sort((x, y) =>
    x.id === meId ? -1 : y.id === meId ? 1 : x.name.localeCompare(y.name));
  const matches = ordered.filter((u) =>
    !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q));
  // The "everyone" row stays visible while it matches the search, so the
  // keyboard list and the rendered list share one index space.
  const showEveryone = !!everyoneLabel && (!q || everyoneLabel.toLowerCase().includes(q));
  const rows: Array<PickerUser | null> = showEveryone ? [null, ...matches] : matches;
  const isSelected = (r: PickerUser | null) => (r ? r.id === activeId : activeId === null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(Math.max(0, rows.findIndex(isSelected)));
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  useEffect(() => { if (query) setActiveIdx(0); }, [query]);

  const pick = (id: UUID | null) => { onSelect(id); setOpen(false); };

  const label = active
    ? (active.id === meId ? 'Me' : active.name)
    : everyoneLabel ?? 'Choose person';

  return (
    <div className="user-picker" ref={wrapRef}>
      <button type="button" className="person-select" data-open={open || undefined}
              aria-haspopup="listbox" aria-expanded={open}
              aria-label={ariaLabel}
              onClick={() => setOpen((v) => !v)}>
        <span className="person-select-name">{label}</span>
        <ChevronDown size={12} strokeWidth={1.75} className="person-select-chevron" />
      </button>
      {open && (
        <div className="user-popover" data-align={align}>
          <input
            ref={inputRef}
            className="user-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search people"
            aria-label="Search people"
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveIdx((i) => Math.min(rows.length - 1, i + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIdx((i) => Math.max(0, i - 1));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                if (activeIdx < rows.length) pick(rows[activeIdx]?.id ?? null);
              }
            }}
          />
          <div className="user-list" role="listbox">
            {rows.length === 0 ? (
              <div className="user-empty">No matches</div>
            ) : rows.map((u, i) => (
              <button key={u?.id ?? '__everyone'} className="user-row" role="option"
                      aria-selected={isSelected(u)}
                      data-active={i === activeIdx}
                      data-selected={isSelected(u)}
                      onMouseEnter={() => setActiveIdx(i)}
                      onClick={() => pick(u?.id ?? null)}>
                {u ? (
                  <span className="avatar" data-me={u.id === meId}>{u.initials}</span>
                ) : (
                  <span className="avatar user-row-everyone"><Users size={12} strokeWidth={1.75} /></span>
                )}
                <span className="user-row-name">
                  {u ? <>{u.name}{u.id === meId && <span className="user-row-you"> (you)</span>}</> : everyoneLabel}
                </span>
                {isSelected(u)
                  ? <Check size={13} strokeWidth={2} className="user-row-check" />
                  : <span />}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
