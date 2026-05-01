import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { ChevronDown } from 'lucide-react';

// Generic dropdown that replaces the native <select>. Native selects render
// the option list with platform chrome (white background, OS font) which
// fights the editorial palette. This one stays inside the design system.
//
// Generic over the value type so callers can pass enum-typed values without
// `as` casts. Options can carry a separate label, an optional `hint` line
// (renders dimmer below the label), and a `disabled` flag.

export interface SelectOption<T extends string> {
  value: T;
  label: string;
  hint?: string;
  disabled?: boolean;
}

interface Props<T extends string> {
  value: T;
  options: SelectOption<T>[];
  onChange: (value: T) => void;
  /// Visual size — the role selector inside member rows is much smaller
  /// than a full-width project picker, so the trigger height changes
  /// while the popover stays consistent.
  size?: 'sm' | 'md';
  className?: string;
  disabled?: boolean;
  /// Force the popover to a specific width. By default it matches the
  /// trigger; for the member-row role selector that's too narrow to read
  /// the hint lines, so callers can widen it.
  menuMinWidth?: number;
  title?: string;
}

export function Select<T extends string>({
  value, options, onChange, size = 'md', className, disabled, menuMinWidth, title,
}: Props<T>) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const id = useId();
  // Computed each open: place the menu in viewport coordinates so it can
  // escape any ancestor with overflow: auto/hidden (modal bodies, etc.).
  // Falls back to "above" if there isn't enough room below.
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; width: number } | null>(null);

  useLayoutEffect(() => {
    if (!open || !triggerRef.current) {
      setMenuPos(null);
      return;
    }
    const place = () => {
      const t = triggerRef.current!.getBoundingClientRect();
      const w = Math.max(t.width, menuMinWidth ?? 0);
      const m = menuRef.current;
      const mh = m ? m.getBoundingClientRect().height : 0;
      const spaceBelow = window.innerHeight - t.bottom;
      const flipUp = mh > 0 && spaceBelow < mh + 8 && t.top > mh + 8;
      const top = flipUp ? Math.max(8, t.top - mh - 4) : t.bottom + 2;
      const left = Math.min(Math.max(8, t.left), window.innerWidth - w - 8);
      setMenuPos({ top, left, width: w });
    };
    place();
    // Re-measure once the menu has DOM-based height so the flip decision is
    // accurate (initial pass treats height as 0 → always renders below).
    const raf = requestAnimationFrame(place);
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
  }, [open, menuMinWidth]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      const t = e.target as Node;
      if (
        (wrapRef.current && wrapRef.current.contains(t))
        || (menuRef.current && menuRef.current.contains(t))
      ) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const current = useMemo(
    () => options.find((o) => o.value === value) ?? null,
    [options, value],
  );

  const cls = `select select-${size}${open ? ' select-open' : ''}${className ? ' ' + className : ''}`;
  return (
    <div className={cls} ref={wrapRef}>
      <button
        ref={triggerRef}
        type="button"
        className="select-trigger"
        onClick={() => !disabled && setOpen((v) => !v)}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={id}
        title={title}
      >
        <span className="select-value">{current?.label ?? '—'}</span>
        <ChevronDown size={size === 'sm' ? 11 : 13} strokeWidth={1.75} />
      </button>
      {open && (
        <div
          ref={menuRef}
          id={id}
          className="select-menu"
          role="listbox"
          style={menuPos
            ? {
                position: 'fixed',
                top: menuPos.top,
                left: menuPos.left,
                minWidth: menuPos.width,
              }
            : { visibility: 'hidden' }}
        >
          {options.map((o) => (
            <button
              key={o.value}
              type="button"
              role="option"
              aria-selected={o.value === value}
              className="select-option"
              data-active={o.value === value}
              disabled={o.disabled}
              onClick={() => {
                if (!o.disabled) {
                  onChange(o.value);
                  setOpen(false);
                }
              }}
            >
              <span className="select-option-label">{o.label}</span>
              {o.hint && <span className="select-option-hint">{o.hint}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
