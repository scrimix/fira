import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Check, ChevronDown } from 'lucide-react';

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
  group?: string;
  /// Colour for the group header's dot (e.g. a sprint's track colour).
  groupColor?: string;
  /// Colour dot shown before the label (e.g. a sprint's track colour).
  dot?: string;
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
  ariaLabel?: string;
  onKeyDown?: React.KeyboardEventHandler<HTMLButtonElement>;
  variant?: 'default' | 'inline';
}

export function Select<T extends string>({
  value, options, onChange, size = 'md', className, disabled, menuMinWidth, title, ariaLabel, onKeyDown, variant = 'default',
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
      // Clamp with the menu's real width — options can be wider than
      // menuMinWidth (badge + label + date), and the clamp must see that.
      const mw = Math.max(w, m ? m.getBoundingClientRect().width : 0);
      const left = Math.min(Math.max(8, t.left), window.innerWidth - mw - 8);
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
    // pointerdown covers both mouse and touch in one event — the prior
    // `mousedown` only fires synthesized on iOS *after* a click and is
    // dropped entirely on touch-without-mouse hardware, which is why the
    // popover felt broken on phones.
    const onDoc = (e: PointerEvent) => {
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
    document.addEventListener('pointerdown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const current = useMemo(
    () => options.find((o) => o.value === value) ?? null,
    [options, value],
  );

  const cls = `select select-${size} select-${variant}${open ? ' select-open' : ''}${className ? ' ' + className : ''}`;
  return (
    <div className={cls} ref={wrapRef}>
      <button
        ref={triggerRef}
        type="button"
        className="select-trigger"
        onClick={() => !disabled && setOpen((v) => !v)}
        disabled={disabled}
        aria-label={ariaLabel}
        onKeyDown={onKeyDown}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={id}
        title={title}
      >
        {current?.dot && <span className="select-dot" style={{ background: current.dot }} />}
        <span className="select-value">{current?.label ?? '—'}</span>
        {variant !== 'inline' && <ChevronDown size={10} strokeWidth={1.75} className="select-chevron" />}
      </button>
      {open && createPortal(
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
            : { visibility: 'hidden', position: 'fixed', top: 0, left: 0 }}
        >
          {options.map((o, index) => <div key={o.value}>
            {o.group && o.group !== options[index - 1]?.group &&
              <div className="select-group-label">
                {o.groupColor && <span className="select-group-dot" style={{ background: o.groupColor }} />}
                {o.group}
              </div>}
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
              {o.dot !== undefined ? (
                <span className="select-option-row">
                  <span className="select-dot" style={{ background: o.dot || 'var(--line-3)' }} />
                  <span className="select-option-label">{o.label}</span>
                  {o.hint && <span className="select-option-hint select-option-hint-inline">{o.hint}</span>}
                  <span className="select-option-check">{o.value === value && <Check size={13} strokeWidth={2} />}</span>
                </span>
              ) : (
                <>
                  <span className="select-option-row">
                    <span className="select-option-label">{o.label}</span>
                    <span className="select-option-check">{o.value === value && <Check size={13} strokeWidth={2} />}</span>
                  </span>
                  {o.hint && <span className="select-option-hint">{o.hint}</span>}
                </>
              )}
            </button>
          </div>)}
        </div>,
        document.body,
      )}
    </div>
  );
}
