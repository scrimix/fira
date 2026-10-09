import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { ReactNode } from 'react';
import '../styles/tooltip.css';

interface Props {
  label: string;
  trigger: ReactNode;
  children: ReactNode;
  className?: string;
  warning?: boolean;
}

/** Immediate, click-toggle help that escapes clipped card containers. */
export function ClickTooltip({ label, trigger, children, className, warning }: Props) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 0, top: 0 });
  const button = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (!open || !button.current || !panel.current) return;
    const reposition = () => {
      if (!button.current || !panel.current) return;
      const anchor = button.current.getBoundingClientRect();
      const box = panel.current.getBoundingClientRect();
      if (anchor.bottom < 0 || anchor.top > window.innerHeight || anchor.right < 0 || anchor.left > window.innerWidth) {
        setOpen(false);
        return;
      }
      setPosition({
        left: Math.max(8, Math.min(anchor.right - box.width, window.innerWidth - box.width - 8)),
        top: anchor.bottom + box.height + 6 <= window.innerHeight - 8
          ? anchor.bottom + 6 : Math.max(8, anchor.top - box.height - 6),
      });
    };
    reposition();
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    return () => {
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
    };
  }, [open, children]);

  useEffect(() => {
    if (!open) return;
    const outside = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!button.current?.contains(target) && !panel.current?.contains(target)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      event.stopPropagation();
      setOpen(false);
      button.current?.focus();
    };
    document.addEventListener('pointerdown', outside);
    document.addEventListener('keydown', escape, true);
    return () => {
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('keydown', escape, true);
    };
  }, [open]);

  return <>
    <button ref={button} type="button" className={className}
      data-warning={warning || undefined} aria-label={label}
      aria-expanded={open} aria-controls={open ? id : undefined}
      aria-describedby={open ? id : undefined}
      onPointerDown={(event) => event.stopPropagation()}
      onClick={(event) => { event.stopPropagation(); setOpen(value => !value); }}
      onBlur={(event) => {
        if (!panel.current?.contains(event.relatedTarget as Node | null)) setOpen(false);
      }}>{trigger}</button>
    {open && createPortal(<div ref={panel} id={id} role="tooltip" tabIndex={-1} className="click-tooltip"
      style={position} onPointerDown={(event) => event.stopPropagation()}
      onBlur={(event) => {
        if (!panel.current?.contains(event.relatedTarget as Node | null) && event.relatedTarget !== button.current) setOpen(false);
      }}
      onClick={(event) => event.stopPropagation()}>{children}</div>, document.body)}
  </>;
}
