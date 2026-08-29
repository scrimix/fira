// The block grid: a Mon-anchored month laid out 7 wide.
//
// Used twice with different fill rules — as the dashboard's hours
// heatmap, and once per goal card. Both want the same geometry, the same
// today ring and the same click-through to the calendar, so the geometry
// lives here and the *meaning* of a cell arrives as a prop.
//
// Intensity is expressed as a 0..1 `fill` that the CSS turns into a
// color-mix over the ramp hue, rather than as a bucketed class. Buckets
// read well for hours (0 / <2h / 2-4h / 4-6h / 6h+) but badly for a goal,
// where the interesting distinction is "how close to target" — a
// continuous ramp serves both, and the hours heatmap quantizes before it
// gets here.
//
// The day-of-month number is deliberately recessive: in a color-coded
// cell a centered number reads as *the value*, which is exactly the
// wrong thing for a date. It sits small in the corner, and the hours
// live in the hover tooltip and the scale legend instead.

import type { MonthCell } from '../time';
import { DAY_LABELS } from '../time';

export interface GridCell {
  /// 0..1 — how filled the cell reads.
  fill: number;
  /// Hatched rather than solid: planned time, or a period still ahead.
  /// Intent is not achievement and shouldn't look like it.
  pending?: boolean;
  /// A cap goal's allowance was blown. Its own color, not "very full".
  over?: boolean;
  /// Tooltip body — what this cell actually measures.
  tip?: string;
}

export interface HoverPayload { text: string; x: number; y: number }

export function MonthGrid({
  cells,
  cellFor,
  today,
  onPick,
  onHover,
  onLeave,
  compact,
}: {
  cells: MonthCell[];
  cellFor: (cell: MonthCell) => GridCell;
  /// Local midnight of today, for the ring. Undefined when the grid is
  /// showing a month that doesn't contain today.
  today?: number;
  onPick?: (ms: number) => void;
  onHover?: (p: HoverPayload) => void;
  onLeave?: () => void;
  /// Goal grids sit inside a card and run smaller than the hero heatmap.
  compact?: boolean;
}) {
  return (
    <div className="month-grid" data-compact={compact ? 'true' : undefined}>
      {DAY_LABELS.map((d) => (
        <div key={d} className="month-grid-dow">{d[0]}</div>
      ))}
      {cells.map((c) => {
        const g = cellFor(c);
        const hover = (e: { currentTarget: EventTarget & HTMLElement }) => {
          if (!onHover || !g.tip) return;
          const r = e.currentTarget.getBoundingClientRect();
          onHover({ text: g.tip, x: r.left + r.width / 2, y: r.top });
        };
        return (
          <button
            key={c.ms}
            className="month-cell"
            data-out={!c.inMonth || undefined}
            data-today={today != null && c.ms === today ? 'true' : undefined}
            data-pending={g.pending ? 'true' : undefined}
            data-over={g.over ? 'true' : undefined}
            // Past roughly half intensity the ramp swallows the date, so
            // the label flips to the ramp's foreground. Hatched cells
            // stay light whatever their fill.
            data-dark={g.fill >= 0.5 && !g.pending ? 'true' : undefined}
            style={{ ['--fill' as string]: String(g.fill) }}
            onClick={onPick ? () => onPick(c.ms) : undefined}
            onMouseEnter={hover}
            onMouseLeave={onLeave}
            onFocus={hover}
            onBlur={onLeave}
            // A cell with no click handler is decoration, not a control —
            // don't put it in the tab order or announce it as a button.
            tabIndex={onPick ? 0 : -1}
            aria-hidden={onPick ? undefined : true}
            aria-label={g.tip}
          >
            <span className="month-cell-day">{c.day}</span>
          </button>
        );
      })}
    </div>
  );
}

/// Weekly-cadence goals get one cell per week instead of per day, so a
/// month is 5-6 wide rather than 42. Same visual language, different
/// geometry — a separate small component rather than a mode flag on
/// MonthGrid, whose whole shape assumes a 7-wide calendar.
export function WeekStrip({
  weeks,
  cellFor,
  currentWeek,
  onHover,
  onLeave,
}: {
  weeks: number[];
  cellFor: (ms: number) => GridCell;
  currentWeek?: number;
  onHover?: (p: HoverPayload) => void;
  onLeave?: () => void;
}) {
  return (
    <div className="week-strip">
      {weeks.map((ms) => {
        const g = cellFor(ms);
        return (
          <div
            key={ms}
            className="week-cell"
            data-today={currentWeek === ms ? 'true' : undefined}
            data-pending={g.pending ? 'true' : undefined}
            data-over={g.over ? 'true' : undefined}
            // Drives the same ramp the daily cells use — without it every
            // week renders flat and a part-way week is indistinguishable
            // from an empty one.
            style={{ ['--fill' as string]: String(g.fill) }}
            aria-label={g.tip}
            onMouseEnter={(e) => {
              if (!onHover || !g.tip) return;
              const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
              onHover({ text: g.tip, x: r.left + r.width / 2, y: r.top });
            }}
            onMouseLeave={onLeave}
          />
        );
      })}
    </div>
  );
}

/// The heatmap's key. A sequential ramp is unreadable without one — the
/// cells encode magnitude in color, and nothing else on the page says
/// what a given darkness is worth.
export function ScaleLegend({ steps }: { steps: { fill: number; label: string }[] }) {
  return (
    <div className="scale-legend">
      <span className="scale-swatch" style={{ ['--fill' as string]: '0' }} />
      <span className="scale-legend-label">none</span>
      {steps.map((s) => (
        <span key={s.label} className="scale-step">
          <span className="scale-swatch" style={{ ['--fill' as string]: String(s.fill) }} />
          <span className="scale-legend-label">{s.label}</span>
        </span>
      ))}
    </div>
  );
}
