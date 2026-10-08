import { useEffect, useRef, useState, type ReactNode, type KeyboardEvent } from 'react';
import { ChevronLeft, ChevronRight, Minus, Plus } from 'lucide-react';
import type { PlanRevisionList } from '../planHistory';

const labels: Record<string, string> = {
  'task.create': 'Task added', 'task.delete': 'Task deleted', 'task.set_sprint': 'Task placement changed',
  'task.tick': 'Task completion changed', 'task.set_status': 'Task status changed',
  'task.set_section': 'Task section changed', 'task.set_title': 'Task renamed',
  'task.reorder': 'Tasks reordered', 'task.move_project': 'Task moved between projects',
  'track.create': 'Track added', 'track.delete': 'Track removed', 'track.set_title': 'Track renamed',
  'track.set_color': 'Track color changed', 'track.reorder': 'Tracks reordered',
  'sprint.create': 'Sprint added', 'sprint.delete': 'Sprint removed', 'sprint.set_title': 'Sprint renamed',
  'sprint.set_dates': 'Sprint dates changed', 'sprint.set_track': 'Sprint track changed',
};
export function revisionTime(ms: number): string {
  return new Date(ms).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    second: '2-digit', fractionalSecondDigits: 3, hour12: false,
  });
}
export function clampHistoryWindow(start: number, span: number, first: number, last: number) {
  const width = Math.min(Math.max(1, last - first), Math.max(1000, span));
  const left = Math.max(first, Math.min(last - width, start));
  return { start: left, end: left + width };
}
// Short ranges use clock ticks; longer ranges use real calendar months/years.
export function historyTicks(start: number, end: number): { at: number; label: string }[] {
  const span = Math.max(1, end - start);
  const intervals = [1000, 5000, 15_000, 60_000, 300_000, 900_000, 3_600_000,
    21_600_000, 86_400_000, 604_800_000];
  const step = intervals.find((value) => span / value <= 9);
  const ticks: { at: number; label: string }[] = [];
  if (step) {
    for (let at = Math.ceil(start / step) * step; at <= end; at += step) {
      ticks.push({ at, label: new Date(at).toLocaleString(undefined, span < 86_400_000
        ? { hour: '2-digit', minute: '2-digit', ...(span < 60_000 ? { second: '2-digit' as const } : {}) }
        : { month: 'short', day: 'numeric' }) });
    }
  } else {
    const months = [1, 3, 6, 12, 24, 60, 120, 240].find((n) => span / (n * 2_629_800_000) <= 9)
      ?? Math.ceil(span / (9 * 31_557_600_000)) * 12;
    const date = new Date(start);
    let month = Math.floor((date.getFullYear() * 12 + date.getMonth()) / months) * months;
    for (;;) {
      const at = new Date(Math.floor(month / 12), month % 12, 1).getTime();
      if (at > end) break;
      if (at >= start) ticks.push({ at, label: new Date(at).toLocaleDateString(undefined,
        months >= 12 ? { year: 'numeric' } : { month: 'short', year: 'numeric' }) });
      month += months;
    }
  }
  return ticks;
}
export function PlanTimeline({ history, selectedAt, selectedSeq, onSelect, status }: {
  history: PlanRevisionList | null; status: ReactNode; selectedAt: string | null; selectedSeq: number | null;
  onSelect: (at: string | null, seq?: number | null) => void;
}) {
  const rail = useRef<HTMLDivElement>(null);
  const drag = useRef<{ mode: 'scrub' | 'pan'; x: number; start: number; end: number; moved: boolean; revisionIndex: number } | null>(null);
  const [windowRange, setWindowRange] = useState<{ start: number; end: number } | null>(null);
  // Freeze the browsing horizon. Wheel/pan renders must not advance Live
  // or continually grow a fully zoomed-out window by a few milliseconds.
  const [openedAt] = useState(() => Date.now());
  const now = history?.changes.reduce((end, change) => Math.max(end, Date.parse(change.at)), openedAt) ?? openedAt;
  const first = history?.genesis ? Date.parse(history.genesis) : now;
  const fullSpan = Math.max(1, now - first);
  const range = windowRange ? clampHistoryWindow(windowRange.start, windowRange.end - windowRange.start, first, now)
    : { start: first, end: now };
  const span = Math.max(1, range.end - range.start);
  const selected = selectedAt ? Date.parse(selectedAt) : now;
  const changes = history?.changes ?? [];
  const selectedIndex = selectedSeq !== null ? changes.findIndex((c) => c.seq === selectedSeq)
    : changes.reduce((last, change, i) => Date.parse(change.at) <= selected ? i : last, -1);
  const previousIndex = selectedSeq !== null ? selectedIndex - 1 : selectedIndex;
  const position = (at: number) => 100 * (at - range.start) / span;
  const chooseRevision = (index: number) => {
    const change = changes[index];
    if (!change) return;
    onSelect(change.at, change.seq);
    const at = Date.parse(change.at);
    if (at < range.start || at > range.end) setWindowRange(clampHistoryWindow(at - span / 2, span, first, now));
  };
  const onRevisionKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      event.preventDefault(); event.stopPropagation();
      chooseRevision(event.key === 'ArrowLeft' ? previousIndex : selectedIndex + 1);
    } else if (event.key === 'Home') {
      event.preventDefault(); event.stopPropagation(); chooseRevision(0);
    } else if (event.key === 'End') {
      event.preventDefault(); event.stopPropagation(); onSelect(null);
    }
  };
  const zoom = (factor: number, fraction = Math.max(0, Math.min(1, (selected - range.start) / span))) => {
    if ((factor > 1 && span >= fullSpan) || (factor < 1 && span <= 1000)) return;
    const anchor = range.start + fraction * span;
    setWindowRange(clampHistoryWindow(anchor - span * factor * fraction, span * factor, first, now));
  };
  useEffect(() => {
    const element = rail.current;
    if (!element) return;
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      const box = element.getBoundingClientRect();
      const fraction = Math.max(0, Math.min(1, (event.clientX - box.left) / box.width));
      const currentSpan = Math.max(1, range.end - range.start);
      if (event.deltaY === 0 || (event.deltaY > 0 && currentSpan >= fullSpan)
        || (event.deltaY < 0 && currentSpan <= 1000)) return;
      const factor = Math.exp(Math.max(-1, Math.min(1, event.deltaY / 300)));
      const anchor = range.start + fraction * currentSpan;
      setWindowRange(clampHistoryWindow(anchor - currentSpan * factor * fraction, currentSpan * factor, first, now));
    };
    element.addEventListener('wheel', wheel, { passive: false });
    return () => element.removeEventListener('wheel', wheel);
  }, [range.start, range.end, first, now, fullSpan]);
  const seek = (x: number) => {
    const box = rail.current?.getBoundingClientRect();
    if (!box) return;
    const fraction = Math.max(0, Math.min(1, (x - box.left) / box.width));
    const at = Math.round(range.start + fraction * span);
    onSelect(at >= now - 1 ? null : new Date(at).toISOString());
  };
  const ticks = historyTicks(range.start, range.end);
  const visibleChanges = changes.filter((c) => Date.parse(c.at) >= range.start && Date.parse(c.at) <= range.end);
  const scale = span >= 31_557_600_000 ? `${(span / 31_557_600_000).toFixed(1)} years`
    : span >= 2_629_800_000 ? `${(span / 2_629_800_000).toFixed(1)} months`
    : span >= 86_400_000 ? `${(span / 86_400_000).toFixed(1)} days`
    : span >= 3_600_000 ? `${(span / 3_600_000).toFixed(1)} hours`
    : span >= 60_000 ? `${(span / 60_000).toFixed(1)} minutes` : `${(span / 1000).toFixed(1)} seconds`;
  return <section className="plan-timeline" aria-label="Plan revision timeline">
    <div className="plan-revision-toolbar">
      <strong>Plan history</strong>
      <div className="week-nav">
        <button className="week-nav-btn" aria-label="Previous revision" disabled={previousIndex < 0}
          onClick={() => chooseRevision(previousIndex)}><ChevronLeft size={14} strokeWidth={1.75} /></button>
        <button className="week-nav-btn" aria-label="Next revision" disabled={selectedIndex >= changes.length - 1}
          onClick={() => chooseRevision(selectedIndex + 1)}><ChevronRight size={14} strokeWidth={1.75} /></button>
      </div>
      <select className="plan-revision-picker" aria-label="Revision" onKeyDown={onRevisionKeyDown}
        value={selectedAt === null ? 'live' : selectedSeq !== null ? String(selectedSeq) : 'time'}
        onChange={(e) => {
          if (e.target.value === 'live') onSelect(null);
          else chooseRevision(changes.findIndex((change) => String(change.seq) === e.target.value));
        }}>
        <option value="live">Live plan</option>
        {selectedSeq === null && selectedAt !== null && <option value="time">Custom time · {revisionTime(selected)}</option>}
        {[...changes].reverse().map((change) => <option key={change.seq} value={change.seq}>
          {revisionTime(Date.parse(change.at))} · {labels[change.kind] ?? 'Plan changed'} · #{change.seq}
        </option>)}
      </select>
      <div className="week-nav plan-revision-zoom">
        <button className="week-nav-btn" aria-label="Zoom out history" disabled={span >= fullSpan}
          onClick={() => zoom(2)}><Minus size={13} /></button>
        <span className="week-nav-count">{scale}</span>
        <button className="week-nav-btn" aria-label="Zoom in history" disabled={span <= 1000}
          onClick={() => zoom(.5)}><Plus size={13} /></button>
        <button className="week-nav-btn" aria-label="Fit all history" onClick={() => setWindowRange(null)}>Fit</button>
      </div>
    </div>
    <div className="plan-revision-axis" ref={rail} role="slider" tabIndex={0}
      data-start={range.start} data-end={range.end}
      aria-label="Scrub plan history" aria-valuemin={first} aria-valuemax={now}
      aria-valuenow={selected} aria-valuetext={selectedAt ? revisionTime(selected) : 'Live plan'}
      onKeyDown={onRevisionKeyDown}
      onPointerDown={(e) => {
        if (e.button !== 0 || !changes.length) return;
        e.preventDefault(); e.currentTarget.focus(); e.currentTarget.setPointerCapture(e.pointerId);
        const target = e.target as HTMLElement;
        const mode = target.closest('.plan-revision-playhead') ? 'scrub' : 'pan';
        const marker = target.closest<HTMLElement>('.plan-revision-marker');
        drag.current = { mode, x: e.clientX, start: range.start, end: range.end, moved: false,
          revisionIndex: marker ? changes.findIndex((change) => String(change.seq) === marker.dataset.seq) : -1 };
        if (mode === 'scrub') seek(e.clientX);
      }}
      onPointerMove={(e) => {
        const gesture = drag.current;
        if (!gesture) return;
        if (Math.abs(e.clientX - gesture.x) > 4) gesture.moved = true;
        if (!gesture.moved) return;
        if (gesture.mode === 'scrub') seek(e.clientX);
        else {
          const width = e.currentTarget.getBoundingClientRect().width;
          const delta = (e.clientX - gesture.x) / width * (gesture.end - gesture.start);
          setWindowRange(clampHistoryWindow(gesture.start - delta, gesture.end - gesture.start, first, now));
        }
      }}
      onPointerUp={(e) => {
        const gesture = drag.current;
        drag.current = null;
        if (gesture?.mode === 'pan' && !gesture.moved) {
          if (gesture.revisionIndex >= 0) chooseRevision(gesture.revisionIndex);
          else seek(e.clientX);
        }
      }} onPointerCancel={() => { drag.current = null; }}>
      <div className="plan-revision-baseline" />
      {ticks.map(({ at, label }) => <div key={at} className="plan-revision-tick" style={{ left: `${position(at)}%` }}>
        <span>{label}</span>
      </div>)}
      {visibleChanges.map((change) => <button key={change.seq} className="plan-revision-marker"
        data-selected={selectedSeq === change.seq || undefined} data-seq={change.seq}
        style={{ left: `${position(Date.parse(change.at))}%` }}
        aria-label={`Revision ${change.seq}: ${labels[change.kind] ?? 'Plan changed'}`}
        title={`${revisionTime(Date.parse(change.at))} · ${labels[change.kind] ?? 'Plan changed'} · #${change.seq}`}
        onClick={(e) => { if (e.detail === 0) onSelect(change.at, change.seq); }} />)}
      {selected >= range.start && selected <= range.end && <div className="plan-revision-playhead"
        style={{ left: `${position(selected)}%` }}><span /></div>}
    </div>
    <div className="plan-revision-caption">
      <span className="plan-history-status" role="status">{status}</span>
      <span>Click to select · Drag to pan · Scroll to zoom · Drag playhead to scrub</span>
    </div>
  </section>;
}
