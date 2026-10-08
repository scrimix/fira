// Time helpers for the calendar grid.
//
// Storage and the wire format are UTC ISO 8601. Display is in the browser's
// local timezone — the calendar grid, week range, and "now" line all anchor
// to local midnight so a user in PST sees Monday start at their 00:00, not
// at 16:00. Day arithmetic uses Date methods (not raw ms) so DST transitions
// don't shift the grid by an hour.

export const HOURS = Array.from({ length: 24 }, (_, i) => i);
export const DAY_LABELS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];

// "Now" provider. Lives behind a function so the playground (and any future
// snapshot/replay mode) can freeze it to the snapshot's timestamp without
// every component reaching for `Date.now()`. Real auth never touches this;
// the override is null and `now()` returns wallclock.
let _frozenNowMs: number | null = null;
export function setFrozenNow(iso: string | null): void {
  _frozenNowMs = iso ? Date.parse(iso) : null;
}
function now(): Date {
  return _frozenNowMs == null ? new Date() : new Date(_frozenNowMs);
}

// Anchors the grid to Monday 00:00 in the user's local timezone, expressed
// as an absolute epoch-ms timestamp. Functions, not const exports, so each
// call re-reads `now()` — important for snapshot mode.
export function weekStartMs(): number {
  const n = now();
  const dayFromMon = (n.getDay() + 6) % 7;
  return new Date(n.getFullYear(), n.getMonth(), n.getDate() - dayFromMon).getTime();
}
export function todayDayIndex(): number {
  return (now().getDay() + 6) % 7;
}
export function nowTimeMin(): number {
  const n = now();
  return n.getHours() * 60 + n.getMinutes();
}

export function weekStartFor(weekOffset: number): number {
  // Step by calendar days, not raw ms, so DST weeks still land on local
  // midnight instead of drifting by an hour.
  const ws = new Date(weekStartMs());
  return new Date(ws.getFullYear(), ws.getMonth(), ws.getDate() + weekOffset * 7).getTime();
}

function addDaysLocal(ms: number, days: number): Date {
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + days);
}

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const MONTHS_FULL = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
];

// --- Month helpers (dashboard) ---
//
// Same rules as the week helpers above: local midnights, day arithmetic
// via Date methods so DST never shifts a cell, and `now()` re-read on
// every call so snapshot mode works.
//
// `monthOffset` counts calendar months from the current one (0 = this
// month, -1 = last). Passing an out-of-range month to the Date
// constructor is well-defined — month 12 rolls into next January — so no
// year arithmetic is needed here.

export function monthStartFor(monthOffset: number): number {
  const n = now();
  return new Date(n.getFullYear(), n.getMonth() + monthOffset, 1).getTime();
}

/// `[start, end)` — local midnight on the 1st, to local midnight on the
/// 1st of the *next* month. End-exclusive so a block starting at 23:30
/// on the last day of the month can't be double-counted by a naive
/// `<=` at the boundary.
export function monthRangeFor(monthOffset: number): { start: number; end: number } {
  const s = new Date(monthStartFor(monthOffset));
  return {
    start: s.getTime(),
    end: new Date(s.getFullYear(), s.getMonth() + 1, 1).getTime(),
  };
}

export function daysInMonthFor(monthOffset: number): number {
  const s = new Date(monthStartFor(monthOffset));
  // Day 0 of the next month is the last day of this one.
  return new Date(s.getFullYear(), s.getMonth() + 1, 0).getDate();
}

export function fmtMonth(monthOffset: number): string {
  const d = new Date(monthStartFor(monthOffset));
  return `${MONTHS_FULL[d.getMonth()]} ${d.getFullYear()}`;
}

export interface MonthCell {
  /// Local midnight of this cell's day — also its bucket key.
  ms: number;
  /// Day of month, for the cell label.
  day: number;
  /// False for the leading/trailing days borrowed from adjacent months,
  /// which the grid dims.
  inMonth: boolean;
}

/// The Mon-anchored calendar layout for a month: always 6 rows of 7, so
/// the grid doesn't change height between a month that needs five rows
/// and one that needs six. Leading and trailing cells come from the
/// adjacent months and are flagged `inMonth: false`.
export function weekdayGridFor(monthOffset: number): MonthCell[] {
  const start = new Date(monthStartFor(monthOffset));
  const lead = (start.getDay() + 6) % 7; // Mon = 0
  const cells: MonthCell[] = [];
  for (let i = 0; i < 42; i++) {
    const d = new Date(start.getFullYear(), start.getMonth(), 1 - lead + i);
    cells.push({
      ms: d.getTime(),
      day: d.getDate(),
      inMonth: d.getMonth() === start.getMonth() && d.getFullYear() === start.getFullYear(),
    });
  }
  return cells;
}

/// Local midnight containing `ms`. The canonical day bucket key — every
/// per-day aggregation keys off this so blocks land in the viewer's day,
/// not UTC's.
export function localMidnight(ms: number): number {
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/// Local midnight of the Monday on or before `ms`. The week bucket key
/// for weekly-cadence goals.
export function weekStartOf(ms: number): number {
  const d = new Date(ms);
  const dayFromMon = (d.getDay() + 6) % 7;
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() - dayFromMon).getTime();
}

// --- Week-axis helpers (plan board) ---
//
// Same rules as above: local midnights, Date-method arithmetic, `now()`
// re-read per call.

/// Local-midnight ms -> `YYYY-MM-DD`.
///
/// NOT `toISOString().slice(0, 10)`. A local midnight east of UTC is the
/// *previous* day in UTC, so that would turn every Monday into a Sunday
/// for anyone ahead of Greenwich — and the sprint span columns are
/// Monday-aligned by CHECK constraint.
export function fmtDateKey(ms: number): string {
  const d = new Date(ms);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${d.getFullYear()}-${mm}-${dd}`;
}

/// `YYYY-MM-DD` -> local-midnight ms. Inverse of `fmtDateKey`.
/// `new Date('2026-10-05')` parses as UTC midnight, hence the explicit
/// component constructor.
export function parseDateKey(key: string): number {
  const [y, m, d] = key.split('-').map(Number);
  return new Date(y, m - 1, d).getTime();
}

/// `[start, end)` over `weekCount` weeks from `weekOffset`, mirroring
/// `monthRangeFor`'s end-exclusive convention.
export function weekRangeFor(weekOffset: number, weekCount: number): { start: number; end: number } {
  const start = weekStartFor(weekOffset);
  return { start, end: addDaysLocal(start, weekCount * 7).getTime() };
}

/// Whole weeks from `aMs` to `bMs`. Both are anchored to their Monday
/// first, and the result is rounded: a span crossing a DST transition is
/// 2.9583 weeks of elapsed milliseconds, and the board needs 3.
export function weeksBetween(aMs: number, bMs: number): number {
  return Math.round((weekStartOf(bMs) - weekStartOf(aMs)) / (7 * 86400000));
}

/// Ascending local-midnight Mondays, `weekCount` of them.
export function weekStartsFor(weekOffset: number, weekCount: number): number[] {
  const first = weekStartFor(weekOffset);
  return Array.from({ length: weekCount }, (_, i) => addDaysLocal(first, i * 7).getTime());
}

/// ISO-8601 week number. The real nearest-Thursday algorithm, not
/// `floor(dayOfYear / 7)` — that gets every year boundary wrong (2027
/// opens in W53 of 2026, and 2024-12-30 is already W01 of 2025).
export function isoWeekNumber(ms: number): number {
  const d = new Date(ms);
  // Thursday of this ISO week decides which year the week belongs to.
  const thursday = new Date(d.getFullYear(), d.getMonth(), d.getDate() - ((d.getDay() + 6) % 7) + 3);
  const jan4 = new Date(thursday.getFullYear(), 0, 4);
  const firstThursday = new Date(
    jan4.getFullYear(), 0, 4 - ((jan4.getDay() + 6) % 7) + 3,
  );
  return 1 + Math.round((thursday.getTime() - firstThursday.getTime()) / (7 * 86400000));
}

export function isoWeekLabel(ms: number): string {
  return `W${String(isoWeekNumber(ms)).padStart(2, '0')}`;
}

/// Month header row for the board, computed from the week list rather
/// than re-derived per column. A week is attributed to the month its
/// Monday falls in, so a week straddling a boundary sits under one
/// header rather than being split.
export function monthSpansFor(weekStarts: number[]): { label: string; weeks: number }[] {
  const out: { label: string; weeks: number }[] = [];
  for (const ms of weekStarts) {
    const d = new Date(ms);
    const label = d.toLocaleDateString(undefined, { month: 'short', year: '2-digit' });
    const last = out[out.length - 1];
    if (last && last.label === label) last.weeks += 1;
    else out.push({ label, weeks: 1 });
  }
  return out;
}

/// Monday starting the fortnight containing `ms`, anchored to *even* ISO
/// weeks so every project in a workspace shares boundaries — two people
/// must never describe the same fortnight differently.
export function fortnightStartOf(ms: number): number {
  const monday = weekStartOf(ms);
  return isoWeekNumber(monday) % 2 === 0 ? monday : addDaysLocal(monday, -7).getTime();
}

export function todayMidnight(): number {
  const n = now();
  return new Date(n.getFullYear(), n.getMonth(), n.getDate()).getTime();
}

export function blockMinutes(b: { start_at: string; end_at: string }): number {
  return (Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000;
}
export function fmtWeekRange(weekStart: number, opts?: { compact?: boolean }): string {
  return fmtDateRange(weekStart, addDaysLocal(weekStart, 6).getTime(), opts);
}

/// The plan board's window as one label: first Monday to last Sunday.
/// Lives here rather than in the crumb so the trailing-day arithmetic
/// stays on `addDaysLocal` — a raw `+ 6 * 86400000` lands at 23:00 the
/// day before across a spring-forward and names the wrong date.
export function fmtWeekSpan(
  weekOffset: number, weekCount: number, opts?: { compact?: boolean },
): string {
  const first = weekStartFor(weekOffset);
  const last = addDaysLocal(weekStartFor(weekOffset + Math.max(1, weekCount) - 1), 6);
  return fmtDateRange(first, last.getTime(), opts);
}

// Inclusive calendar span, collapsing whatever the two ends share:
// "Aug 31 – Sep 6", "Oct 5 – 11", "Aug 31, 2026 – Feb 28, 2027". The
// plan board's crumb spans months, so it needs the general form rather
// than fmtWeekRange's seven-day special case — joining two week labels
// produced "Aug 31 – Sep 6 – Feb 22 – 28".
export function fmtDateRange(
  startMs: number, endMs: number, opts?: { compact?: boolean },
): string {
  const start = new Date(startMs);
  const end = new Date(endMs);
  const sameMonth = start.getMonth() === end.getMonth();
  const sameYear = start.getFullYear() === end.getFullYear();
  const sm = MONTHS[start.getMonth()];
  const em = MONTHS[end.getMonth()];
  // Same month in different years is not the same month.
  const sameMonthSameYear = sameMonth && sameYear;
  // Compact: drop the year — that's the part most likely to push the
  // title to a second line on phones, and it's rarely the disambiguating
  // info in normal use.
  if (opts?.compact) {
    if (sameMonthSameYear) return `${sm} ${start.getDate()} – ${end.getDate()}`;
    return `${sm} ${start.getDate()} – ${em} ${end.getDate()}`;
  }
  if (sameMonthSameYear) {
    return `${sm} ${start.getDate()} – ${end.getDate()}, ${start.getFullYear()}`;
  }
  if (sameYear) {
    return `${sm} ${start.getDate()} – ${em} ${end.getDate()}, ${start.getFullYear()}`;
  }
  return `${sm} ${start.getDate()}, ${start.getFullYear()} – ${em} ${end.getDate()}, ${end.getFullYear()}`;
}

// Lowercase "mon d" anchor for the list's "week of …" caption. Defaults to
// the current week and reads `now()` on every call, so it follows the clock
// (and snapshot mode) instead of freezing at first render.
export function fmtWeekOf(weekStart: number = weekStartMs()): string {
  const d = new Date(weekStart);
  return `${MONTHS[d.getMonth()].toLowerCase()} ${d.getDate()}`;
}

export function dayOfMonthFor(weekStart: number, dayIdx: number): number {
  return addDaysLocal(weekStart, dayIdx).getDate();
}

// Mobile 3-day grid anchor: the local-midnight ms of "yesterday relative to
// today + dayOffset". Column 0 of the 3-day grid is anchored to this date,
// so dayOffset=0 → [yesterday, today, tomorrow]. Used in place of weekStart
// for blockToGrid / gridToBlock when in mobile mode.
export function dayAnchorFor(dayOffset: number): number {
  const n = now();
  return new Date(n.getFullYear(), n.getMonth(), n.getDate() + dayOffset - 1).getTime();
}

// Day-of-week label for a specific date (used by the mobile day headers).
const DOW_LABELS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
export function dayOfWeekLabelFor(anchorMs: number, dayIdx: number): string {
  const d = addDaysLocal(anchorMs, dayIdx);
  return DOW_LABELS[d.getDay()];
}

export function blockToGrid(start_at: string, end_at: string, weekStart: number = weekStartMs()): {
  day: number; start_min: number; dur_min: number;
} {
  const s = new Date(start_at);
  const e = new Date(end_at);
  // Anchor both ends to local midnight before measuring the day diff so a
  // DST transition in the week doesn't push a Tuesday block onto Monday.
  const sMid = new Date(s.getFullYear(), s.getMonth(), s.getDate()).getTime();
  const ws = new Date(weekStart);
  const wsMid = new Date(ws.getFullYear(), ws.getMonth(), ws.getDate()).getTime();
  const day = Math.round((sMid - wsMid) / 86400000);
  const start_min = s.getHours() * 60 + s.getMinutes();
  const dur_min = Math.round((e.getTime() - s.getTime()) / 60000);
  return { day, start_min, dur_min };
}

export function gridToBlock(day: number, start_min: number, dur_min: number, weekStart: number = weekStartMs()): {
  start_at: string; end_at: string;
} {
  const ws = new Date(weekStart);
  const start = new Date(
    ws.getFullYear(), ws.getMonth(), ws.getDate() + day,
    Math.floor(start_min / 60), start_min % 60, 0, 0,
  );
  const end = new Date(start.getTime() + dur_min * 60000);
  return {
    start_at: start.toISOString(),
    end_at: end.toISOString(),
  };
}

// Parse human-friendly duration: "1h30", "1h 30m", "90m", "90", "1.5h" → minutes.
// Returns null if unparseable, 0 for empty.
export function parseEstimate(input: string): number | null {
  const s = input.trim().toLowerCase();
  if (!s) return null;
  let total = 0;
  let matched = false;
  let rest = s;
  const h = rest.match(/(\d+(?:\.\d+)?)\s*h/);
  if (h) {
    total += parseFloat(h[1]) * 60;
    matched = true;
    rest = rest.replace(h[0], ' ');
  }
  const m = rest.match(/(\d+)\s*m?/);
  if (m && m[1]) {
    total += parseInt(m[1], 10);
    matched = true;
  }
  if (!matched) return null;
  return Math.max(0, Math.round(total));
}

export const fmtMin = (m: number | null | undefined): string => {
  if (m == null) return '—';
  // Sign-aware: split off the sign and format the magnitude. JS `%` and
  // `Math.floor` on negatives produced "-4h-15" (both halves carrying the
  // sign) instead of "-4h15".
  const sign = m < 0 ? '-' : '';
  const abs = Math.abs(m);
  const h = Math.floor(abs / 60);
  const r = abs % 60;
  if (h === 0) return `${sign}${r}m`;
  if (r === 0) return `${sign}${h}h`;
  return `${sign}${h}h${String(r).padStart(2, '0')}`;
};

export const fmtClockShort = (m: number): string => {
  const h = Math.floor(m / 60);
  const r = m % 60;
  return `${h}:${String(r).padStart(2, '0')}`;
};

import type { Task, TimeBlock } from './types';

export function taskCompletedMin(task: Task, blocks: TimeBlock[]): number {
  const fromBlocks = blocks
    .filter((b) => b.task_id === task.id && b.state === 'completed')
    .reduce((s, b) => s + (Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000, 0);
  return (task.spent_min ?? 0) + fromBlocks;
}
export function taskPlannedMin(task: Task, blocks: TimeBlock[]): number {
  return blocks
    .filter((b) => b.task_id === task.id && b.state === 'planned')
    .reduce((s, b) => s + (Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000, 0);
}
export function taskTimeLeft(task: Task, blocks: TimeBlock[]): number | null {
  // Signed: negative means more time has been spent + planned than estimated,
  // i.e. the plan has gone over. Callers that only want a non-negative number
  // should clamp themselves.
  if (task.estimate_min == null) return null;
  const todayStart = addDaysLocal(weekStartMs(), todayDayIndex()).getTime();
  const futurePlanned = blocks
    .filter((b) => b.task_id === task.id && b.state === 'planned' && Date.parse(b.start_at) >= todayStart)
    .reduce((s, b) => s + (Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000, 0);
  return task.estimate_min - taskCompletedMin(task, blocks) - futurePlanned;
}
