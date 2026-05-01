// Time helpers for the calendar grid.
//
// Storage and the wire format are UTC ISO 8601. Display is in the browser's
// local timezone — the calendar grid, week range, and "now" line all anchor
// to local midnight so a user in PST sees Monday start at their 00:00, not
// at 16:00. Day arithmetic uses Date methods (not raw ms) so DST transitions
// don't shift the grid by an hour.

export const HOURS = Array.from({ length: 24 }, (_, i) => i);
export const DAY_LABELS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];

function computeWeekStart(): number {
  const now = new Date();
  const dayFromMon = (now.getDay() + 6) % 7; // 0=Mon..6=Sun
  return new Date(now.getFullYear(), now.getMonth(), now.getDate() - dayFromMon).getTime();
}

// Resolved at module load. Anchors the grid to Monday 00:00 in the user's
// local timezone, expressed as an absolute epoch-ms timestamp.
export const WEEK_START_MS = computeWeekStart();
export const TODAY_DAY_INDEX = (new Date().getDay() + 6) % 7;
export const NOW_TIME_MIN = (() => {
  const n = new Date();
  return n.getHours() * 60 + n.getMinutes();
})();

export function weekStartFor(weekOffset: number): number {
  // Step by calendar days, not raw ms, so DST weeks still land on local
  // midnight instead of drifting by an hour.
  const ws = new Date(WEEK_START_MS);
  return new Date(ws.getFullYear(), ws.getMonth(), ws.getDate() + weekOffset * 7).getTime();
}

function addDaysLocal(ms: number, days: number): Date {
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + days);
}

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
export function fmtWeekRange(weekStartMs: number): string {
  const start = new Date(weekStartMs);
  const end = addDaysLocal(weekStartMs, 6);
  const sameMonth = start.getMonth() === end.getMonth();
  const sameYear = start.getFullYear() === end.getFullYear();
  const sm = MONTHS[start.getMonth()];
  const em = MONTHS[end.getMonth()];
  if (sameMonth) {
    return `${sm} ${start.getDate()} – ${end.getDate()}, ${start.getFullYear()}`;
  }
  if (sameYear) {
    return `${sm} ${start.getDate()} – ${em} ${end.getDate()}, ${start.getFullYear()}`;
  }
  return `${sm} ${start.getDate()}, ${start.getFullYear()} – ${em} ${end.getDate()}, ${end.getFullYear()}`;
}

export function dayOfMonthFor(weekStartMs: number, dayIdx: number): number {
  return addDaysLocal(weekStartMs, dayIdx).getDate();
}

export function blockToGrid(start_at: string, end_at: string, weekStartMs: number = WEEK_START_MS): {
  day: number; start_min: number; dur_min: number;
} {
  const s = new Date(start_at);
  const e = new Date(end_at);
  // Anchor both ends to local midnight before measuring the day diff so a
  // DST transition in the week doesn't push a Tuesday block onto Monday.
  const sMid = new Date(s.getFullYear(), s.getMonth(), s.getDate()).getTime();
  const ws = new Date(weekStartMs);
  const wsMid = new Date(ws.getFullYear(), ws.getMonth(), ws.getDate()).getTime();
  const day = Math.round((sMid - wsMid) / 86400000);
  const start_min = s.getHours() * 60 + s.getMinutes();
  const dur_min = Math.round((e.getTime() - s.getTime()) / 60000);
  return { day, start_min, dur_min };
}

export function gridToBlock(day: number, start_min: number, dur_min: number, weekStartMs: number = WEEK_START_MS): {
  start_at: string; end_at: string;
} {
  const ws = new Date(weekStartMs);
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
  const todayStart = addDaysLocal(WEEK_START_MS, TODAY_DAY_INDEX).getTime();
  const futurePlanned = blocks
    .filter((b) => b.task_id === task.id && b.state === 'planned' && Date.parse(b.start_at) >= todayStart)
    .reduce((s, b) => s + (Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000, 0);
  return task.estimate_min - taskCompletedMin(task, blocks) - futurePlanned;
}
