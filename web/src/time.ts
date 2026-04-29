// Time helpers for the calendar grid.
//
// The DB stores ISO timestamps. The grid wants (day 0..6, start_min, dur_min)
// relative to the visible week. Anchor: Mon 00:00 in the user's local TZ.
//
// For the seeded mock data, "today" is Wed Apr 29 2026; we hardcode it so the
// calendar's visible week matches the fixture even when the wall clock differs
// — this makes the prototype a reproducible fixture rather than a moving target.

export const HOURS = Array.from({ length: 24 }, (_, i) => i);
export const DAY_LABELS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];

// Mon Apr 27 2026 00:00 PT == 2026-04-27T07:00:00Z (PDT, UTC-7).
// We anchor in UTC to match what the seeder emits.
export const WEEK_START_UTC = Date.parse('2026-04-27T07:00:00Z');
export const TODAY_DAY_INDEX = 2; // Wed
export const NOW_TIME_MIN = 14 * 60 + 32;

export const WEEK_MS = 7 * 86400000;

export function weekStartFor(weekOffset: number): number {
  return WEEK_START_UTC + weekOffset * WEEK_MS;
}

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
export function fmtWeekRange(weekStartMs: number): string {
  const start = new Date(weekStartMs);
  const end = new Date(weekStartMs + 6 * 86400000);
  const sameMonth = start.getUTCMonth() === end.getUTCMonth();
  const sameYear = start.getUTCFullYear() === end.getUTCFullYear();
  const sm = MONTHS[start.getUTCMonth()];
  const em = MONTHS[end.getUTCMonth()];
  if (sameMonth) {
    return `${sm} ${start.getUTCDate()} – ${end.getUTCDate()}, ${start.getUTCFullYear()}`;
  }
  if (sameYear) {
    return `${sm} ${start.getUTCDate()} – ${em} ${end.getUTCDate()}, ${start.getUTCFullYear()}`;
  }
  return `${sm} ${start.getUTCDate()}, ${start.getUTCFullYear()} – ${em} ${end.getUTCDate()}, ${end.getUTCFullYear()}`;
}

export function dayOfMonthFor(weekStartMs: number, dayIdx: number): number {
  return new Date(weekStartMs + dayIdx * 86400000).getUTCDate();
}

export function blockToGrid(start_at: string, end_at: string, weekStartMs: number = WEEK_START_UTC): {
  day: number; start_min: number; dur_min: number;
} {
  const s = Date.parse(start_at);
  const e = Date.parse(end_at);
  const offsetMin = Math.round((s - weekStartMs) / 60000);
  const day = Math.floor(offsetMin / (24 * 60));
  const start_min = offsetMin - day * 24 * 60;
  const dur_min = Math.round((e - s) / 60000);
  return { day, start_min, dur_min };
}

export function gridToBlock(day: number, start_min: number, dur_min: number, weekStartMs: number = WEEK_START_UTC): {
  start_at: string; end_at: string;
} {
  const startMs = weekStartMs + day * 86400000 + start_min * 60000;
  const endMs = startMs + dur_min * 60000;
  return {
    start_at: new Date(startMs).toISOString(),
    end_at: new Date(endMs).toISOString(),
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
  const h = Math.floor(m / 60);
  const r = m % 60;
  if (h === 0) return `${r}m`;
  if (r === 0) return `${h}h`;
  return `${h}h${String(r).padStart(2, '0')}`;
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
  const todayStart = WEEK_START_UTC + TODAY_DAY_INDEX * 86400000;
  const futurePlanned = blocks
    .filter((b) => b.task_id === task.id && b.state === 'planned' && Date.parse(b.start_at) >= todayStart)
    .reduce((s, b) => s + (Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000, 0);
  return task.estimate_min - taskCompletedMin(task, blocks) - futurePlanned;
}
