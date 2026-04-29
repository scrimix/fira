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

export function blockToGrid(start_at: string, end_at: string): {
  day: number; start_min: number; dur_min: number;
} {
  const s = Date.parse(start_at);
  const e = Date.parse(end_at);
  const offsetMin = Math.round((s - WEEK_START_UTC) / 60000);
  const day = Math.floor(offsetMin / (24 * 60));
  const start_min = offsetMin - day * 24 * 60;
  const dur_min = Math.round((e - s) / 60000);
  return { day, start_min, dur_min };
}

export function gridToBlock(day: number, start_min: number, dur_min: number): {
  start_at: string; end_at: string;
} {
  const startMs = WEEK_START_UTC + day * 86400000 + start_min * 60000;
  const endMs = startMs + dur_min * 60000;
  return {
    start_at: new Date(startMs).toISOString(),
    end_at: new Date(endMs).toISOString(),
  };
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
  const ampm = h >= 12 ? 'pm' : 'am';
  const h12 = ((h + 11) % 12) + 1;
  return r === 0 ? `${h12}${ampm}` : `${h12}:${String(r).padStart(2, '0')}${ampm}`;
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
  if (task.estimate_min == null) return null;
  const todayStart = WEEK_START_UTC + TODAY_DAY_INDEX * 86400000;
  const futurePlanned = blocks
    .filter((b) => b.task_id === task.id && b.state === 'planned' && Date.parse(b.start_at) >= todayStart)
    .reduce((s, b) => s + (Date.parse(b.end_at) - Date.parse(b.start_at)) / 60000, 0);
  return Math.max(0, task.estimate_min - taskCompletedMin(task, blocks) - futurePlanned);
}
