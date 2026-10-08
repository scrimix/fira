import type { PlanSprintInput, PlanTaskInput, PlanTrackInput } from './plan';

export interface PlanHistory {
  at: string;
  genesis: string | null;
  revision: number | null;
  tracks: PlanTrackInput[];
  sprints: PlanSprintInput[];
  tasks: PlanTaskInput[];
}

export interface PlanRevisionList {
  genesis: string | null;
  changes: { at: string; count: number; seq: number; kind: string }[];
}

// Keep in sync with the backend projection's PLAN_KINDS.
export const PLAN_HISTORY_KINDS = new Set([
  'task.create', 'task.delete', 'task.set_sprint', 'task.tick', 'task.set_status',
  'task.set_section', 'task.set_title', 'task.reorder', 'task.move_project',
  'track.create', 'track.delete', 'track.set_title', 'track.set_color', 'track.reorder',
  'sprint.create', 'sprint.delete', 'sprint.set_title', 'sprint.set_dates', 'sprint.set_track',
]);
