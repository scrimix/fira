import type { PlanSprintInput, PlanTaskInput, PlanTrackInput } from './plan';

export interface PlanHistory {
  at: string;
  genesis: string | null;
  revision: number | null;
  changes: { at: string; count: number; seq: number; kind: string }[];
  tracks: PlanTrackInput[];
  sprints: PlanSprintInput[];
  tasks: PlanTaskInput[];
}
