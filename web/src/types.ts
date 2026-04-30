// Shapes the API returns. Mirror api/src/models.rs by hand for now —
// not worth a codegen toolchain at this size.

export type UUID = string;

export type Section = 'now' | 'later' | 'done';
export type Status = 'backlog' | 'todo' | 'in_progress' | 'done';
export type Priority = 'p0' | 'p1' | 'p2' | 'p3';
export type Source = 'local' | 'jira' | 'notion';
export type BlockState = 'planned' | 'completed';

export interface User {
  id: UUID;
  email: string;
  name: string;
  initials: string;
}

export interface Project {
  id: UUID;
  title: string;
  icon: string;
  color: string;
  source: Source;
  description: string | null;
  /// URL template for manual issue links. `{key}` is replaced with the
  /// task's `external_id`. Null means no tracker — bare external_ids show
  /// as plain text instead of links.
  external_url_template: string | null;
  members: UUID[];
}

export interface Epic {
  id: UUID;
  project_id: UUID;
  title: string;
}

export interface Sprint {
  id: UUID;
  project_id: UUID;
  title: string;
  dates: string | null;
  active: boolean;
}

export interface Subtask {
  id: UUID;
  task_id: UUID;
  title: string;
  done: boolean;
  sort_key: string;
}

export interface Task {
  id: UUID;
  project_id: UUID;
  epic_id: UUID | null;
  sprint_id: UUID | null;
  assignee_id: UUID | null;
  title: string;
  description_md: string;
  section: Section;
  status: Status;
  priority: Priority | null;
  source: Source;
  external_id: string | null;
  estimate_min: number | null;
  spent_min: number;
  tags: string[];
  sort_key: string;
  subtasks: Subtask[];
}

export interface TimeBlock {
  id: UUID;
  task_id: UUID;
  user_id: UUID;
  start_at: string; // ISO
  end_at: string;
  state: BlockState;
}

export interface GcalEvent {
  id: UUID;
  user_id: UUID;
  title: string;
  start_at: string;
  end_at: string;
}

export interface Bootstrap {
  users: User[];
  projects: Project[];
  epics: Epic[];
  sprints: Sprint[];
  tasks: Task[];
  blocks: TimeBlock[];
  gcal: GcalEvent[];
  /// Initial change-feed cursor — start polling /changes from here.
  cursor: number;
}
