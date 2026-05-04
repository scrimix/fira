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

export type WorkspaceRole = 'owner' | 'member';
export type ProjectRole = 'owner' | 'lead' | 'member' | 'inactive';

export interface WorkspaceMember {
  user_id: UUID;
  role: WorkspaceRole;
}

export interface Workspace {
  id: UUID;
  title: string;
  is_personal: boolean;
  members: WorkspaceMember[];
}

export interface ProjectMember {
  user_id: UUID;
  role: ProjectRole;
}

export interface Project {
  id: UUID;
  workspace_id: UUID;
  title: string;
  icon: string;
  color: string;
  source: Source;
  description: string | null;
  /// URL template for manual issue links. `{key}` is replaced with the
  /// task's `external_id`. Null means no tracker — bare external_ids show
  /// as plain text instead of links.
  external_url_template: string | null;
  members: ProjectMember[];
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
  /// Optional full URL — overrides the project's URL template at render
  /// time. Set this for trackers without a `{key}` pattern (Notion, etc.).
  external_url: string | null;
  estimate_min: number | null;
  spent_min: number;
  tag_ids: UUID[];
  sort_key: string;
  /// ISO timestamp of when the task was created. Stable across edits.
  /// Used by the inbox to sort the Done section newest-first.
  created_at: string;
  subtasks: Subtask[];
}

export interface Tag {
  id: UUID;
  project_id: UUID;
  title: string;
  /// Hex color (`#rrggbb`).
  color: string;
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

export type LinkStatus = 'pending' | 'accepted';
export type LinkDirection = 'sent' | 'received' | 'accepted';

export interface UserLink {
  id: UUID;
  partner_id: UUID;
  status: LinkStatus;
  direction: LinkDirection;
  created_at: string;
  accepted_at: string | null;
}

/// Workspace invite — email-based membership grant. Bootstrap only
/// returns `pending` rows; resolved (accepted/declined/cancelled)
/// invites disappear from the client.
export type InviteStatus = 'pending' | 'accepted' | 'declined' | 'cancelled';
export type InviteDirection = 'sent' | 'received';
export interface WorkspaceInvite {
  id: UUID;
  workspace_id: UUID;
  workspace_title: string;
  email: string;
  role: WorkspaceRole;
  status: InviteStatus;
  direction: InviteDirection;
  invited_by: UUID;
  invited_by_name: string;
  invited_by_email: string;
  created_at: string;
}

/// Linked partner's task projection — minimal fields needed to render
/// their blocks on the calendar overlay. Read-only.
export interface LinkedTask {
  id: UUID;
  title: string;
  status: Status;
  project_color: string;
}

export interface LinkedCalendar {
  partner_id: UUID;
  blocks: TimeBlock[];
  tasks: LinkedTask[];
  gcal: GcalEvent[];
}

/// Caller's personal-workspace overlay — same shape as LinkedCalendar
/// but without a partner (it's the caller's own data, just from a
/// different workspace) and without gcal (gcal isn't workspace-scoped).
export interface PersonalCalendar {
  blocks: TimeBlock[];
  tasks: LinkedTask[];
}

/// Caller's work-workspace overlay — the inverse of PersonalCalendar.
/// Aggregates the user's own blocks across every non-personal workspace
/// they belong to, projected read-only when the active workspace is
/// personal.
export interface WorkCalendar {
  blocks: TimeBlock[];
  tasks: LinkedTask[];
}

export interface Bootstrap {
  users: User[];
  projects: Project[];
  epics: Epic[];
  sprints: Sprint[];
  tasks: Task[];
  tags: Tag[];
  blocks: TimeBlock[];
  gcal: GcalEvent[];
  links: UserLink[];
  workspace_invites: WorkspaceInvite[];
  /// Initial change-feed cursor — start polling /changes from here.
  cursor: number;
}
