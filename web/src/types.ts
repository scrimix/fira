// Shapes the API returns. Mirror api/src/models.rs by hand for now —
// not worth a codegen toolchain at this size.

export type UUID = string;

export type Section = 'now' | 'later' | 'done' | 'someday' | 'recurring';
export type Status = 'backlog' | 'todo' | 'in_progress' | 'done';
export type Priority = 'p0' | 'p1' | 'p2' | 'p3';
export type Source = 'local' | 'jira' | 'notion';
export type BlockState = 'planned' | 'completed';

/// The app's top-level surfaces. Single source of truth: the type is
/// derived from the array, so a runtime whitelist (`loadLastView`) and
/// the compile-time union can't drift — they did, and `'dashboard'`
/// breadcrumbs were silently discarded for two sprints as a result.
export const VIEWS = ['calendar', 'list', 'dashboard', 'plan'] as const;
export type ViewName = (typeof VIEWS)[number];

export interface User {
  id: UUID;
  email: string;
  name: string;
  initials: string;
}

/// One row in the login picker. Mirrors `auth::AccountSummary` on the
/// server. `account_badge` lets the UI render "Switch to Personal" /
/// "Switch to Work" instead of raw email chips when the user has
/// tagged an account.
export interface AccountSummary {
  user_id: UUID;
  email: string;
  name: string;
  initials: string;
  avatar_url: string | null;
  account_badge: 'personal' | 'work' | null;
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
  /// Shared Jira Cloud site for this workspace, e.g.
  /// `https://your-domain.atlassian.net`. `null` = Jira not configured.
  /// Owner-editable in WorkspaceModal.
  jira_site_url: string | null;
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
  /// Jira project key (e.g. `FIR`) this project pushes issues to, within
  /// the workspace's configured Jira site. Null = doesn't push to Jira.
  jira_project_key: string | null;
  members: ProjectMember[];
}

/// A plan-board row. `epics` pre-migration 0034.
export interface Track {
  id: UUID;
  project_id: UUID;
  title: string;
  color: string;
  sort_key: string;
  created_at: string;
}

export interface Sprint {
  id: UUID;
  project_id: UUID;
  /// null = "No track" — reachable, not an error. Deleting a track
  /// orphans its sprints rather than destroying them.
  track_id: UUID | null;
  title: string;
  /// Week-aligned Monday, `YYYY-MM-DD`. Start of the card's span.
  starts_on: string | null;
  /// EXCLUSIVE. Colspan is (ends_on - starts_on)/7, no +1.
  ends_on: string | null;
  /// Legacy free-text label. Nothing writes it any more.
  dates: string | null;
  active: boolean;
  sort_key: string;
  created_at: string;
}

export interface Subtask {
  id: UUID;
  task_id: UUID;
  title: string;
  done: boolean;
  sort_key: string;
}

export interface Attachment {
  id: UUID;
  task_id: UUID;
  filename: string;
  storage_path: string;
  content_type: string;
  size_bytes: number;
  created_at: string;
}

export interface Task {
  id: UUID;
  project_id: UUID;
  /// Workstream when the task isn't in a sprint yet. A task's track
  /// resolves as its sprint's track if it has a sprint, else this.
  track_id: UUID | null;
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
  /// Fallback sort key for the Done section when `finished_at` is null
  /// (legacy rows from before migration 0017).
  created_at: string;
  /// User who created the task. Server-managed: stamped on `task.create`
  /// from the acting user. Null on legacy rows from before migration 0017.
  created_by: UUID | null;
  /// ISO timestamp of when the task transitioned into status='done'.
  /// Cleared when the task moves out of done. Server-managed via the
  /// `task.tick` / `task.set_status` ops. Used by the list to sort
  /// the Done section newest-finished-first; falls back to `created_at`
  /// when null.
  finished_at: string | null;
  subtasks: Subtask[];
  attachments: Attachment[];
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
  /// Jira worklog id once this block has been pushed. Null = never pushed.
  jira_worklog_id: string | null;
  /// Last error from a push/resync attempt. Null on success or never tried.
  jira_sync_error: string | null;
}

export interface GcalEvent {
  id: UUID;
  user_id: UUID;
  title: string;
  start_at: string;
  end_at: string;
  description: string | null;
  html_link: string | null;
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
  tasks: WorkTask[];
}

/// `LinkedTask` plus the workspace it lives in. Only `/work/calendar`
/// returns these — its payload is the caller's own blocks in workspaces
/// they belong to, so naming those workspaces leaks nothing.
///
/// The workspace fields exist for the dashboard: `TimeBlock` carries no
/// workspace attribution, so joining `block.task_id` through here is the
/// only way to split other-workspace hours per workspace rather than
/// showing one undifferentiated "Work" total.
export interface WorkTask extends LinkedTask {
  workspace_id: UUID;
  workspace_title: string;
}

/// A named filter over your own blocks with a daily or weekly target,
/// rendered as a block grid on the month dashboard.
///
/// Personal by construction: the server only ever returns your own, and
/// `goal.*` ops are delivered only back to their author. There is no
/// team-level goal.
///
/// Scoped to the active workspace — `workspace_id` and `user_id` are
/// constants from the client's point of view and stay off the wire.
export interface Goal {
  id: UUID;
  name: string;
  cadence: GoalCadence;
  /// Which side of the target counts as success.
  direction: GoalDirection;
  /// null = "any block counts": the period is met if a matching block
  /// exists at all, regardless of duration. Floors only — a cap without
  /// a target is meaningless and the schema rejects it.
  target_min: number | null;
  /// Scope, AND-combined. All null = every block in the workspace.
  /// Note `tag_id` already implies a project, since tags are
  /// project-scoped.
  project_id: UUID | null;
  tag_id: UUID | null;
  task_id: UUID | null;
  sort_key: string;
}

export type GoalCadence = 'daily' | 'weekly';

/// A floor or a cap. `at_least` is the default and the common case
/// ("1h of drawing a day"); `at_most` is the inverse ("no more than 30m
/// of meetings a day").
///
/// The two are not symmetric in the UI. Under a cap an empty period
/// *passes* — no meetings is the ideal outcome — so the grid's
/// interesting state is overshoot rather than shortfall, and "18/31 days
/// met" counts days you stayed under rather than days you reached.
export type GoalDirection = 'at_least' | 'at_most';

/// Available UI color themes. Extending with a new theme: add the value
/// here, add a matching `:root[data-theme="..."]` block in globals.css,
/// widen the DB CHECK constraint (new migration) and VALID_THEMES in
/// the API, and add one more option to ThemePicker in
/// AccountSettingsModal.tsx.
export type Theme = 'classic' | 'dark';

/// UI shape/density style. Orthogonal to `Theme` — the theme picks the
/// palette, the style picks corner radius, elevation and density, so
/// every (theme, style) pair is a valid combination. Extending works the
/// same way as Theme, against `:root[data-style="..."]`, VALID_UI_STYLES
/// and StylePicker.
export type UiStyle = 'classic' | 'modern';

/// Per-user, account-scoped settings. Independent of workspace.
/// Populated from `/api/bootstrap.settings` and updated via
/// `PATCH /api/me/settings`.
export interface UserSettings {
  /// Personal/work mode badge shown next to the topbar avatar. Null
  /// when the user hasn't picked one.
  account_badge: 'personal' | 'work' | null;
  /// UI color theme. Always populated (server defaults to 'classic').
  theme: Theme;
  /// UI shape/density style. Always populated (server defaults to
  /// 'classic'). Independent of `theme`.
  ui_style: UiStyle;
  /// True iff the user has an active Google Calendar connection.
  /// Drives the AccountSettings modal's connected/disconnected UI.
  gcal_connected: boolean;
  /// Email of the connected Google account, when known.
  gcal_email: string | null;
  /// Stored sync error, prefixed by kind:
  ///   - `invalid_grant:` → refresh token dead, must reconnect.
  ///   - `refresh_failed:` → transient (network/5xx during refresh).
  ///   - `sync_failed:`    → transient (network/5xx during fetch).
  /// Cleared on the next successful sync. Null when no error.
  gcal_last_sync_error: string | null;
}

/// Caller's Jira connection status *within the active workspace*. Unlike
/// gcal (account-wide), Jira is scoped per-(user, workspace) — the site
/// itself is a workspace setting (`Workspace.jira_site_url`), so the same
/// person can be connected differently per workspace. Lives on
/// `Bootstrap`, not `UserSettings`, because it varies with the active
/// workspace.
export interface JiraStatus {
  connected: boolean;
  email: string | null;
  last_sync_error: string | null;
  auto_sync_new_blocks: boolean;
}

export interface Bootstrap {
  users: User[];
  projects: Project[];
  tracks: Track[];
  sprints: Sprint[];
  tasks: Task[];
  tags: Tag[];
  blocks: TimeBlock[];
  /// Your own goals in this workspace — never anyone else's.
  goals: Goal[];
  gcal: GcalEvent[];
  links: UserLink[];
  workspace_invites: WorkspaceInvite[];
  /// Initial change-feed cursor — start polling /changes from here.
  cursor: number;
  /// Caller's account-scoped settings.
  settings: UserSettings;
  /// Caller's Jira connection status for this workspace.
  jira: JiraStatus;
}
