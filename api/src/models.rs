use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub initials: String,
}

/// Per-user, account-scoped settings. Independent of workspace. Today
/// only `account_badge` is wired up (personal/work mode chip in the
/// topbar); future preferences land on this same row.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserSettings {
    /// `personal` or `work`, or NULL when the user hasn't picked yet.
    pub account_badge: Option<String>,
    /// Whether the user has connected their Google Calendar. Sourced from
    /// the presence of a row in `gcal_credentials` (not stored on the
    /// settings row itself), but reported here so the AccountSettings
    /// modal can render the right state on first paint.
    #[sqlx(default)]
    pub gcal_connected: bool,
    /// Email of the connected Google account (the calendar owner).
    /// `None` when not connected.
    #[sqlx(default)]
    pub gcal_email: Option<String>,
    /// Last sync error stored on the credentials row. The web client
    /// branches on the `invalid_grant:` / `refresh_failed:` /
    /// `sync_failed:` prefix to decide between "Reconnect" and a
    /// muted retry hint. `None` when the last sync succeeded or no
    /// sync has run yet.
    #[sqlx(default)]
    pub gcal_last_sync_error: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Project {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub icon: String,
    pub color: String,
    pub source: String,
    pub description: Option<String>,
    /// URL template for the manual issue-link feature. `{key}` is replaced
    /// with the task's `external_id`. NULL = no tracker configured.
    pub external_url_template: Option<String>,
    #[sqlx(skip)]
    pub members: Vec<ProjectMember>,
}

#[derive(Debug, Serialize, sqlx::FromRow, Clone)]
pub struct ProjectMember {
    pub user_id: Uuid,
    /// `lead` or `member`.
    pub role: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Workspace {
    pub id: Uuid,
    pub title: String,
    pub is_personal: bool,
    #[sqlx(skip)]
    pub members: Vec<WorkspaceMember>,
}

#[derive(Debug, Serialize, sqlx::FromRow, Clone)]
pub struct WorkspaceMember {
    pub user_id: Uuid,
    pub role: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Epic {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Sprint {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub dates: Option<String>,
    pub active: bool,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Task {
    pub id: Uuid,
    pub project_id: Uuid,
    pub epic_id: Option<Uuid>,
    pub sprint_id: Option<Uuid>,
    pub assignee_id: Option<Uuid>,
    pub title: String,
    pub description_md: String,
    pub section: String,
    pub status: String,
    pub priority: Option<String>,
    pub source: String,
    pub external_id: Option<String>,
    /// Optional full URL — overrides the project's URL template.
    /// For trackers without a stable `{key}` pattern (Notion, etc.).
    pub external_url: Option<String>,
    pub estimate_min: Option<i32>,
    pub spent_min: i32,
    pub sort_key: String,
    /// Creation wallclock. Set on INSERT (`DEFAULT now()`) and never
    /// touched after. Used by the web inbox to sort the Done section
    /// newest-first — approximate (it's "newest task in Done", not
    /// "most recently finished"), but stable across edits.
    pub created_at: DateTime<Utc>,
    /// User who created the task. Nullable to cover legacy rows from
    /// before migration 0017 where the creator wasn't recorded; new
    /// tasks always have it set to the acting user via the ops handler.
    pub created_by: Option<Uuid>,
    /// Wallclock when the task transitioned into status='done'. Cleared
    /// when the task moves back out of done. Nullable: NULL means the
    /// task hasn't finished. Used by the inbox's Done section to sort
    /// newest-finished-first; client falls back to `created_at` when
    /// `finished_at` is missing.
    pub finished_at: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    pub subtasks: Vec<Subtask>,
    /// IDs of `tags` rows attached to this task. Hydrated via the
    /// `task_tags` join — the column doesn't exist on `tasks` itself.
    #[sqlx(skip)]
    pub tag_ids: Vec<Uuid>,
    #[sqlx(skip)]
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Tag {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    /// Hex (`#rrggbb`) — same palette as projects for now.
    pub color: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Subtask {
    pub id: Uuid,
    pub task_id: Uuid,
    pub title: String,
    pub done: bool,
    pub sort_key: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TimeBlock {
    pub id: Uuid,
    pub task_id: Uuid,
    pub user_id: Uuid,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Attachment {
    pub id: Uuid,
    pub task_id: Uuid,
    pub filename: String,
    pub storage_path: String,
    pub content_type: String,
    pub size: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct GcalEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub description: Option<String>,
    pub html_link: Option<String>,
}

/// A link between two user accounts. Returned to the caller from their
/// own perspective: `partner_id` is the other side, `direction` says who
/// initiated relative to the caller.
#[derive(Debug, Serialize)]
pub struct UserLink {
    pub id: Uuid,
    pub partner_id: Uuid,
    /// `pending` (awaiting accept) or `accepted` (mutual visibility on).
    pub status: String,
    /// `sent` — caller is the requester, awaiting partner accept.
    /// `received` — partner requested, caller can accept.
    /// `accepted` — mutual, no direction matters.
    pub direction: String,
    pub created_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

/// Workspace invite, returned to the caller from their own perspective.
/// Mirrors `UserLink`'s shape: a single row represents one invite, the
/// `direction` field tells the caller whether they sent it or received
/// it. The recipient is matched by canonicalized email — there's no
/// recipient user_id until/unless the invite is accepted.
#[derive(Debug, Serialize)]
pub struct WorkspaceInvite {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub workspace_title: String,
    pub email: String,
    pub role: String,
    /// `pending`, `accepted`, `declined`, or `cancelled`. Bootstrap
    /// only returns `pending`; the others are terminal and the row is
    /// invisible to the client after that.
    pub status: String,
    /// `sent` — caller is the inviter awaiting acceptance.
    /// `received` — invite addressed to caller's email.
    pub direction: String,
    /// Inviter's display name and email so the receive-side modal can
    /// say "Alice (alice@example.com) invited you to Atlas." Always
    /// populated; the inviter is FK-required.
    pub invited_by: Uuid,
    pub invited_by_name: String,
    pub invited_by_email: String,
    pub created_at: DateTime<Utc>,
}

/// Minimal projection of a linked partner's task — what the calendar
/// overlay needs to render their blocks. Cross-workspace, read-only.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct LinkedTask {
    pub id: Uuid,
    pub title: String,
    pub status: String,
    pub project_color: String,
}
