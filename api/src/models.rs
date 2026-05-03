use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub initials: String,
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
    pub tags: Vec<String>,
    pub sort_key: String,
    #[sqlx(skip)]
    pub subtasks: Vec<Subtask>,
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

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct GcalEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
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
