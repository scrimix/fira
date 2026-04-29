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
    pub title: String,
    pub icon: String,
    pub color: String,
    pub source: String,
    pub description: Option<String>,
    #[sqlx(skip)]
    pub members: Vec<Uuid>,
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
