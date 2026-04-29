use crate::models::*;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub async fn list_users(pool: &PgPool) -> sqlx::Result<Vec<User>> {
    sqlx::query_as::<_, User>("SELECT id, email, name, initials FROM users ORDER BY name")
        .fetch_all(pool)
        .await
}

pub async fn list_projects(pool: &PgPool) -> sqlx::Result<Vec<Project>> {
    let mut projects: Vec<Project> = sqlx::query_as(
        "SELECT id, title, icon, color, source, description
         FROM projects ORDER BY title",
    )
    .fetch_all(pool)
    .await?;

    let rows: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT project_id, user_id FROM project_members")
            .fetch_all(pool)
            .await?;
    let mut by_project: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (pid, uid) in rows {
        by_project.entry(pid).or_default().push(uid);
    }
    for p in &mut projects {
        if let Some(m) = by_project.remove(&p.id) {
            p.members = m;
        }
    }
    Ok(projects)
}

pub async fn list_epics(pool: &PgPool) -> sqlx::Result<Vec<Epic>> {
    sqlx::query_as("SELECT id, project_id, title FROM epics ORDER BY title")
        .fetch_all(pool)
        .await
}

pub async fn list_sprints(pool: &PgPool) -> sqlx::Result<Vec<Sprint>> {
    sqlx::query_as("SELECT id, project_id, title, dates, active FROM sprints ORDER BY title")
        .fetch_all(pool)
        .await
}

pub async fn list_tasks(pool: &PgPool) -> sqlx::Result<Vec<Task>> {
    let mut tasks: Vec<Task> = sqlx::query_as(
        "SELECT id, project_id, epic_id, sprint_id, assignee_id, title, description_md,
                section, status, priority, source, external_id, estimate_min, spent_min,
                tags, sort_key
         FROM tasks
         ORDER BY sort_key, created_at",
    )
    .fetch_all(pool)
    .await?;

    let subs: Vec<Subtask> = sqlx::query_as(
        "SELECT id, task_id, title, done, sort_key FROM subtasks ORDER BY sort_key",
    )
    .fetch_all(pool)
    .await?;
    let mut by_task: HashMap<Uuid, Vec<Subtask>> = HashMap::new();
    for s in subs {
        by_task.entry(s.task_id).or_default().push(s);
    }
    for t in &mut tasks {
        if let Some(s) = by_task.remove(&t.id) {
            t.subtasks = s;
        }
    }
    Ok(tasks)
}

pub async fn list_time_blocks(pool: &PgPool) -> sqlx::Result<Vec<TimeBlock>> {
    sqlx::query_as(
        "SELECT id, task_id, user_id, start_at, end_at, state
         FROM time_blocks
         ORDER BY start_at",
    )
    .fetch_all(pool)
    .await
}

pub async fn list_gcal_events(pool: &PgPool) -> sqlx::Result<Vec<GcalEvent>> {
    sqlx::query_as(
        "SELECT id, user_id, title, start_at, end_at
         FROM gcal_events
         ORDER BY start_at",
    )
    .fetch_all(pool)
    .await
}
