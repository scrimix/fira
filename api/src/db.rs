use crate::models::*;
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

// Set of project IDs visible to a user: projects they own, plus projects
// they're an explicit member of. In personal mode the second set is empty;
// company mode will populate it via project_members.
pub async fn project_scope(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM projects WHERE owner_id = $1
         UNION
         SELECT project_id FROM project_members WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

// Users surfaced to the client = the caller plus any co-members of their
// projects. Personal mode returns just the caller; company mode includes
// teammates without leaking unrelated users.
pub async fn list_users_in_scope(
    pool: &PgPool,
    scope: &[Uuid],
    me: Uuid,
) -> sqlx::Result<Vec<User>> {
    if scope.is_empty() {
        return sqlx::query_as("SELECT id, email, name, initials FROM users WHERE id = $1")
            .bind(me)
            .fetch_all(pool)
            .await;
    }
    sqlx::query_as(
        "SELECT DISTINCT u.id, u.email, u.name, u.initials
         FROM users u
         WHERE u.id = $1
            OR u.id IN (SELECT user_id FROM project_members WHERE project_id = ANY($2))
            OR u.id IN (SELECT owner_id FROM projects WHERE id = ANY($2) AND owner_id IS NOT NULL)
         ORDER BY u.name",
    )
    .bind(me)
    .bind(scope)
    .fetch_all(pool)
    .await
}

pub async fn list_projects_in_scope(
    pool: &PgPool,
    scope: &[Uuid],
) -> sqlx::Result<Vec<Project>> {
    if scope.is_empty() {
        return Ok(vec![]);
    }
    let mut projects: Vec<Project> = sqlx::query_as(
        "SELECT id, title, icon, color, source, description
         FROM projects WHERE id = ANY($1) ORDER BY title",
    )
    .bind(scope)
    .fetch_all(pool)
    .await?;

    let rows: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT project_id, user_id FROM project_members WHERE project_id = ANY($1)")
            .bind(scope)
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

pub async fn list_epics_in_scope(pool: &PgPool, scope: &[Uuid]) -> sqlx::Result<Vec<Epic>> {
    if scope.is_empty() {
        return Ok(vec![]);
    }
    sqlx::query_as("SELECT id, project_id, title FROM epics WHERE project_id = ANY($1) ORDER BY title")
        .bind(scope)
        .fetch_all(pool)
        .await
}

pub async fn list_sprints_in_scope(pool: &PgPool, scope: &[Uuid]) -> sqlx::Result<Vec<Sprint>> {
    if scope.is_empty() {
        return Ok(vec![]);
    }
    sqlx::query_as(
        "SELECT id, project_id, title, dates, active FROM sprints
         WHERE project_id = ANY($1) ORDER BY title",
    )
    .bind(scope)
    .fetch_all(pool)
    .await
}

pub async fn list_tasks_in_scope(pool: &PgPool, scope: &[Uuid]) -> sqlx::Result<Vec<Task>> {
    if scope.is_empty() {
        return Ok(vec![]);
    }
    let mut tasks: Vec<Task> = sqlx::query_as(
        "SELECT id, project_id, epic_id, sprint_id, assignee_id, title, description_md,
                section, status, priority, source, external_id, estimate_min, spent_min,
                tags, sort_key
         FROM tasks WHERE project_id = ANY($1)
         ORDER BY sort_key, created_at",
    )
    .bind(scope)
    .fetch_all(pool)
    .await?;

    let task_ids: Vec<Uuid> = tasks.iter().map(|t| t.id).collect();
    let subs: Vec<Subtask> = if task_ids.is_empty() {
        vec![]
    } else {
        sqlx::query_as(
            "SELECT id, task_id, title, done, sort_key FROM subtasks
             WHERE task_id = ANY($1) ORDER BY sort_key",
        )
        .bind(&task_ids)
        .fetch_all(pool)
        .await?
    };
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

pub async fn create_project_tx(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    title: &str,
    icon: &str,
    color: &str,
) -> sqlx::Result<Project> {
    let id = Uuid::new_v4();
    // source = 'local' for personal-mode projects; integrations will set it
    // to 'jira'/'notion' through their own write paths later.
    sqlx::query(
        "INSERT INTO projects (id, title, icon, color, source, owner_id)
         VALUES ($1, $2, $3, $4, 'local', $5)",
    )
    .bind(id)
    .bind(title)
    .bind(icon)
    .bind(color)
    .bind(owner_id)
    .execute(&mut **tx)
    .await?;

    // The owner is implicitly a member. Keeps the membership query in
    // `list_users_in_scope` honest and means switching this project to
    // "shared" later is a no-op.
    sqlx::query(
        "INSERT INTO project_members (project_id, user_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(owner_id)
    .execute(&mut **tx)
    .await?;

    Ok(Project {
        id,
        title: title.to_string(),
        icon: icon.to_string(),
        color: color.to_string(),
        source: "local".to_string(),
        description: None,
        members: vec![owner_id],
    })
}

// Patch fields. None = leave alone. Returns None if no row was updated
// (project doesn't exist OR caller isn't the owner — the API layer treats
// both as 404 to avoid leaking project existence).
pub async fn update_project_tx(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    project_id: Uuid,
    title: Option<&str>,
    icon: Option<&str>,
    color: Option<&str>,
) -> sqlx::Result<Option<Project>> {
    let row: Option<(Uuid, String, String, String, String, Option<String>)> = sqlx::query_as(
        "UPDATE projects SET
            title = COALESCE($3, title),
            icon  = COALESCE($4, icon),
            color = COALESCE($5, color)
         WHERE id = $1 AND owner_id = $2
         RETURNING id, title, icon, color, source, description",
    )
    .bind(project_id)
    .bind(owner_id)
    .bind(title)
    .bind(icon)
    .bind(color)
    .fetch_optional(&mut **tx)
    .await?;

    let Some((id, title, icon, color, source, description)) = row else {
        return Ok(None);
    };

    let members: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM project_members WHERE project_id = $1")
            .bind(id)
            .fetch_all(&mut **tx)
            .await?;

    Ok(Some(Project {
        id,
        title,
        icon,
        color,
        source,
        description,
        members: members.into_iter().map(|(u,)| u).collect(),
    }))
}

pub async fn list_blocks_for_user(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<TimeBlock>> {
    sqlx::query_as(
        "SELECT id, task_id, user_id, start_at, end_at, state
         FROM time_blocks WHERE user_id = $1 ORDER BY start_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn list_gcal_for_user(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<GcalEvent>> {
    sqlx::query_as(
        "SELECT id, user_id, title, start_at, end_at
         FROM gcal_events WHERE user_id = $1 ORDER BY start_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}
