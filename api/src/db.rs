use crate::models::*;
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

// Set of project IDs visible to a user: projects they own, plus projects
// they're an explicit (non-removed) member of. Soft-removed memberships are
// excluded so the project disappears from the user's UI without losing
// historical task assignments stored alongside the row.
pub async fn project_scope(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM projects WHERE owner_id = $1
         UNION
         SELECT project_id FROM project_members
         WHERE user_id = $1 AND removed_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

// Full directory — used by the project editor's Members picker so an owner
// can add a teammate they haven't shared a project with yet. No scope filter
// (we already require auth) but we exclude no one.
pub async fn list_all_users(pool: &PgPool) -> sqlx::Result<Vec<User>> {
    sqlx::query_as("SELECT id, email, name, initials FROM users ORDER BY name")
        .fetch_all(pool)
        .await
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
            OR u.id IN (SELECT user_id FROM project_members
                        WHERE project_id = ANY($2) AND removed_at IS NULL)
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

    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT project_id, user_id FROM project_members
         WHERE project_id = ANY($1) AND removed_at IS NULL",
    )
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
        "INSERT INTO project_members (project_id, user_id, removed_at)
         VALUES ($1, $2, NULL)
         ON CONFLICT (project_id, user_id) DO UPDATE SET removed_at = NULL",
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

// Patch visual fields (title/icon/color). None = leave alone. Returns None if
// no row was updated (project doesn't exist OR caller isn't the owner — the
// API layer treats both as 404 to avoid leaking project existence).
// Membership is handled separately by `set_project_members_tx`.
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

    let members_rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM project_members
         WHERE project_id = $1 AND removed_at IS NULL",
    )
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
        members: members_rows.into_iter().map(|(u,)| u).collect(),
    }))
}

// Reconcile project_members for `project_id` to exactly `desired` (plus the
// owner, who is implicit and force-included so an owner can't lock themselves
// out). New users get inserted (or have their `removed_at` cleared);
// previously-active members not in the desired set get soft-removed by
// stamping `removed_at = now()` — the row stays so historical assignee FKs
// remain valid and we can surface "previously a member" later if needed.
//
// Returns the refreshed Project, or None if the project doesn't exist or the
// caller isn't the owner. Mirrors update_project_tx's not-found behavior.
pub async fn set_project_members_tx(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    project_id: Uuid,
    desired: &[Uuid],
) -> sqlx::Result<Option<Project>> {
    let row: Option<(Uuid, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, title, icon, color, source, description
         FROM projects WHERE id = $1 AND owner_id = $2",
    )
    .bind(project_id)
    .bind(owner_id)
    .fetch_optional(&mut **tx)
    .await?;

    let Some((id, title, icon, color, source, description)) = row else {
        return Ok(None);
    };

    let mut want: Vec<Uuid> = desired.to_vec();
    if !want.contains(&owner_id) {
        want.push(owner_id);
    }

    for u in &want {
        sqlx::query(
            "INSERT INTO project_members (project_id, user_id, removed_at)
             VALUES ($1, $2, NULL)
             ON CONFLICT (project_id, user_id) DO UPDATE SET removed_at = NULL",
        )
        .bind(id)
        .bind(u)
        .execute(&mut **tx)
        .await?;
    }

    sqlx::query(
        "UPDATE project_members SET removed_at = now()
         WHERE project_id = $1
           AND removed_at IS NULL
           AND user_id <> ALL($2)",
    )
    .bind(id)
    .bind(&want)
    .execute(&mut **tx)
    .await?;

    let members_rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM project_members
         WHERE project_id = $1 AND removed_at IS NULL",
    )
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
        members: members_rows.into_iter().map(|(u,)| u).collect(),
    }))
}

// Blocks for any user, scoped to tasks in projects the caller can see.
// The calendar pins multiple teammates (UserPicker) and switches between
// their weeks — so we need everyone's blocks, not just the caller's. The
// task→project FK + scope filter keeps cross-tenant blocks out.
pub async fn list_blocks_in_scope(pool: &PgPool, scope: &[Uuid]) -> sqlx::Result<Vec<TimeBlock>> {
    if scope.is_empty() {
        return Ok(vec![]);
    }
    sqlx::query_as(
        "SELECT b.id, b.task_id, b.user_id, b.start_at, b.end_at, b.state
         FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         WHERE t.project_id = ANY($1)
         ORDER BY b.start_at",
    )
    .bind(scope)
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
