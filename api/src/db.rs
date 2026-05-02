use crate::models::*;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

// Set of project IDs visible to a user, scoped to a single workspace.
// Workspace owners see every project in the workspace (administrative
// scope). Everyone else sees projects they're an explicit member of.
pub async fn project_scope(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
) -> sqlx::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT p.id FROM projects p
         WHERE p.workspace_id = $2
           AND (
             p.id IN (
               SELECT project_id FROM project_members
               WHERE user_id = $1 AND removed_at IS NULL
             )
             OR EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $2 AND wm.user_id = $1
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             )
           )",
    )
    .bind(user_id)
    .bind(workspace_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Whether the caller is a workspace owner. Used wherever owner-only
/// authority matters (workspace mutations, project creation, role
/// changes on project members).
pub async fn is_workspace_owner(
    pool: &PgPool,
    workspace_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<bool> {
    Ok(workspace_role(pool, workspace_id, user_id).await?.as_deref() == Some("owner"))
}

/// Whether the caller has project-edit authority: an explicit `owner` or
/// `lead` row on the project, OR workspace ownership (wildcard across every
/// project). Used by handlers that gate project edits.
pub async fn has_project_lead_authority(
    pool: &PgPool,
    workspace_id: Uuid,
    project_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<bool> {
    if is_workspace_owner(pool, workspace_id, user_id).await? {
        return Ok(true);
    }
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM project_members
         WHERE project_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(r,)| r == "lead" || r == "owner").unwrap_or(false))
}

/// Workspaces a user belongs to (active membership only — soft-removed
/// rows are hidden). Sorted by personal first, then title.
pub async fn list_user_workspaces(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<Workspace>> {
    let mut workspaces: Vec<Workspace> = sqlx::query_as(
        "SELECT w.id, w.title, w.is_personal
         FROM workspaces w
         JOIN workspace_members wm ON wm.workspace_id = w.id
         WHERE wm.user_id = $1 AND wm.removed_at IS NULL
         ORDER BY w.is_personal DESC, w.title",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let ids: Vec<Uuid> = workspaces.iter().map(|w| w.id).collect();
    if ids.is_empty() {
        return Ok(workspaces);
    }
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT workspace_id, user_id, role FROM workspace_members
         WHERE workspace_id = ANY($1) AND removed_at IS NULL",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    let mut by_ws: HashMap<Uuid, Vec<WorkspaceMember>> = HashMap::new();
    for (ws, user, role) in rows {
        by_ws.entry(ws).or_default().push(WorkspaceMember { user_id: user, role });
    }
    for w in &mut workspaces {
        if let Some(m) = by_ws.remove(&w.id) {
            w.members = m;
        }
    }
    Ok(workspaces)
}

/// The caller's role in a workspace, or None if not a member (or removed).
pub async fn workspace_role(
    pool: &PgPool,
    workspace_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM workspace_members
         WHERE workspace_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(workspace_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(r,)| r))
}

/// Create a workspace and seat the creator as `owner`.
pub async fn create_workspace_tx(
    tx: &mut Transaction<'_, Postgres>,
    creator_id: Uuid,
    title: &str,
    is_personal: bool,
) -> sqlx::Result<Workspace> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workspaces (id, title, is_personal, created_by)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(title)
    .bind(is_personal)
    .bind(creator_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, role, removed_at)
         VALUES ($1, $2, 'owner', NULL)",
    )
    .bind(id)
    .bind(creator_id)
    .execute(&mut **tx)
    .await?;
    Ok(Workspace {
        id,
        title: title.to_string(),
        is_personal,
        members: vec![WorkspaceMember { user_id: creator_id, role: "owner".into() }],
    })
}

/// Ensure every Google-authenticated user has a personal workspace. Idempotent
/// — repeats on every login but only inserts if absent.
pub async fn ensure_personal_workspace(
    pool: &PgPool,
    user_id: Uuid,
    user_name: &str,
) -> sqlx::Result<Uuid> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT w.id FROM workspaces w
         JOIN workspace_members wm ON wm.workspace_id = w.id
         WHERE wm.user_id = $1 AND w.is_personal = true AND wm.removed_at IS NULL
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    if let Some((id,)) = existing {
        return Ok(id);
    }
    let mut tx = pool.begin().await?;
    let title = if user_name.trim().is_empty() {
        "Personal".to_string()
    } else {
        format!("{}'s workspace", user_name.split_whitespace().next().unwrap_or(user_name))
    };
    let ws = create_workspace_tx(&mut tx, user_id, &title, true).await?;
    tx.commit().await?;
    Ok(ws.id)
}

/// Hard-delete a workspace. Cascades through projects → tasks/subtasks/
/// blocks/epics/sprints/project_members and through workspace_members.
/// processed_ops is decoupled by migration 0010; the per-user nudge channel
/// (pubsub::Hub::notify_user) is what tells (former) members to refetch
/// their workspace list, since the change-feed scope is now gone.
pub async fn delete_workspace_tx(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query("DELETE FROM workspaces WHERE id = $1")
        .bind(workspace_id)
        .execute(&mut **tx)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn rename_workspace_tx(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    title: &str,
) -> sqlx::Result<Option<Workspace>> {
    let row: Option<(Uuid, String, bool)> = sqlx::query_as(
        "UPDATE workspaces SET title = $2 WHERE id = $1
         RETURNING id, title, is_personal",
    )
    .bind(workspace_id)
    .bind(title)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((id, title, is_personal)) = row else { return Ok(None); };
    let members = list_workspace_members_tx(tx, id).await?;
    Ok(Some(Workspace { id, title, is_personal, members }))
}

async fn list_workspace_members_tx(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
) -> sqlx::Result<Vec<WorkspaceMember>> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT user_id, role FROM workspace_members
         WHERE workspace_id = $1 AND removed_at IS NULL
         ORDER BY role",
    )
    .bind(workspace_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().map(|(user_id, role)| WorkspaceMember { user_id, role }).collect())
}

/// Replace the active member set of a workspace. `desired` is a list of
/// (user_id, role). The acting user (caller) is force-kept as `owner` so a
/// workspace can never lock itself out of management. Members not in the
/// desired list get soft-removed; new members get added (or re-activated if
/// previously removed).
pub async fn set_workspace_members_tx(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    actor_id: Uuid,
    desired: &[(Uuid, String)],
) -> sqlx::Result<Option<Workspace>> {
    let row: Option<(Uuid, String, bool)> = sqlx::query_as(
        "SELECT id, title, is_personal FROM workspaces WHERE id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((id, title, is_personal)) = row else { return Ok(None); };

    // Personal workspaces don't have managed membership — the single owner
    // is fixed at creation. Refuse to touch their member set.
    if is_personal {
        return Ok(Some(Workspace {
            id, title, is_personal,
            members: list_workspace_members_tx(tx, id).await?,
        }));
    }

    let mut want: Vec<(Uuid, String)> = desired.to_vec();
    if !want.iter().any(|(u, _)| *u == actor_id) {
        want.push((actor_id, "owner".to_string()));
    }

    for (uid, role) in &want {
        sqlx::query(
            "INSERT INTO workspace_members (workspace_id, user_id, role, removed_at)
             VALUES ($1, $2, $3, NULL)
             ON CONFLICT (workspace_id, user_id) DO UPDATE
                 SET role = EXCLUDED.role, removed_at = NULL",
        )
        .bind(id)
        .bind(uid)
        .bind(role)
        .execute(&mut **tx)
        .await?;
    }

    let want_ids: Vec<Uuid> = want.iter().map(|(u, _)| *u).collect();
    sqlx::query(
        "UPDATE workspace_members SET removed_at = now()
         WHERE workspace_id = $1 AND removed_at IS NULL AND user_id <> ALL($2)",
    )
    .bind(id)
    .bind(&want_ids)
    .execute(&mut **tx)
    .await?;

    Ok(Some(Workspace {
        id, title, is_personal,
        members: list_workspace_members_tx(tx, id).await?,
    }))
}

/// Update one member's role.
pub async fn set_workspace_member_role_tx(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> sqlx::Result<Option<Workspace>> {
    let updated = sqlx::query(
        "UPDATE workspace_members SET role = $3
         WHERE workspace_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(workspace_id)
    .bind(user_id)
    .bind(role)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(None);
    }
    let row: Option<(Uuid, String, bool)> = sqlx::query_as(
        "SELECT id, title, is_personal FROM workspaces WHERE id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((id, title, is_personal)) = row else { return Ok(None); };
    Ok(Some(Workspace {
        id, title, is_personal,
        members: list_workspace_members_tx(tx, id).await?,
    }))
}

/// Users in a workspace, used by the project editor's Members picker.
pub async fn list_users_in_workspace(
    pool: &PgPool,
    workspace_id: Uuid,
) -> sqlx::Result<Vec<User>> {
    sqlx::query_as(
        "SELECT u.id, u.email, u.name, u.initials
         FROM users u
         JOIN workspace_members wm ON wm.user_id = u.id
         WHERE wm.workspace_id = $1 AND wm.removed_at IS NULL
         ORDER BY u.name",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
}

/// Every user in the system. Used by the workspace settings modal so
/// owners can add people who aren't in any workspace they share yet —
/// a Google-authenticated user who's never been added to a team
/// workspace lives here, even if their personal workspace is the only
/// row connecting them to anything.
pub async fn list_all_users(pool: &PgPool) -> sqlx::Result<Vec<User>> {
    sqlx::query_as("SELECT id, email, name, initials FROM users ORDER BY name")
        .fetch_all(pool)
        .await
}

// Users surfaced to the client = the caller, the active workspace's
// members, and every link partner the caller has (pending sent / received
// / accepted). Linked accounts can live in any workspace — the topbar /
// modal still need their name + initials, so we include them in the
// bootstrap user list regardless of workspace membership.
pub async fn list_users_in_scope(
    pool: &PgPool,
    workspace_id: Uuid,
    me: Uuid,
) -> sqlx::Result<Vec<User>> {
    sqlx::query_as(
        "SELECT DISTINCT u.id, u.email, u.name, u.initials
         FROM users u
         WHERE u.id = $1
            OR u.id IN (SELECT user_id FROM workspace_members
                        WHERE workspace_id = $2 AND removed_at IS NULL)
            OR u.id IN (
                SELECT CASE WHEN user_a_id = $1 THEN user_b_id ELSE user_a_id END
                FROM user_links
                WHERE user_a_id = $1 OR user_b_id = $1
            )
         ORDER BY u.name",
    )
    .bind(me)
    .bind(workspace_id)
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
        "SELECT id, workspace_id, title, icon, color, source, description, external_url_template
         FROM projects WHERE id = ANY($1) ORDER BY title",
    )
    .bind(scope)
    .fetch_all(pool)
    .await?;

    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT project_id, user_id, role FROM project_members
         WHERE project_id = ANY($1) AND removed_at IS NULL",
    )
    .bind(scope)
    .fetch_all(pool)
    .await?;
    let mut by_project: HashMap<Uuid, Vec<ProjectMember>> = HashMap::new();
    for (pid, uid, role) in rows {
        by_project.entry(pid).or_default().push(ProjectMember { user_id: uid, role });
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
                section, status, priority, source, external_id, external_url,
                estimate_min, spent_min, tags, sort_key
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
    workspace_id: Uuid,
    owner_id: Uuid,
    title: &str,
    icon: &str,
    color: &str,
) -> sqlx::Result<Project> {
    let id = Uuid::new_v4();
    // source = 'local' for personal-mode projects; integrations will set it
    // to 'jira'/'notion' through their own write paths later.
    sqlx::query(
        "INSERT INTO projects (id, workspace_id, title, icon, color, source, owner_id)
         VALUES ($1, $2, $3, $4, $5, 'local', $6)",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(title)
    .bind(icon)
    .bind(color)
    .bind(owner_id)
    .execute(&mut **tx)
    .await?;

    // Project creation is gated to workspace owners, so the creator is the
    // workspace owner — they get the per-project 'owner' row, which is
    // hidden from inbox assignee groups by default until they up-rank
    // themselves or get tasks assigned. workspace_id on project_members is
    // filled in by the BEFORE-INSERT trigger.
    sqlx::query(
        "INSERT INTO project_members (project_id, user_id, removed_at, role)
         VALUES ($1, $2, NULL, 'owner')
         ON CONFLICT (project_id, user_id) DO UPDATE
             SET removed_at = NULL, role = 'owner'",
    )
    .bind(id)
    .bind(owner_id)
    .execute(&mut **tx)
    .await?;

    Ok(Project {
        id,
        workspace_id,
        title: title.to_string(),
        icon: icon.to_string(),
        color: color.to_string(),
        source: "local".to_string(),
        description: None,
        external_url_template: None,
        members: vec![ProjectMember { user_id: owner_id, role: "owner".into() }],
    })
}

// Patch visual fields (title/icon/color). None = leave alone. Returns None if
// no row was updated (project doesn't exist OR caller isn't the owner — the
// API layer treats both as 404 to avoid leaking project existence).
// Membership is handled separately by `set_project_members_tx`.
pub async fn update_project_tx(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    title: Option<&str>,
    icon: Option<&str>,
    color: Option<&str>,
    // None = leave unchanged. Some(Some(s)) = set to s. Some(None) = clear.
    external_url_template: Option<Option<&str>>,
) -> sqlx::Result<Option<Project>> {
    // Three-state for nullable field: build the SET clause dynamically so
    // a JSON `null` clears the column while an absent field leaves it.
    let (eut_set, eut_value): (&str, Option<&str>) = match external_url_template {
        None => ("external_url_template", None),
        Some(v) => ("$5", v),
    };
    let sql = format!(
        "UPDATE projects SET
            title = COALESCE($2, title),
            icon  = COALESCE($3, icon),
            color = COALESCE($4, color),
            external_url_template = {eut_set}
         WHERE id = $1
         RETURNING id, workspace_id, title, icon, color, source, description, external_url_template",
    );
    let mut q = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, String, Option<String>, Option<String>)>(&sql)
        .bind(project_id)
        .bind(title)
        .bind(icon)
        .bind(color);
    if external_url_template.is_some() {
        q = q.bind(eut_value);
    }
    let row = q.fetch_optional(&mut **tx).await?;

    let Some((id, workspace_id, title, icon, color, source, description, external_url_template)) = row else {
        return Ok(None);
    };

    let members_rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT user_id, role FROM project_members
         WHERE project_id = $1 AND removed_at IS NULL",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(Some(Project {
        id,
        workspace_id,
        title,
        icon,
        color,
        source,
        description,
        external_url_template,
        members: members_rows.into_iter().map(|(u, r)| ProjectMember { user_id: u, role: r }).collect(),
    }))
}

/// Hard-delete a project. Tasks, subtasks, time_blocks, epics, sprints, and
/// project_members all have ON DELETE CASCADE pointing at projects, so a
/// single DELETE handles the entity tree. processed_ops is decoupled from
/// the cascade by migration 0010 — log rows survive entity deletion.
pub async fn delete_project_tx(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(project_id)
        .execute(&mut **tx)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Look up a project's workspace and its owner — used by handlers to
/// authorize edits before calling update_project_tx / set_project_members_tx.
/// Returns None if the project doesn't exist.
pub async fn project_owner_and_workspace(
    pool: &PgPool,
    project_id: Uuid,
) -> sqlx::Result<Option<(Uuid, Option<Uuid>)>> {
    let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT workspace_id, owner_id FROM projects WHERE id = $1",
    )
    .bind(project_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
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
/// Reconcile project_members for `project_id` to exactly `desired`.
/// Each desired entry is `(user_id, role)`. The current workspace owner is
/// force-included so they can never be locked out — if `desired` names them
/// the role is honored, otherwise they default to `owner`. Workspace
/// ownership is the anchor (rather than `projects.owner_id`, the historical
/// creator) because that's the user who actually has cross-project authority
/// today.
///
/// `allow_role_change`: if false (project lead is editing), existing
/// rows keep their role and new rows are inserted with whatever role is
/// in `desired` *except* `lead`/`owner` — non-owner editors can only add
/// `member`s. Workspace owners pass true and can promote/demote freely,
/// including their own row.
pub async fn set_project_members_tx(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    desired: &[(Uuid, String)],
    allow_role_change: bool,
) -> sqlx::Result<Option<Project>> {
    let row: Option<(Uuid, Uuid, String, String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, workspace_id, title, icon, color, source, description, external_url_template
         FROM projects WHERE id = $1",
    )
    .bind(project_id)
    .fetch_optional(&mut **tx)
    .await?;

    let Some((id, workspace_id, title, icon, color, source, description, external_url_template)) = row else {
        return Ok(None);
    };

    // Look up the workspace owner once so we can force-include them below.
    // There's exactly one owner per workspace under current invariants; if
    // that ever changes, the first row wins and the rest still survive
    // because their existing project_members rows are preserved.
    let ws_owner: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM workspace_members
         WHERE workspace_id = $1 AND role = 'owner' AND removed_at IS NULL
         LIMIT 1",
    )
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;

    let mut want: Vec<(Uuid, String)> = desired.to_vec();
    if let Some((o,)) = ws_owner {
        if !want.iter().any(|(u, _)| *u == o) {
            want.push((o, "owner".into()));
        }
    }

    // Pre-existing rows we have to read so non-owner edits don't accidentally
    // demote a lead. We only consult this when role changes are not allowed.
    let existing: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT user_id, role FROM project_members
         WHERE project_id = $1 AND removed_at IS NULL",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    let existing_role: std::collections::HashMap<Uuid, String> =
        existing.into_iter().collect();

    for (uid, role_in) in &want {
        let role = if allow_role_change {
            role_in.clone()
        } else {
            // Non-owner editing: keep existing role if any, otherwise force 'member'.
            existing_role
                .get(uid)
                .cloned()
                .unwrap_or_else(|| "member".to_string())
        };
        sqlx::query(
            "INSERT INTO project_members (project_id, user_id, removed_at, role)
             VALUES ($1, $2, NULL, $3)
             ON CONFLICT (project_id, user_id) DO UPDATE
                 SET removed_at = NULL, role = EXCLUDED.role",
        )
        .bind(id)
        .bind(uid)
        .bind(&role)
        .execute(&mut **tx)
        .await?;
    }

    let want_ids: Vec<Uuid> = want.iter().map(|(u, _)| *u).collect();
    sqlx::query(
        "UPDATE project_members SET removed_at = now()
         WHERE project_id = $1
           AND removed_at IS NULL
           AND user_id <> ALL($2)",
    )
    .bind(id)
    .bind(&want_ids)
    .execute(&mut **tx)
    .await?;

    let members_rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT user_id, role FROM project_members
         WHERE project_id = $1 AND removed_at IS NULL",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(Some(Project {
        id,
        workspace_id,
        title,
        icon,
        color,
        source,
        description,
        external_url_template,
        members: members_rows.into_iter().map(|(u, r)| ProjectMember { user_id: u, role: r }).collect(),
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

// --- account links ---

/// All links involving the caller (pending sent + received + accepted),
/// projected from the caller's perspective.
pub async fn list_user_links(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<UserLink>> {
    let rows: Vec<(Uuid, Uuid, Uuid, Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>)> =
        sqlx::query_as(
            "SELECT id, user_a_id, user_b_id, requested_by, status, created_at, accepted_at
             FROM user_links
             WHERE user_a_id = $1 OR user_b_id = $1
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(id, a, b, req, status, created_at, accepted_at)| {
            let partner_id = if a == user_id { b } else { a };
            let direction = if status == "accepted" {
                "accepted".to_string()
            } else if req == user_id {
                "sent".to_string()
            } else {
                "received".to_string()
            };
            UserLink { id, partner_id, status, direction, created_at, accepted_at }
        })
        .collect())
}

/// Look up a link row and the two user_ids on it. Used by accept/cancel
/// to authorize the actor and find the partner for nudges.
pub async fn get_link_parties(
    pool: &PgPool,
    link_id: Uuid,
) -> sqlx::Result<Option<(Uuid, Uuid, Uuid, String)>> {
    let row: Option<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT user_a_id, user_b_id, requested_by, status FROM user_links WHERE id = $1",
    )
    .bind(link_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn create_link_request_tx(
    tx: &mut Transaction<'_, Postgres>,
    requester_id: Uuid,
    target_id: Uuid,
) -> sqlx::Result<Option<Uuid>> {
    let (a, b) = if requester_id < target_id {
        (requester_id, target_id)
    } else {
        (target_id, requester_id)
    };
    let row: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO user_links (user_a_id, user_b_id, requested_by, status)
         VALUES ($1, $2, $3, 'pending')
         ON CONFLICT (user_a_id, user_b_id) DO NOTHING
         RETURNING id",
    )
    .bind(a)
    .bind(b)
    .bind(requester_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|(id,)| id))
}

pub async fn accept_link_tx(
    tx: &mut Transaction<'_, Postgres>,
    link_id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "UPDATE user_links SET status = 'accepted', accepted_at = now()
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(link_id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn delete_link_tx(
    tx: &mut Transaction<'_, Postgres>,
    link_id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query("DELETE FROM user_links WHERE id = $1")
        .bind(link_id)
        .execute(&mut **tx)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// The user_id of the caller's accepted partner, if any.
pub async fn accepted_partner_id(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Option<Uuid>> {
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT user_a_id, user_b_id FROM user_links
         WHERE status = 'accepted' AND (user_a_id = $1 OR user_b_id = $1)
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(a, b)| if a == user_id { b } else { a }))
}

/// Linked partner's blocks across **every** workspace they belong to.
/// Linking is mutual consent to share the calendar — the workspace
/// scope rule that gates everything else doesn't apply here.
pub async fn list_blocks_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> sqlx::Result<Vec<TimeBlock>> {
    sqlx::query_as(
        "SELECT id, task_id, user_id, start_at, end_at, state
         FROM time_blocks WHERE user_id = $1 ORDER BY start_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Minimal task projection for the partner's blocks. We only need
/// title + status (for done-state styling) + the project color so the
/// overlay can match the existing block visual language.
pub async fn list_linked_tasks_for_blocks(
    pool: &PgPool,
    block_owner: Uuid,
) -> sqlx::Result<Vec<LinkedTask>> {
    sqlx::query_as(
        "SELECT DISTINCT t.id, t.title, t.status, p.color AS project_color
         FROM tasks t
         JOIN projects p ON p.id = t.project_id
         JOIN time_blocks b ON b.task_id = t.id
         WHERE b.user_id = $1",
    )
    .bind(block_owner)
    .fetch_all(pool)
    .await
}

/// Caller's personal workspace id, if they have one. Used by the
/// personal-overlay endpoint to know which workspace's data to project.
pub async fn personal_workspace_id(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Option<Uuid>> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT w.id FROM workspaces w
         JOIN workspace_members wm ON wm.workspace_id = w.id
         WHERE wm.user_id = $1 AND w.is_personal = true AND wm.removed_at IS NULL
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// Blocks owned by `user_id` whose tasks live under projects in
/// `workspace_id`. Used by the personal-workspace overlay (caller's own
/// blocks but in a different workspace than the active one).
pub async fn list_blocks_in_workspace_for_user(
    pool: &PgPool,
    workspace_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Vec<TimeBlock>> {
    sqlx::query_as(
        "SELECT b.id, b.task_id, b.user_id, b.start_at, b.end_at, b.state
         FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         JOIN projects p ON p.id = t.project_id
         WHERE b.user_id = $1 AND p.workspace_id = $2
         ORDER BY b.start_at",
    )
    .bind(user_id)
    .bind(workspace_id)
    .fetch_all(pool)
    .await
}

/// Minimal task projection for the caller's personal-workspace blocks.
/// Mirrors `list_linked_tasks_for_blocks` but scoped to a workspace
/// rather than to "every block this user owns".
pub async fn list_linked_tasks_in_workspace_for_user(
    pool: &PgPool,
    workspace_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Vec<LinkedTask>> {
    sqlx::query_as(
        "SELECT DISTINCT t.id, t.title, t.status, p.color AS project_color
         FROM tasks t
         JOIN projects p ON p.id = t.project_id
         JOIN time_blocks b ON b.task_id = t.id
         WHERE b.user_id = $1 AND p.workspace_id = $2",
    )
    .bind(user_id)
    .bind(workspace_id)
    .fetch_all(pool)
    .await
}

/// Whether two users are mutually accepted-linked. Used for ad-hoc
/// authorization checks (e.g. /api/linked/calendar) to make sure the
/// caller still has the link before exposing the partner's data.
pub async fn are_linked(pool: &PgPool, a: Uuid, b: Uuid) -> sqlx::Result<bool> {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM user_links
         WHERE user_a_id = $1 AND user_b_id = $2 AND status = 'accepted'",
    )
    .bind(lo)
    .bind(hi)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}
