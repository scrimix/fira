use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

// --- authorization helpers ---

// Auth predicate: caller owns the project, is an explicit member, OR is an
// owner/lead of the project's workspace. The workspace_id parameter scopes
// the check so an `X-Workspace-Id` header can't be paired with a project_id
// from a different workspace — the project row's workspace_id must match.
pub async fn require_project_access(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    project_id: Uuid,
) -> anyhow::Result<()> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM projects p
         WHERE id = $1 AND p.workspace_id = $3
           AND (
             p.owner_id = $2
             OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL)
             OR EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             )
           )",
    )
    .bind(project_id)
    .bind(user_id)
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_none() {
        anyhow::bail!("project not in scope");
    }
    Ok(())
}

pub async fn ensure_task_in_scope(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    task_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM tasks t
         JOIN projects p ON p.id = t.project_id
         WHERE t.id = $1 AND p.workspace_id = $3
           AND (
             p.owner_id = $2
             OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL)
             OR EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             )
           )",
    )
    .bind(task_id)
    .bind(user_id)
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|(p,)| p)
        .ok_or_else(|| anyhow::anyhow!("task not in scope"))
}

pub async fn ensure_attachment_in_scope(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    attachment_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM tasks t
         JOIN projects p ON p.id = t.project_id
         JOIN attachments a ON a.task_id = t.id
         WHERE a.id = $1 AND p.workspace_id = $3
           AND (
             p.owner_id = $2
             OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL)
             OR EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             )
           )",
    )
    .bind(attachment_id)
    .bind(user_id)
    .bind(workspace_id)
    .fetch_optional(pool)
    .await?;
    row.map(|(p,)| p)
        .ok_or_else(|| anyhow::anyhow!("task not in scope"))
}

pub async fn ensure_subtask_in_scope(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    subtask_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM subtasks s
         JOIN tasks t ON t.id = s.task_id
         JOIN projects p ON p.id = t.project_id
         WHERE s.id = $1 AND p.workspace_id = $3
           AND (
             p.owner_id = $2
             OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL)
             OR EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             )
           )",
    )
    .bind(subtask_id)
    .bind(user_id)
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|(p,)| p)
        .ok_or_else(|| anyhow::anyhow!("subtask not in scope"))
}

pub async fn ensure_tag_in_scope(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    tag_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM tags t
         JOIN projects p ON p.id = t.project_id
         WHERE t.id = $1 AND p.workspace_id = $3
           AND (
             p.owner_id = $2
             OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL)
             OR EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             )
           )",
    )
    .bind(tag_id)
    .bind(user_id)
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|(p,)| p)
        .ok_or_else(|| anyhow::anyhow!("tag not in scope"))
}

pub async fn ensure_block_in_scope(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    block_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         JOIN projects p ON p.id = t.project_id
         WHERE b.id = $1 AND p.workspace_id = $3
           AND (
             p.owner_id = $2
             OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL)
             OR EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             )
           )",
    )
    .bind(block_id)
    .bind(user_id)
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|(p,)| p)
        .ok_or_else(|| anyhow::anyhow!("block not in scope"))
}
