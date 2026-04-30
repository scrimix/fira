// Outbox sync endpoint: POST /ops accepts a batch of mutation ops, applies
// each in its own transaction, and returns per-op status.
//
// Why per-op (not per-batch) transactions: one bad op (e.g. a stale task_id
// after concurrent delete) shouldn't block the rest of the batch. Each op
// records itself in `processed_ops` for idempotency — a duplicate op_id
// short-circuits without re-applying.
//
// processed_ops also doubles as the change log: every accepted op becomes a
// row with a monotonic `seq`, the original wire payload, and the relevant
// project_id. GET /changes consumes that log scoped to the caller's projects.
//
// Authorization: every op requires the affected resource to live within the
// caller's project_scope (own + member). Cross-tenant writes are rejected
// with NotAuthorized rather than silently no-op'd.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct OpEnvelope {
    pub op_id: String,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    /// Wire-shape JSON of the op. We deserialize a typed `Op` from it for
    /// dispatch, but the original Value is what we persist + replay.
    pub payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub enum Op {
    #[serde(rename = "task.create")]
    TaskCreate { task: TaskInput },
    #[serde(rename = "task.tick")]
    TaskTick { task_id: Uuid, done: bool },
    #[serde(rename = "task.set_status")]
    TaskSetStatus { task_id: Uuid, status: String },
    #[serde(rename = "task.set_section")]
    TaskSetSection { task_id: Uuid, section: String },
    #[serde(rename = "task.set_assignee")]
    TaskSetAssignee { task_id: Uuid, assignee_id: Option<Uuid> },
    #[serde(rename = "task.set_estimate")]
    TaskSetEstimate { task_id: Uuid, estimate_min: Option<i32> },
    #[serde(rename = "task.set_title")]
    TaskSetTitle { task_id: Uuid, title: String },
    #[serde(rename = "task.set_description")]
    TaskSetDescription { task_id: Uuid, description_md: String },
    #[serde(rename = "task.set_external_id")]
    TaskSetExternalId { task_id: Uuid, external_id: Option<String> },
    #[serde(rename = "task.reorder")]
    TaskReorder { project_id: Uuid, section: String, ordered: Vec<Uuid> },
    #[serde(rename = "subtask.create")]
    SubtaskCreate { subtask: SubtaskInput },
    #[serde(rename = "subtask.tick")]
    SubtaskTick { subtask_id: Uuid, done: bool },
    #[serde(rename = "subtask.set_title")]
    SubtaskSetTitle { subtask_id: Uuid, title: String },
    #[serde(rename = "subtask.delete")]
    SubtaskDelete { subtask_id: Uuid },
    #[serde(rename = "block.create")]
    BlockCreate { block: BlockInput },
    #[serde(rename = "block.update")]
    BlockUpdate { block_id: Uuid, patch: BlockPatch },
    #[serde(rename = "block.delete")]
    BlockDelete { block_id: Uuid },
}

impl Op {
    fn kind_str(&self) -> &'static str {
        match self {
            Op::TaskCreate { .. } => "task.create",
            Op::TaskTick { .. } => "task.tick",
            Op::TaskSetStatus { .. } => "task.set_status",
            Op::TaskSetSection { .. } => "task.set_section",
            Op::TaskSetAssignee { .. } => "task.set_assignee",
            Op::TaskSetEstimate { .. } => "task.set_estimate",
            Op::TaskSetTitle { .. } => "task.set_title",
            Op::TaskSetDescription { .. } => "task.set_description",
            Op::TaskSetExternalId { .. } => "task.set_external_id",
            Op::TaskReorder { .. } => "task.reorder",
            Op::SubtaskCreate { .. } => "subtask.create",
            Op::SubtaskTick { .. } => "subtask.tick",
            Op::SubtaskSetTitle { .. } => "subtask.set_title",
            Op::SubtaskDelete { .. } => "subtask.delete",
            Op::BlockCreate { .. } => "block.create",
            Op::BlockUpdate { .. } => "block.update",
            Op::BlockDelete { .. } => "block.delete",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TaskInput {
    pub id: Uuid,
    pub project_id: Uuid,
    #[serde(default)] pub epic_id: Option<Uuid>,
    #[serde(default)] pub sprint_id: Option<Uuid>,
    #[serde(default)] pub assignee_id: Option<Uuid>,
    pub title: String,
    #[serde(default)] pub description_md: String,
    pub section: String,
    pub status: String,
    #[serde(default)] pub priority: Option<String>,
    pub source: String,
    #[serde(default)] pub external_id: Option<String>,
    #[serde(default)] pub estimate_min: Option<i32>,
    #[serde(default)] pub spent_min: i32,
    #[serde(default)] pub tags: Vec<String>,
    #[serde(default = "default_sort")] pub sort_key: String,
}
fn default_sort() -> String { "M".into() }

#[derive(Debug, Deserialize)]
pub struct SubtaskInput {
    pub id: Uuid,
    pub task_id: Uuid,
    pub title: String,
    #[serde(default)] pub done: bool,
    #[serde(default = "default_sort")] pub sort_key: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockInput {
    pub id: Uuid,
    pub task_id: Uuid,
    pub user_id: Uuid,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub state: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct BlockPatch {
    #[serde(default)] pub start_at: Option<DateTime<Utc>>,
    #[serde(default)] pub end_at: Option<DateTime<Utc>>,
    #[serde(default)] pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OpsRequest {
    pub ops: Vec<OpEnvelope>,
}

#[derive(Debug, Serialize)]
pub struct OpResult {
    pub op_id: String,
    pub status: &'static str, // "ok" | "error"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OpsResponse {
    pub results: Vec<OpResult>,
}

pub async fn post_ops(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<OpsRequest>,
) -> Result<(StatusCode, Json<OpsResponse>), StatusCode> {
    let mut results = Vec::with_capacity(req.ops.len());
    for env in req.ops {
        let res = apply_one(&s.pool, user.id, env).await;
        results.push(match res {
            Ok((op_id, _outcome)) => OpResult { op_id, status: "ok", error: None },
            Err((op_id, e)) => {
                tracing::warn!("op {op_id} failed: {e:#}");
                OpResult { op_id, status: "error", error: Some(e.to_string()) }
            }
        });
    }
    Ok((StatusCode::OK, Json(OpsResponse { results })))
}

enum ApplyOutcome {
    Applied,
    AlreadyApplied,
}

async fn apply_one(
    pool: &PgPool,
    user_id: Uuid,
    env: OpEnvelope,
) -> Result<(String, ApplyOutcome), (String, anyhow::Error)> {
    let op_id = env.op_id.clone();
    let payload_value = env.payload.clone();
    let op: Op = match serde_json::from_value(env.payload) {
        Ok(o) => o,
        Err(e) => return Err((op_id, e.into())),
    };
    let kind = op.kind_str().to_string();

    let result: anyhow::Result<ApplyOutcome> = (async {
        let mut tx = pool.begin().await?;

        // Apply the mutation, capturing project_id along the way so we can
        // scope log delivery later. apply_payload returns Err on auth failure.
        let mut project_id: Option<Uuid> = None;
        apply_payload(&mut tx, user_id, op, &mut project_id).await?;

        // Log + idempotency: PK conflict on op_id means a concurrent retry
        // of the same op_id won. Roll back so we don't double-apply.
        let inserted: Option<(i64,)> = sqlx::query_as(
            "INSERT INTO processed_ops (op_id, user_id, kind, payload, project_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (op_id) DO NOTHING
             RETURNING seq",
        )
        .bind(&op_id)
        .bind(user_id)
        .bind(&kind)
        .bind(&payload_value)
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await?;

        if inserted.is_none() {
            tx.rollback().await?;
            return Ok(ApplyOutcome::AlreadyApplied);
        }
        tx.commit().await?;
        Ok(ApplyOutcome::Applied)
    }).await;

    match result {
        Ok(o) => Ok((op_id, o)),
        Err(e) => Err((op_id, e)),
    }
}

async fn apply_payload(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    payload: Op,
    out_project_id: &mut Option<Uuid>,
) -> anyhow::Result<()> {
    match payload {
        Op::TaskCreate { task } => {
            require_project_access(tx, user_id, task.project_id).await?;
            *out_project_id = Some(task.project_id);
            sqlx::query(
                "INSERT INTO tasks (id, project_id, epic_id, sprint_id, assignee_id,
                    title, description_md, section, status, priority,
                    source, external_id, estimate_min, spent_min, tags, sort_key)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(task.id)
            .bind(task.project_id)
            .bind(task.epic_id)
            .bind(task.sprint_id)
            .bind(task.assignee_id)
            .bind(&task.title)
            .bind(&task.description_md)
            .bind(&task.section)
            .bind(&task.status)
            .bind(&task.priority)
            .bind(&task.source)
            .bind(&task.external_id)
            .bind(task.estimate_min)
            .bind(task.spent_min)
            .bind(&task.tags)
            .bind(&task.sort_key)
            .execute(&mut **tx)
            .await?;
        }
        Op::TaskTick { task_id, done } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            let next = if done { "done" } else { "in_progress" };
            sqlx::query("UPDATE tasks SET status = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(next).execute(&mut **tx).await?;
        }
        Op::TaskSetStatus { task_id, status } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            sqlx::query("UPDATE tasks SET status = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(&status).execute(&mut **tx).await?;
        }
        Op::TaskSetSection { task_id, section } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            sqlx::query("UPDATE tasks SET section = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(&section).execute(&mut **tx).await?;
        }
        Op::TaskSetAssignee { task_id, assignee_id } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            sqlx::query("UPDATE tasks SET assignee_id = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(assignee_id).execute(&mut **tx).await?;
        }
        Op::TaskSetEstimate { task_id, estimate_min } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            sqlx::query("UPDATE tasks SET estimate_min = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(estimate_min).execute(&mut **tx).await?;
        }
        Op::TaskSetTitle { task_id, title } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            sqlx::query("UPDATE tasks SET title = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(&title).execute(&mut **tx).await?;
        }
        Op::TaskSetDescription { task_id, description_md } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            sqlx::query("UPDATE tasks SET description_md = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(&description_md).execute(&mut **tx).await?;
        }
        Op::TaskSetExternalId { task_id, external_id } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, task_id).await?);
            // Empty string from the UI = clear (consistent with PATCH semantics).
            let value = external_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
            sqlx::query("UPDATE tasks SET external_id = $2, updated_at = now() WHERE id = $1")
                .bind(task_id).bind(value).execute(&mut **tx).await?;
        }
        Op::TaskReorder { project_id, section: _, ordered } => {
            require_project_access(tx, user_id, project_id).await?;
            *out_project_id = Some(project_id);
            for (i, task_id) in ordered.iter().enumerate() {
                let sort_key = format!("{:08}", (i + 1) * 1000);
                sqlx::query(
                    "UPDATE tasks SET sort_key = $2, updated_at = now()
                     WHERE id = $1 AND project_id = $3",
                )
                .bind(task_id).bind(&sort_key).bind(project_id)
                .execute(&mut **tx).await?;
            }
        }
        Op::SubtaskCreate { subtask } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, subtask.task_id).await?);
            sqlx::query(
                "INSERT INTO subtasks (id, task_id, title, done, sort_key)
                 VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(subtask.id)
            .bind(subtask.task_id)
            .bind(&subtask.title)
            .bind(subtask.done)
            .bind(&subtask.sort_key)
            .execute(&mut **tx).await?;
        }
        Op::SubtaskTick { subtask_id, done } => {
            *out_project_id = Some(ensure_subtask_in_scope(tx, user_id, subtask_id).await?);
            sqlx::query("UPDATE subtasks SET done = $2 WHERE id = $1")
                .bind(subtask_id).bind(done).execute(&mut **tx).await?;
        }
        Op::SubtaskSetTitle { subtask_id, title } => {
            *out_project_id = Some(ensure_subtask_in_scope(tx, user_id, subtask_id).await?);
            sqlx::query("UPDATE subtasks SET title = $2 WHERE id = $1")
                .bind(subtask_id).bind(&title).execute(&mut **tx).await?;
        }
        Op::SubtaskDelete { subtask_id } => {
            *out_project_id = Some(ensure_subtask_in_scope(tx, user_id, subtask_id).await?);
            sqlx::query("DELETE FROM subtasks WHERE id = $1")
                .bind(subtask_id).execute(&mut **tx).await?;
        }
        Op::BlockCreate { block } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, block.task_id).await?);
            sqlx::query(
                "INSERT INTO time_blocks (id, task_id, user_id, start_at, end_at, state)
                 VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(block.id)
            .bind(block.task_id)
            .bind(block.user_id)
            .bind(block.start_at)
            .bind(block.end_at)
            .bind(&block.state)
            .execute(&mut **tx).await?;
        }
        Op::BlockUpdate { block_id, patch } => {
            *out_project_id = Some(ensure_block_in_scope(tx, user_id, block_id).await?);
            sqlx::query(
                "UPDATE time_blocks SET
                    start_at = COALESCE($2, start_at),
                    end_at   = COALESCE($3, end_at),
                    state    = COALESCE($4, state)
                 WHERE id = $1",
            )
            .bind(block_id)
            .bind(patch.start_at)
            .bind(patch.end_at)
            .bind(patch.state)
            .execute(&mut **tx).await?;
        }
        Op::BlockDelete { block_id } => {
            *out_project_id = Some(ensure_block_in_scope(tx, user_id, block_id).await?);
            sqlx::query("DELETE FROM time_blocks WHERE id = $1")
                .bind(block_id).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

// --- /changes ---

#[derive(Debug, Deserialize)]
pub struct ChangesQuery {
    #[serde(default)]
    pub since: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ChangesResponse {
    pub ops: Vec<ChangeEntry>,
    pub cursor: i64,
}

#[derive(Debug, Serialize)]
pub struct ChangeEntry {
    pub seq: i64,
    pub op_id: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub applied_at: DateTime<Utc>,
}

pub async fn get_changes(
    State(s): State<AppState>,
    user: AuthUser,
    Query(q): Query<ChangesQuery>,
) -> ApiResult<Json<ChangesResponse>> {
    let since = q.since.unwrap_or(0);

    // Change-feed scope is broader than the bootstrap scope: a user who was
    // just soft-removed needs to receive the `project.update` op that did
    // the removing so their client can drop the project from local state.
    // We bound that with `applied_at <= removed_at` so the ex-member gets
    // exactly one terminal op and nothing after — no read-leak of ongoing
    // project activity once they're out.
    let rows: Vec<(i64, String, String, serde_json::Value, DateTime<Utc>)> = sqlx::query_as(
        "SELECT po.seq, po.op_id, po.kind, po.payload, po.applied_at
         FROM processed_ops po
         WHERE po.seq > $1
           AND po.project_id IS NOT NULL
           AND (
             po.project_id IN (SELECT id FROM projects WHERE owner_id = $2)
             OR po.project_id IN (
               SELECT pm.project_id FROM project_members pm
               WHERE pm.user_id = $2
                 AND (pm.removed_at IS NULL OR po.applied_at <= pm.removed_at)
             )
           )
         ORDER BY po.seq ASC
         LIMIT 500",
    )
    .bind(since)
    .bind(user.id)
    .fetch_all(&s.pool)
    .await?;

    let cursor = rows.last().map(|r| r.0).unwrap_or(since);
    let ops = rows
        .into_iter()
        .map(|(seq, op_id, kind, payload, applied_at)| ChangeEntry {
            seq, op_id, kind, payload, applied_at,
        })
        .collect();

    Ok(Json(ChangesResponse { ops, cursor }))
}

/// Current cursor — used by /bootstrap so a fresh client knows where to
/// start polling from. Doesn't filter by scope: returning a cursor higher
/// than what the user can currently see is harmless (they'll catch up if
/// scope expands later).
pub async fn current_cursor(pool: &PgPool) -> sqlx::Result<i64> {
    // MAX() over an empty table yields one row with a NULL value — decode
    // as Option, not i64.
    let row: (Option<i64>,) = sqlx::query_as("SELECT MAX(seq) FROM processed_ops")
        .fetch_one(pool)
        .await?;
    Ok(row.0.unwrap_or(0))
}

// --- log helper for non-/ops mutations (project create/update) ---

/// Write a synthesized op to the change log so REST mutations propagate
/// through /changes the same as outbox-driven ones.
pub async fn record_synthesized_op(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    kind: &str,
    payload: serde_json::Value,
    project_id: Option<Uuid>,
) -> sqlx::Result<()> {
    let op_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO processed_ops (op_id, user_id, kind, payload, project_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(op_id)
    .bind(user_id)
    .bind(kind)
    .bind(payload)
    .bind(project_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// --- authorization helpers ---

async fn require_project_access(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    project_id: Uuid,
) -> anyhow::Result<()> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM projects WHERE id = $1
         AND (owner_id = $2 OR id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL))",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_none() {
        anyhow::bail!("project not in scope");
    }
    Ok(())
}

async fn ensure_task_in_scope(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    task_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM tasks t
         JOIN projects p ON p.id = t.project_id
         WHERE t.id = $1
         AND (p.owner_id = $2 OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL))",
    )
    .bind(task_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|(p,)| p).ok_or_else(|| anyhow::anyhow!("task not in scope"))
}

async fn ensure_subtask_in_scope(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    subtask_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM subtasks s
         JOIN tasks t ON t.id = s.task_id
         JOIN projects p ON p.id = t.project_id
         WHERE s.id = $1
         AND (p.owner_id = $2 OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL))",
    )
    .bind(subtask_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|(p,)| p).ok_or_else(|| anyhow::anyhow!("subtask not in scope"))
}

async fn ensure_block_in_scope(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    block_id: Uuid,
) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT t.project_id FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         JOIN projects p ON p.id = t.project_id
         WHERE b.id = $1
         AND (p.owner_id = $2 OR p.id IN (SELECT project_id FROM project_members WHERE user_id = $2 AND removed_at IS NULL))",
    )
    .bind(block_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|(p,)| p).ok_or_else(|| anyhow::anyhow!("block not in scope"))
}

