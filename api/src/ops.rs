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
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::ensure_scope::*;
use crate::error::ApiResult;
use crate::AppState;
use crate::{attachments::delete_task_attachments, auth::AuthCtx, storage::StorageBackend};

#[derive(Debug, Deserialize)]
pub struct OpEnvelope {
    pub op_id: String,
    /// Wire-shape JSON of the op. We deserialize a typed `Op` from it for
    /// dispatch, but the original Value is what we persist + replay.
    pub payload: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
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
    TaskSetAssignee {
        task_id: Uuid,
        assignee_id: Option<Uuid>,
    },
    #[serde(rename = "task.set_estimate")]
    TaskSetEstimate {
        task_id: Uuid,
        estimate_min: Option<i32>,
    },
    #[serde(rename = "task.set_title")]
    TaskSetTitle { task_id: Uuid, title: String },
    #[serde(rename = "task.set_description")]
    TaskSetDescription {
        task_id: Uuid,
        description_md: String,
    },
    #[serde(rename = "task.set_external_id")]
    TaskSetExternalId {
        task_id: Uuid,
        external_id: Option<String>,
    },
    #[serde(rename = "task.set_external_url")]
    TaskSetExternalUrl {
        task_id: Uuid,
        external_url: Option<String>,
    },
    #[serde(rename = "task.reorder")]
    TaskReorder {
        project_id: Uuid,
        ordered: Vec<Uuid>,
    },
    #[serde(rename = "task.delete")]
    TaskDelete { task_id: Uuid },
    #[serde(rename = "subtask.create")]
    SubtaskCreate { subtask: SubtaskInput },
    #[serde(rename = "subtask.tick")]
    SubtaskTick { subtask_id: Uuid, done: bool },
    #[serde(rename = "subtask.set_title")]
    SubtaskSetTitle { subtask_id: Uuid, title: String },
    #[serde(rename = "subtask.delete")]
    SubtaskDelete { subtask_id: Uuid },
    #[serde(rename = "subtask.reorder")]
    SubtaskReorder { task_id: Uuid, ordered: Vec<Uuid> },
    #[serde(rename = "block.create")]
    BlockCreate { block: BlockInput },
    #[serde(rename = "block.update")]
    BlockUpdate { block_id: Uuid, patch: BlockPatch },
    #[serde(rename = "block.delete")]
    BlockDelete { block_id: Uuid },
    #[serde(rename = "tag.create")]
    TagCreate { tag: TagInput },
    #[serde(rename = "tag.set_title")]
    TagSetTitle { tag_id: Uuid, title: String },
    #[serde(rename = "tag.set_color")]
    TagSetColor { tag_id: Uuid, color: String },
    #[serde(rename = "tag.delete")]
    TagDelete { tag_id: Uuid },
    #[serde(rename = "task.set_tags")]
    TaskSetTags { task_id: Uuid, tag_ids: Vec<Uuid> },
    // Plan-board ops. Narrow per-field setters, like task.set_assignee:
    // `track_id` is meaningfully nullable ("No track") and sprints are
    // edited by drag rather than a form, so neither goal.update's
    // whole-entity shape nor block.update's `Partial<>` fits.
    #[serde(rename = "track.create")]
    TrackCreate { track: TrackInput },
    #[serde(rename = "track.set_title")]
    TrackSetTitle { track_id: Uuid, title: String },
    #[serde(rename = "track.set_color")]
    TrackSetColor { track_id: Uuid, color: String },
    #[serde(rename = "track.reorder")]
    TrackReorder {
        project_id: Uuid,
        ordered: Vec<Uuid>,
    },
    #[serde(rename = "track.delete")]
    TrackDelete { track_id: Uuid },
    #[serde(rename = "sprint.create")]
    SprintCreate { sprint: SprintInput },
    #[serde(rename = "sprint.set_title")]
    SprintSetTitle { sprint_id: Uuid, title: String },
    // One op for two columns: a span is a single value, and move and
    // resize both emit it. Never independently null.
    #[serde(rename = "sprint.set_dates")]
    SprintSetDates {
        sprint_id: Uuid,
        starts_on: NaiveDate,
        ends_on: NaiveDate,
    },
    #[serde(rename = "sprint.set_track")]
    SprintSetTrack {
        sprint_id: Uuid,
        track_id: Option<Uuid>,
    },
    #[serde(rename = "sprint.delete")]
    SprintDelete { sprint_id: Uuid },
    #[serde(rename = "task.set_sprint")]
    TaskSetSprint {
        task_id: Uuid,
        sprint_id: Option<Uuid>,
    },
    // Goal ops are *private kinds*: see `is_private_kind` and the
    // authorship arm in `get_changes`.
    #[serde(rename = "goal.create")]
    GoalCreate { goal: GoalInput },
    #[serde(rename = "goal.update")]
    GoalUpdate { goal: GoalInput },
    #[serde(rename = "goal.delete")]
    GoalDelete { goal_id: Uuid },
}

/// Op kinds that carry data private to the acting user. `get_changes`
/// delivers these only back to their author, and `apply_payload` must
/// leave `out_project_id` as `None` for them so they never ride a
/// project's fan-out either.
fn is_private_kind(kind: &str) -> bool {
    kind.starts_with("goal.")
}

impl Op {
    pub(crate) fn kind_str(&self) -> &'static str {
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
            Op::TaskSetExternalUrl { .. } => "task.set_external_url",
            Op::TaskReorder { .. } => "task.reorder",
            Op::TaskDelete { .. } => "task.delete",
            Op::SubtaskCreate { .. } => "subtask.create",
            Op::SubtaskTick { .. } => "subtask.tick",
            Op::SubtaskSetTitle { .. } => "subtask.set_title",
            Op::SubtaskDelete { .. } => "subtask.delete",
            Op::SubtaskReorder { .. } => "subtask.reorder",
            Op::BlockCreate { .. } => "block.create",
            Op::BlockUpdate { .. } => "block.update",
            Op::BlockDelete { .. } => "block.delete",
            Op::TagCreate { .. } => "tag.create",
            Op::TagSetTitle { .. } => "tag.set_title",
            Op::TagSetColor { .. } => "tag.set_color",
            Op::TagDelete { .. } => "tag.delete",
            Op::TaskSetTags { .. } => "task.set_tags",
            Op::TrackCreate { .. } => "track.create",
            Op::TrackSetTitle { .. } => "track.set_title",
            Op::TrackSetColor { .. } => "track.set_color",
            Op::TrackReorder { .. } => "track.reorder",
            Op::TrackDelete { .. } => "track.delete",
            Op::SprintCreate { .. } => "sprint.create",
            Op::SprintSetTitle { .. } => "sprint.set_title",
            Op::SprintSetDates { .. } => "sprint.set_dates",
            Op::SprintSetTrack { .. } => "sprint.set_track",
            Op::SprintDelete { .. } => "sprint.delete",
            Op::TaskSetSprint { .. } => "task.set_sprint",
            Op::GoalCreate { .. } => "goal.create",
            Op::GoalUpdate { .. } => "goal.update",
            Op::GoalDelete { .. } => "goal.delete",
        }
    }
}

/// A goal's full definition. `goal.update` replaces all of it rather
/// than patching field-by-field: `target_min` and the three scope refs
/// are all meaningfully nullable, so a COALESCE-style partial patch
/// couldn't distinguish "leave it alone" from "clear it" without
/// double-Option gymnastics. The editor is a modal that submits the
/// whole form anyway.
///
/// Note what is *absent*: `workspace_id` and `user_id`. Both come from
/// `AuthCtx` at apply time, so a client cannot write a goal into
/// another user's row or another workspace.
#[derive(Debug, Deserialize, Serialize)]
pub struct GoalInput {
    pub id: Uuid,
    pub name: String,
    pub cadence: String,
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default)]
    pub target_min: Option<i32>,
    #[serde(default)]
    pub project_id: Option<Uuid>,
    #[serde(default)]
    pub tag_id: Option<Uuid>,
    #[serde(default)]
    pub task_id: Option<Uuid>,
    #[serde(default = "default_sort")]
    pub sort_key: String,
}

fn default_direction() -> String {
    "at_least".into()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TaskInput {
    pub id: Uuid,
    pub project_id: Uuid,
    /// `epic_id` pre-0034. The alias is load-bearing: processed_ops is
    /// never pruned, so older payloads still say `epic_id` and the
    /// scrubber would otherwise null their track link on replay.
    #[serde(default, alias = "epic_id")]
    pub track_id: Option<Uuid>,
    #[serde(default)]
    pub sprint_id: Option<Uuid>,
    #[serde(default)]
    pub assignee_id: Option<Uuid>,
    pub title: String,
    #[serde(default)]
    pub description_md: String,
    pub section: String,
    pub status: String,
    #[serde(default)]
    pub priority: Option<String>,
    pub source: String,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub external_url: Option<String>,
    #[serde(default)]
    pub estimate_min: Option<i32>,
    #[serde(default)]
    pub spent_min: i32,
    #[serde(default)]
    pub tag_ids: Vec<Uuid>,
    #[serde(default = "default_sort")]
    pub sort_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TrackInput {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    #[serde(default = "default_track_color")]
    pub color: String,
    #[serde(default = "default_sort")]
    pub sort_key: String,
}

fn default_track_color() -> String {
    "#334155".into()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SprintInput {
    pub id: Uuid,
    pub project_id: Uuid,
    #[serde(default)]
    pub track_id: Option<Uuid>,
    pub title: String,
    #[serde(default)]
    pub starts_on: Option<NaiveDate>,
    #[serde(default)]
    pub ends_on: Option<NaiveDate>,
    #[serde(default = "default_sort")]
    pub sort_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TagInput {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub color: String,
}
fn default_sort() -> String {
    "M".into()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubtaskInput {
    pub id: Uuid,
    pub task_id: Uuid,
    pub title: String,
    #[serde(default)]
    pub done: bool,
    #[serde(default = "default_sort")]
    pub sort_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockInput {
    pub id: Uuid,
    pub task_id: Uuid,
    pub user_id: Uuid,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct BlockPatch {
    #[serde(default)]
    pub start_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub state: Option<String>,
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
    ctx: AuthCtx,
    Json(req): Json<OpsRequest>,
) -> Result<(StatusCode, Json<OpsResponse>), StatusCode> {
    let mut results = Vec::with_capacity(req.ops.len());
    for env in req.ops {
        let res = apply_one(&s.pool, ctx.user.id, ctx.workspace_id, env, &s.storage).await;
        results.push(match res {
            Ok((op_id, _outcome)) => OpResult {
                op_id,
                status: "ok",
                error: None,
            },
            Err((op_id, e)) => {
                // Transient DB errors (stale pool connection killed by
                // the server, pool timeout, network blip) used to surface
                // as a per-op `status: "error"`, which the frontend
                // treats as a permanent rejection — the user sees
                // `block.update rejected` and has to manually retry.
                // Bail out of the whole batch with 503 instead so the
                // outbox catch path re-queues for the next tick. The
                // partial work is safe to redo: the per-op idempotency
                // check (`already_applied`) drops duplicates server-
                // side. Genuine validation errors (BadRequest, etc.)
                // still flow through as per-op status: "error".
                if is_transient_db_error(&e) {
                    tracing::warn!("op {op_id} transient DB error, returning 503: {e:#}");
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                tracing::warn!("op {op_id} failed: {e:#}");
                OpResult {
                    op_id,
                    status: "error",
                    error: Some(e.to_string()),
                }
            }
        });
    }
    Ok((StatusCode::OK, Json(OpsResponse { results })))
}

/// `true` for errors that mean "try again later, the data layer
/// hiccuped" — connection-was-closed (`Io`), pool exhaustion, pool
/// shutting down. Genuine business-logic / constraint-violation errors
/// from `sqlx::Error::Database` are *not* transient — those should
/// surface as per-op rejections so the user can resolve them.
fn is_transient_db_error(e: &anyhow::Error) -> bool {
    if let Some(sqlx_err) = e.downcast_ref::<sqlx::Error>() {
        return matches!(
            sqlx_err,
            sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed,
        );
    }
    false
}

enum ApplyOutcome {
    Applied,
    AlreadyApplied,
}

async fn apply_one(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    env: OpEnvelope,
    storage: &StorageBackend,
) -> Result<(String, ApplyOutcome), (String, anyhow::Error)> {
    let op_id = env.op_id.clone();
    let payload_value = env.payload.clone();
    let op: Op = match serde_json::from_value(env.payload) {
        Ok(o) => o,
        Err(e) => return Err((op_id, e.into())),
    };
    let kind = op.kind_str().to_string();
    // Captured before `op` moves into apply_payload below — used after
    // commit to fire background Jira work. These reads run against `pool`
    // directly, outside the mutation transaction below: it's a best-effort
    // snapshot for a fire-and-forget follow-up call, not something that
    // needs to be transactionally consistent with the write it follows.
    //
    // block_update_id: resyncs a worklog that was already pushed. First
    // push is manual-only (see jira.rs); this only keeps it in sync with
    // further edits.
    let block_update_id: Option<Uuid> = match &op {
        Op::BlockUpdate { block_id, .. } => Some(*block_id),
        _ => None,
    };
    // block_create_id: makes the *first* push for a brand-new block, but
    // only if its owner opted into auto-sync (see
    // `jira::auto_sync_new_block_if_enabled`) — everyone else still relies
    // on the manual "Log to Jira" button for that first push.
    let block_create_id: Option<Uuid> = match &op {
        Op::BlockCreate { block } => Some(block.id),
        _ => None,
    };
    // pending_worklog_deletes: a block/task delete may be orphaning a Jira
    // worklog. Looked up now because the row(s) needed to find it won't
    // exist after apply_payload's delete goes through below.
    let pending_worklog_deletes: Vec<crate::jira::PendingWorklogDelete> = match &op {
        Op::BlockDelete { block_id } => crate::jira::pending_worklog_delete(pool, *block_id)
            .await
            .unwrap_or(None)
            .into_iter()
            .collect(),
        Op::TaskDelete { task_id } => crate::jira::pending_worklog_deletes_for_task(pool, *task_id)
            .await
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    let result: anyhow::Result<ApplyOutcome> = (async {
        let mut tx = pool.begin().await?;

        // Apply the mutation, capturing project_id along the way so we can
        // scope log delivery later. apply_payload returns Err on auth failure.
        let mut project_id: Option<Uuid> = None;
        apply_payload(&mut tx, user_id, workspace_id, op, &mut project_id, storage).await?;

        // A private kind that picked up a project_id would be delivered
        // to that project's members by the arm in `get_changes`. Fail
        // loudly here rather than leaking quietly if someone later adds
        // an `out_project_id` assignment to a goal branch.
        if is_private_kind(&kind) && project_id.is_some() {
            anyhow::bail!("private op kind {kind} must not carry a project_id");
        }

        // Log + idempotency: PK conflict on op_id means a concurrent retry
        // of the same op_id won. Roll back so we don't double-apply.
        let inserted: Option<(i64,)> = sqlx::query_as(
            "INSERT INTO processed_ops (op_id, user_id, kind, payload, project_id, workspace_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (op_id) DO NOTHING
             RETURNING seq",
        )
        .bind(&op_id)
        .bind(user_id)
        .bind(&kind)
        .bind(&payload_value)
        .bind(project_id)
        .bind(workspace_id)
        .fetch_optional(&mut *tx)
        .await?;

        let seq = match inserted {
            Some((s,)) => s,
            None => {
                tx.rollback().await?;
                return Ok(ApplyOutcome::AlreadyApplied);
            }
        };
        // Nudge: fires only on commit (NOTIFY is transactional). Listeners
        // on every API instance receive it and dispatch to local WS clients.
        sqlx::query("SELECT pg_notify('ops_changes', $1)")
            .bind(crate::pubsub::format_payload(workspace_id, seq))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(ApplyOutcome::Applied)
    })
    .await;

    // Fire-and-forget: never let Jira's latency/availability sit on the
    // critical path of an /ops response. Same posture as gcal's background
    // sync from bootstrap.
    if matches!(result, Ok(ApplyOutcome::Applied)) {
        if let Some(block_id) = block_update_id {
            let pool = pool.clone();
            tokio::spawn(async move {
                crate::jira::resync_block_if_linked(&pool, workspace_id, block_id).await;
            });
        }
        if let Some(block_id) = block_create_id {
            let pool = pool.clone();
            tokio::spawn(async move {
                crate::jira::auto_sync_new_block_if_enabled(&pool, workspace_id, block_id).await;
            });
        }
        for job in pending_worklog_deletes {
            let pool = pool.clone();
            tokio::spawn(async move {
                crate::jira::delete_worklog_if_linked(&pool, workspace_id, job).await;
            });
        }
    }

    match result {
        Ok(o) => Ok((op_id, o)),
        Err(e) => Err((op_id, e)),
    }
}

/// Check a goal's scope refs resolve inside the caller's view of this
/// workspace. Each ref is validated with the same helper the
/// corresponding entity's own ops use, so a goal can't be used as a
/// side-channel to probe for ids the caller can't otherwise see.
///
/// The return value is discarded on purpose: these calls are for their
/// authorization effect, not to learn a project id. Learning one would
/// tempt a caller into setting `out_project_id`, which is exactly what
/// must not happen for a private kind.
async fn validate_goal(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    goal: &GoalInput,
) -> anyhow::Result<()> {
    if goal.cadence != "daily" && goal.cadence != "weekly" {
        anyhow::bail!("cadence must be daily or weekly");
    }
    if goal.name.trim().is_empty() {
        anyhow::bail!("goal name is required");
    }
    if goal.direction != "at_least" && goal.direction != "at_most" {
        anyhow::bail!("direction must be at_least or at_most");
    }
    if let Some(min) = goal.target_min {
        if min <= 0 {
            anyhow::bail!("target_min must be positive when set");
        }
    } else if goal.direction == "at_most" {
        // Mirrors goals_cap_needs_target. Caught here so the client gets
        // a readable per-op error instead of a raw constraint violation.
        anyhow::bail!("an at_most goal needs a target");
    }
    if let Some(project_id) = goal.project_id {
        require_project_access(tx, user_id, workspace_id, project_id).await?;
    }
    if let Some(tag_id) = goal.tag_id {
        ensure_tag_in_scope(tx, user_id, workspace_id, tag_id).await?;
    }
    if let Some(task_id) = goal.task_id {
        ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?;
    }
    Ok(())
}

/// Mirror of the CHECKs in 0034, caught here so the client gets a
/// readable per-op error instead of a raw constraint violation.
/// `[starts_on, ends_on)` — end-exclusive, both week-aligned Mondays.
fn validate_span(starts_on: NaiveDate, ends_on: NaiveDate) -> anyhow::Result<()> {
    if ends_on <= starts_on {
        anyhow::bail!("a sprint's ends_on must be after its starts_on");
    }
    if starts_on.weekday().number_from_monday() != 1 || ends_on.weekday().number_from_monday() != 1 {
        anyhow::bail!("a sprint's starts_on and ends_on must both be Mondays");
    }
    Ok(())
}

/// The single apply seam: every content mutation in the system goes
/// through here. `/ops` calls it per-op, the seeder replays its backdated
/// fixture through it, and the integration tests drive it directly — so
/// there is exactly one implementation of what an op means.
pub async fn apply_payload(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    payload: Op,
    out_project_id: &mut Option<Uuid>,
    storage: &StorageBackend,
) -> anyhow::Result<()> {
    match payload {
        Op::TaskCreate { task } => {
            require_project_access(tx, user_id, workspace_id, task.project_id).await?;
            *out_project_id = Some(task.project_id);
            sqlx::query(
                "INSERT INTO tasks (id, project_id, track_id, sprint_id, assignee_id,
                    title, description_md, section, status, priority,
                    source, external_id, external_url, estimate_min, spent_min, sort_key,
                    created_by)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(task.id)
            .bind(task.project_id)
            .bind(task.track_id)
            .bind(task.sprint_id)
            .bind(task.assignee_id)
            .bind(&task.title)
            .bind(&task.description_md)
            .bind(&task.section)
            .bind(&task.status)
            .bind(&task.priority)
            .bind(&task.source)
            .bind(&task.external_id)
            .bind(&task.external_url)
            .bind(task.estimate_min)
            .bind(task.spent_min)
            .bind(&task.sort_key)
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
            // Re-apply tag links idempotently. If task.create lost the race
            // with a concurrent create (ON CONFLICT DO NOTHING above), the
            // earlier writer's links stand, but applying our own links on
            // top of theirs is safe — same task, same intent.
            for tag_id in &task.tag_ids {
                sqlx::query(
                    "INSERT INTO task_tags (task_id, tag_id) VALUES ($1, $2)
                     ON CONFLICT DO NOTHING",
                )
                .bind(task.id)
                .bind(tag_id)
                .execute(&mut **tx)
                .await?;
            }
        }
        Op::TaskTick { task_id, done } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            let next = if done { "done" } else { "in_progress" };
            // finished_at is server-managed: stamped on transition into
            // 'done', cleared on transition out. Set unconditionally on the
            // transition direction — re-ticking a task already done bumps
            // the timestamp to the most recent finish, which matches the
            // intent of "newest finished first" in the Done section.
            sqlx::query(
                "UPDATE tasks SET status = $2, updated_at = now(),
                    finished_at = CASE WHEN $3 THEN now() ELSE NULL END
                 WHERE id = $1",
            )
            .bind(task_id)
            .bind(next)
            .bind(done)
            .execute(&mut **tx)
            .await?;
        }
        Op::TaskSetStatus { task_id, status } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            // Same finished_at policy as task.tick: any status transition
            // into 'done' stamps it, any transition away clears it. CASE
            // is on the *new* status only — we don't need the old one to
            // pick the right side.
            sqlx::query(
                "UPDATE tasks SET status = $2, updated_at = now(),
                    finished_at = CASE WHEN $2 = 'done' THEN now() ELSE NULL END
                 WHERE id = $1",
            )
            .bind(task_id)
            .bind(&status)
            .execute(&mut **tx)
            .await?;
        }
        Op::TaskSetSection { task_id, section } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            sqlx::query("UPDATE tasks SET section = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(&section)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetAssignee {
            task_id,
            assignee_id,
        } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            sqlx::query("UPDATE tasks SET assignee_id = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(assignee_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetEstimate {
            task_id,
            estimate_min,
        } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            sqlx::query("UPDATE tasks SET estimate_min = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(estimate_min)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetTitle { task_id, title } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            sqlx::query("UPDATE tasks SET title = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(&title)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetDescription {
            task_id,
            description_md,
        } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            sqlx::query("UPDATE tasks SET description_md = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(&description_md)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetExternalId {
            task_id,
            external_id,
        } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            // Empty string from the UI = clear (consistent with PATCH semantics).
            let value = external_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            sqlx::query("UPDATE tasks SET external_id = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(value)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetExternalUrl {
            task_id,
            external_url,
        } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            let value = external_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            // Soft validation — same shape as projects.external_url_template.
            if let Some(u) = value {
                if u.len() > 2048 || !(u.starts_with("http://") || u.starts_with("https://")) {
                    anyhow::bail!("external_url must be an http(s) URL ≤ 2048 chars");
                }
            }
            sqlx::query("UPDATE tasks SET external_url = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(value)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskReorder {
            project_id,
            ordered,
        } => {
            require_project_access(tx, user_id, workspace_id, project_id).await?;
            *out_project_id = Some(project_id);
            for (i, task_id) in ordered.iter().enumerate() {
                let sort_key = format!("{:08}", (i + 1) * 1000);
                sqlx::query(
                    "UPDATE tasks SET sort_key = $2, updated_at = now()
                     WHERE id = $1 AND project_id = $3",
                )
                .bind(task_id)
                .bind(&sort_key)
                .bind(project_id)
                .execute(&mut **tx)
                .await?;
            }
        }
        Op::TaskDelete { task_id } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            delete_task_attachments(tx, storage, task_id).await?;
            // subtasks + time_blocks cascade via FK ON DELETE CASCADE.
            sqlx::query("DELETE FROM tasks WHERE id = $1")
                .bind(task_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::SubtaskCreate { subtask } => {
            *out_project_id =
                Some(ensure_task_in_scope(tx, user_id, workspace_id, subtask.task_id).await?);
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
            .execute(&mut **tx)
            .await?;
        }
        Op::SubtaskTick { subtask_id, done } => {
            *out_project_id =
                Some(ensure_subtask_in_scope(tx, user_id, workspace_id, subtask_id).await?);
            sqlx::query("UPDATE subtasks SET done = $2 WHERE id = $1")
                .bind(subtask_id)
                .bind(done)
                .execute(&mut **tx)
                .await?;
        }
        Op::SubtaskSetTitle { subtask_id, title } => {
            *out_project_id =
                Some(ensure_subtask_in_scope(tx, user_id, workspace_id, subtask_id).await?);
            sqlx::query("UPDATE subtasks SET title = $2 WHERE id = $1")
                .bind(subtask_id)
                .bind(&title)
                .execute(&mut **tx)
                .await?;
        }
        Op::SubtaskDelete { subtask_id } => {
            *out_project_id =
                Some(ensure_subtask_in_scope(tx, user_id, workspace_id, subtask_id).await?);
            sqlx::query("DELETE FROM subtasks WHERE id = $1")
                .bind(subtask_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::SubtaskReorder { task_id, ordered } => {
            *out_project_id = Some(ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?);
            // Same `M{NNN}` sort_key scheme tasks use — fixed-width so a
            // text comparison gives the desired order.
            for (i, sub_id) in ordered.iter().enumerate() {
                let sort_key = format!("M{:03}", i);
                sqlx::query("UPDATE subtasks SET sort_key = $2 WHERE id = $1 AND task_id = $3")
                    .bind(sub_id)
                    .bind(&sort_key)
                    .bind(task_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        Op::BlockCreate { block } => {
            *out_project_id =
                Some(ensure_task_in_scope(tx, user_id, workspace_id, block.task_id).await?);
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
            .execute(&mut **tx)
            .await?;
        }
        Op::BlockUpdate { block_id, patch } => {
            *out_project_id =
                Some(ensure_block_in_scope(tx, user_id, workspace_id, block_id).await?);
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
            .execute(&mut **tx)
            .await?;
        }
        Op::BlockDelete { block_id } => {
            *out_project_id =
                Some(ensure_block_in_scope(tx, user_id, workspace_id, block_id).await?);
            sqlx::query("DELETE FROM time_blocks WHERE id = $1")
                .bind(block_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::TagCreate { tag } => {
            require_project_access(tx, user_id, workspace_id, tag.project_id).await?;
            *out_project_id = Some(tag.project_id);
            sqlx::query(
                "INSERT INTO tags (id, project_id, title, color)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(tag.id)
            .bind(tag.project_id)
            .bind(&tag.title)
            .bind(&tag.color)
            .execute(&mut **tx)
            .await?;
        }
        Op::TagSetTitle { tag_id, title } => {
            *out_project_id = Some(ensure_tag_in_scope(tx, user_id, workspace_id, tag_id).await?);
            sqlx::query("UPDATE tags SET title = $2 WHERE id = $1")
                .bind(tag_id)
                .bind(&title)
                .execute(&mut **tx)
                .await?;
        }
        Op::TagSetColor { tag_id, color } => {
            *out_project_id = Some(ensure_tag_in_scope(tx, user_id, workspace_id, tag_id).await?);
            sqlx::query("UPDATE tags SET color = $2 WHERE id = $1")
                .bind(tag_id)
                .bind(&color)
                .execute(&mut **tx)
                .await?;
        }
        Op::TagDelete { tag_id } => {
            *out_project_id = Some(ensure_tag_in_scope(tx, user_id, workspace_id, tag_id).await?);
            // task_tags rows cascade via FK ON DELETE CASCADE.
            sqlx::query("DELETE FROM tags WHERE id = $1")
                .bind(tag_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::GoalCreate { goal } | Op::GoalUpdate { goal } => {
            // Deliberately no `*out_project_id = ...`, even when the
            // goal is scoped to a project: setting it would fan the op
            // out to every member of that project. Goals reach their
            // author through the private-kind arm in `get_changes`.
            validate_goal(tx, user_id, workspace_id, &goal).await?;
            // Upsert, so create and update share one statement and a
            // replayed create after an edit can't clobber the edit's
            // ownership. The WHERE guard means an id belonging to
            // another user is a no-op rather than a takeover.
            sqlx::query(
                "INSERT INTO goals
                    (id, workspace_id, user_id, name, cadence, direction,
                     target_min, project_id, tag_id, task_id, sort_key)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                 ON CONFLICT (id) DO UPDATE SET
                    name       = EXCLUDED.name,
                    cadence    = EXCLUDED.cadence,
                    direction  = EXCLUDED.direction,
                    target_min = EXCLUDED.target_min,
                    project_id = EXCLUDED.project_id,
                    tag_id     = EXCLUDED.tag_id,
                    task_id    = EXCLUDED.task_id,
                    sort_key   = EXCLUDED.sort_key
                 WHERE goals.user_id = $3 AND goals.workspace_id = $2",
            )
            .bind(goal.id)
            .bind(workspace_id)
            .bind(user_id)
            .bind(&goal.name)
            .bind(&goal.cadence)
            .bind(&goal.direction)
            .bind(goal.target_min)
            .bind(goal.project_id)
            .bind(goal.tag_id)
            .bind(goal.task_id)
            .bind(&goal.sort_key)
            .execute(&mut **tx)
            .await?;
        }
        Op::GoalDelete { goal_id } => {
            // Scoped by user_id: deleting someone else's goal is a
            // no-op, not an error, matching the idempotent posture of
            // the other delete ops.
            sqlx::query("DELETE FROM goals WHERE id = $1 AND user_id = $2 AND workspace_id = $3")
                .bind(goal_id)
                .bind(user_id)
                .bind(workspace_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetTags { task_id, tag_ids } => {
            let project_id = ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?;
            *out_project_id = Some(project_id);
            // All tag_ids must belong to the same project as the task.
            // Reject the whole op if any cross over — silently filtering
            // would lose the user's intent without telling them.
            if !tag_ids.is_empty() {
                let row: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM tags WHERE id = ANY($1) AND project_id = $2",
                )
                .bind(&tag_ids)
                .bind(project_id)
                .fetch_one(&mut **tx)
                .await?;
                if (row.0 as usize) != tag_ids.len() {
                    anyhow::bail!("tag_ids include unknown or cross-project tags");
                }
            }
            sqlx::query("DELETE FROM task_tags WHERE task_id = $1")
                .bind(task_id)
                .execute(&mut **tx)
                .await?;
            for tag_id in &tag_ids {
                sqlx::query(
                    "INSERT INTO task_tags (task_id, tag_id) VALUES ($1, $2)
                     ON CONFLICT DO NOTHING",
                )
                .bind(task_id)
                .bind(tag_id)
                .execute(&mut **tx)
                .await?;
            }
        }
        Op::TrackCreate { track } => {
            require_project_access(tx, user_id, workspace_id, track.project_id).await?;
            *out_project_id = Some(track.project_id);
            sqlx::query(
                "INSERT INTO tracks (id, project_id, title, color, sort_key)
                 VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(track.id)
            .bind(track.project_id)
            .bind(&track.title)
            .bind(&track.color)
            .bind(&track.sort_key)
            .execute(&mut **tx)
            .await?;
        }
        Op::TrackSetTitle { track_id, title } => {
            *out_project_id =
                Some(ensure_track_in_scope(tx, user_id, workspace_id, track_id).await?);
            sqlx::query("UPDATE tracks SET title = $2 WHERE id = $1")
                .bind(track_id)
                .bind(&title)
                .execute(&mut **tx)
                .await?;
        }
        Op::TrackSetColor { track_id, color } => {
            *out_project_id =
                Some(ensure_track_in_scope(tx, user_id, workspace_id, track_id).await?);
            sqlx::query("UPDATE tracks SET color = $2 WHERE id = $1")
                .bind(track_id)
                .bind(&color)
                .execute(&mut **tx)
                .await?;
        }
        Op::TrackReorder {
            project_id,
            ordered,
        } => {
            require_project_access(tx, user_id, workspace_id, project_id).await?;
            *out_project_id = Some(project_id);
            // The project_id predicate *is* the authorization: ids inside
            // `ordered` are never trusted, so a forged list can't touch
            // another project's rows. Same shape as task.reorder.
            for (i, track_id) in ordered.iter().enumerate() {
                let sort_key = format!("M{:03}", i);
                sqlx::query("UPDATE tracks SET sort_key = $2 WHERE id = $1 AND project_id = $3")
                    .bind(track_id)
                    .bind(&sort_key)
                    .bind(project_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        Op::TrackDelete { track_id } => {
            *out_project_id =
                Some(ensure_track_in_scope(tx, user_id, workspace_id, track_id).await?);
            // Child sprints' track_id and member tasks' track_id both go
            // NULL via ON DELETE SET NULL (0001/0034). Nothing is
            // destroyed; the board shows the orphans in a "No track" row.
            sqlx::query("DELETE FROM tracks WHERE id = $1")
                .bind(track_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::SprintCreate { sprint } => {
            require_project_access(tx, user_id, workspace_id, sprint.project_id).await?;
            *out_project_id = Some(sprint.project_id);
            if let (Some(a), Some(b)) = (sprint.starts_on, sprint.ends_on) {
                validate_span(a, b)?;
            } else if sprint.starts_on.is_some() != sprint.ends_on.is_some() {
                anyhow::bail!("a sprint's span needs both starts_on and ends_on, or neither");
            }
            if let Some(track_id) = sprint.track_id {
                let track_project =
                    ensure_track_in_scope(tx, user_id, workspace_id, track_id).await?;
                if track_project != sprint.project_id {
                    anyhow::bail!("track_id belongs to a different project");
                }
            }
            sqlx::query(
                "INSERT INTO sprints (id, project_id, track_id, title, starts_on, ends_on, sort_key)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(sprint.id)
            .bind(sprint.project_id)
            .bind(sprint.track_id)
            .bind(&sprint.title)
            .bind(sprint.starts_on)
            .bind(sprint.ends_on)
            .bind(&sprint.sort_key)
            .execute(&mut **tx)
            .await?;
        }
        Op::SprintSetTitle { sprint_id, title } => {
            *out_project_id =
                Some(ensure_sprint_in_scope(tx, user_id, workspace_id, sprint_id).await?);
            sqlx::query("UPDATE sprints SET title = $2 WHERE id = $1")
                .bind(sprint_id)
                .bind(&title)
                .execute(&mut **tx)
                .await?;
        }
        Op::SprintSetDates {
            sprint_id,
            starts_on,
            ends_on,
        } => {
            *out_project_id =
                Some(ensure_sprint_in_scope(tx, user_id, workspace_id, sprint_id).await?);
            validate_span(starts_on, ends_on)?;
            sqlx::query("UPDATE sprints SET starts_on = $2, ends_on = $3 WHERE id = $1")
                .bind(sprint_id)
                .bind(starts_on)
                .bind(ends_on)
                .execute(&mut **tx)
                .await?;
        }
        Op::SprintSetTrack {
            sprint_id,
            track_id,
        } => {
            let project_id = ensure_sprint_in_scope(tx, user_id, workspace_id, sprint_id).await?;
            *out_project_id = Some(project_id);
            // Resolve the target through its own scope helper, so the op
            // can't be used to probe for ids the caller can't see.
            if let Some(track_id) = track_id {
                let track_project =
                    ensure_track_in_scope(tx, user_id, workspace_id, track_id).await?;
                if track_project != project_id {
                    anyhow::bail!("track_id belongs to a different project");
                }
            }
            sqlx::query("UPDATE sprints SET track_id = $2 WHERE id = $1")
                .bind(sprint_id)
                .bind(track_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::SprintDelete { sprint_id } => {
            *out_project_id =
                Some(ensure_sprint_in_scope(tx, user_id, workspace_id, sprint_id).await?);
            // Member tasks' sprint_id goes NULL, so they return to the
            // plan inbox rather than being destroyed.
            sqlx::query("DELETE FROM sprints WHERE id = $1")
                .bind(sprint_id)
                .execute(&mut **tx)
                .await?;
        }
        Op::TaskSetSprint {
            task_id,
            sprint_id,
        } => {
            let project_id = ensure_task_in_scope(tx, user_id, workspace_id, task_id).await?;
            *out_project_id = Some(project_id);
            if let Some(sprint_id) = sprint_id {
                let sprint_project =
                    ensure_sprint_in_scope(tx, user_id, workspace_id, sprint_id).await?;
                if sprint_project != project_id {
                    anyhow::bail!("sprint_id belongs to a different project");
                }
            }
            sqlx::query("UPDATE tasks SET sprint_id = $2, updated_at = now() WHERE id = $1")
                .bind(task_id)
                .bind(sprint_id)
                .execute(&mut **tx)
                .await?;
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
    ctx: AuthCtx,
    Query(q): Query<ChangesQuery>,
) -> ApiResult<Json<ChangesResponse>> {
    let since = q.since.unwrap_or(0);

    // Change-feed scope, in workspace context:
    //   - workspace.* ops (workspace_id set, project_id NULL): every active
    //     workspace member receives them.
    //   - project ops: scoped to projects the user can see in the workspace
    //     (own + member). Ex-members still get the terminal `project.set_members`
    //     op (`applied_at <= removed_at`) so their client can drop state.
    //   - private kinds (`goal.*`): delivered only back to their author.
    //
    // That last arm is load-bearing, not belt-and-braces. Goal ops carry
    // a NULL project_id, and the workspace arm below hands *every*
    // NULL-project op to *every* active workspace member — so without
    // the authorship filter, creating a goal would broadcast its name to
    // the whole team. Giving goal ops a project_id instead would only
    // narrow the leak from the workspace to the project.
    let rows: Vec<(i64, String, String, serde_json::Value, DateTime<Utc>)> = sqlx::query_as(
        "SELECT po.seq, po.op_id, po.kind, po.payload, po.applied_at
         FROM processed_ops po
         WHERE po.seq > $1
           AND po.workspace_id = $3
           AND (po.kind NOT LIKE 'goal.%' OR po.user_id = $2)
           AND (
             (po.project_id IS NULL AND EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2 AND wm.removed_at IS NULL
             ))
             OR po.project_id IN (SELECT id FROM projects WHERE owner_id = $2 AND workspace_id = $3)
             OR po.project_id IN (
               SELECT pm.project_id FROM project_members pm
               WHERE pm.user_id = $2 AND pm.workspace_id = $3
                 AND (pm.removed_at IS NULL OR po.applied_at <= pm.removed_at)
             )
             OR (po.project_id IS NOT NULL AND EXISTS (
               SELECT 1 FROM workspace_members wm
               WHERE wm.workspace_id = $3 AND wm.user_id = $2
                 AND wm.removed_at IS NULL AND wm.role = 'owner'
             ))
           )
         ORDER BY po.seq ASC
         LIMIT 500",
    )
    .bind(since)
    .bind(ctx.user.id)
    .bind(ctx.workspace_id)
    .fetch_all(&s.pool)
    .await?;

    let cursor = rows.last().map(|r| r.0).unwrap_or(since);
    let ops = rows
        .into_iter()
        .map(|(seq, op_id, kind, payload, applied_at)| ChangeEntry {
            seq,
            op_id,
            kind,
            payload,
            applied_at,
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
/// through /changes the same as outbox-driven ones. Used for project.*
/// REST writes that originate outside the outbox.
pub async fn record_synthesized_op(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    kind: &str,
    payload: serde_json::Value,
    project_id: Option<Uuid>,
) -> sqlx::Result<()> {
    let op_id = Uuid::new_v4().to_string();
    let seq: (i64,) = sqlx::query_as(
        "INSERT INTO processed_ops (op_id, user_id, kind, payload, project_id, workspace_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING seq",
    )
    .bind(op_id)
    .bind(user_id)
    .bind(kind)
    .bind(payload)
    .bind(project_id)
    .bind(workspace_id)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("SELECT pg_notify('ops_changes', $1)")
        .bind(crate::pubsub::format_payload(workspace_id, seq.0))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Workspace-scoped op (no project). Goes to every workspace member via
/// the change feed.
pub async fn record_workspace_op(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    kind: &str,
    payload: serde_json::Value,
    workspace_id: Uuid,
) -> sqlx::Result<()> {
    let op_id = Uuid::new_v4().to_string();
    let seq: (i64,) = sqlx::query_as(
        "INSERT INTO processed_ops (op_id, user_id, kind, payload, project_id, workspace_id)
         VALUES ($1, $2, $3, $4, NULL, $5)
         RETURNING seq",
    )
    .bind(op_id)
    .bind(user_id)
    .bind(kind)
    .bind(payload)
    .bind(workspace_id)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("SELECT pg_notify('ops_changes', $1)")
        .bind(crate::pubsub::format_payload(workspace_id, seq.0))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Seeder-only twin of `record_synthesized_op` with an explicit
/// `applied_at`, so the fixture's op log carries the dates its narrative
/// claims instead of all collapsing onto `now()`. No `pg_notify`: the
/// seeder wipes and rewrites everything, and nudging live clients
/// mid-reseed only makes them fetch a half-built world.
pub(crate) async fn record_fixture_op(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    workspace_id: Uuid,
    kind: &str,
    payload: serde_json::Value,
    project_id: Option<Uuid>,
    applied_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO processed_ops (op_id, user_id, kind, payload, project_id, workspace_id, applied_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(kind)
    .bind(payload)
    .bind(project_id)
    .bind(workspace_id)
    .bind(applied_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
