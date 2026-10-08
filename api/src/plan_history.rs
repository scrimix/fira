//! Authorized point-in-time reads. The projection itself remains pure in `plan`.
use axum::{
    extract::{Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::AuthCtx,
    db,
    error::{ApiError, ApiResult},
    plan::{project_at, LoggedOp, PlanState, PLAN_KINDS},
    AppState,
};

#[derive(Deserialize)]
pub struct PlanQuery {
    pub project_id: Uuid,
    pub t: Option<DateTime<Utc>>,
    pub seq: Option<i64>,
}

#[derive(Serialize)]
pub struct PlanHistory {
    pub at: DateTime<Utc>,
    pub genesis: Option<DateTime<Utc>>,
    pub changes: Vec<PlanChange>,
    pub revision: Option<i64>,
    #[serde(flatten)]
    pub state: PlanState,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PlanChange {
    pub seq: i64,
    pub kind: String,
    pub at: DateTime<Utc>,
    pub count: i64,
}

pub async fn get_at(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Query(q): Query<PlanQuery>,
) -> ApiResult<Json<PlanHistory>> {
    Ok(Json(
        read_revision(
            &s.pool,
            ctx.user.id,
            ctx.workspace_id,
            q.project_id,
            q.t,
            q.seq,
        )
        .await?,
    ))
}

pub async fn read_plan(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    project_id: Uuid,
    requested_at: Option<DateTime<Utc>>,
) -> ApiResult<PlanHistory> {
    read_revision(pool, user_id, workspace_id, project_id, requested_at, None).await
}

pub async fn read_revision(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    project_id: Uuid,
    requested_at: Option<DateTime<Utc>>,
    requested_seq: Option<i64>,
) -> ApiResult<PlanHistory> {
    // Current access is required even when reading old log rows. Deleted
    // projects and revoked memberships must not become accessible via replay.
    if !db::project_scope(pool, user_id, workspace_id)
        .await?
        .contains(&project_id)
    {
        return Err(ApiError::Forbidden);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let now = Utc::now();
    let changes = sqlx::query_as::<_, PlanChange>(
        "SELECT seq, kind, applied_at AS at, 1::bigint AS count FROM processed_ops
         WHERE project_id = $1 AND workspace_id = $2 AND kind = ANY($3)
           AND applied_at <= $4
         ORDER BY seq",
    )
    .bind(project_id)
    .bind(workspace_id)
    .bind(PLAN_KINDS)
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    let genesis = changes.iter().map(|c| c.at).min();
    let mut at = requested_at.unwrap_or(now).min(now);
    if let Some(start) = genesis {
        at = at.max(start);
    }
    if let Some(seq) = requested_seq {
        at = changes
            .iter()
            .find(|change| change.seq == seq)
            .ok_or_else(|| {
                ApiError::BadRequest("Revision is not in this project's history".into())
            })?
            .at;
    }
    let rows = sqlx::query_as::<_, (i64, DateTime<Utc>, String, serde_json::Value)>(
        "SELECT seq, applied_at, kind, payload FROM processed_ops
         WHERE project_id = $1 AND workspace_id = $2 AND kind = ANY($3)
           AND applied_at <= $4 AND ($5::bigint IS NULL OR seq <= $5) ORDER BY seq",
    )
    .bind(project_id)
    .bind(workspace_id)
    .bind(PLAN_KINDS)
    .bind(at)
    .bind(requested_seq)
    .fetch_all(&mut *tx)
    .await?;
    let revision = rows.last().map(|row| row.0);
    tx.commit().await?;
    let ops: Vec<_> = rows
        .into_iter()
        .map(|(seq, applied_at, kind, payload)| LoggedOp {
            seq,
            applied_at,
            kind,
            payload,
        })
        .collect();
    let mut state = project_at(&ops, at);
    // Outgoing moves are logged for the source audience, but their embedded
    // entity belongs to the destination. Never return that entity to source readers.
    state.tasks.retain(|t| t.project_id == project_id);
    state.tracks.retain(|t| t.project_id == project_id);
    state.sprints.retain(|s| s.project_id == project_id);
    Ok(PlanHistory {
        at,
        genesis,
        changes,
        revision,
        state,
    })
}
