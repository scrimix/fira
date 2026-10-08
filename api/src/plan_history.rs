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
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
        read_snapshot(
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

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub project_id: Uuid,
    pub since: Option<i64>,
}

#[derive(Serialize)]
pub struct RevisionList {
    pub genesis: Option<DateTime<Utc>>,
    pub changes: Vec<PlanChange>,
}

pub async fn get_history(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<RevisionList>> {
    Ok(Json(
        read_history(
            &s.pool,
            ctx.user.id,
            ctx.workspace_id,
            q.project_id,
            q.since,
        )
        .await?,
    ))
}

pub async fn read_history(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    project_id: Uuid,
    since: Option<i64>,
) -> ApiResult<RevisionList> {
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
    let genesis = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT MIN(applied_at) FROM processed_ops WHERE project_id=$1 AND workspace_id=$2 AND kind=ANY($3) AND applied_at <= $4",
    ).bind(project_id).bind(workspace_id).bind(PLAN_KINDS).bind(now).fetch_one(&mut *tx).await?;
    let changes = sqlx::query_as::<_, PlanChange>(
        "SELECT seq, kind, applied_at AS at, 1::bigint AS count FROM processed_ops
         WHERE project_id=$1 AND workspace_id=$2 AND kind=ANY($3) AND applied_at <= $4 AND seq > $5 ORDER BY seq",
    ).bind(project_id).bind(workspace_id).bind(PLAN_KINDS).bind(now).bind(since.unwrap_or(0)).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(RevisionList { genesis, changes })
}

/// Snapshot reads used by HTTP scrubbing: no revision list query or transfer.
pub async fn read_snapshot(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    project_id: Uuid,
    requested_at: Option<DateTime<Utc>>,
    requested_seq: Option<i64>,
) -> ApiResult<PlanHistory> {
    read_projection(
        pool,
        user_id,
        workspace_id,
        project_id,
        requested_at,
        requested_seq,
        false,
    )
    .await
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
    read_projection(
        pool,
        user_id,
        workspace_id,
        project_id,
        requested_at,
        requested_seq,
        true,
    )
    .await
}

// Combined helper retained for projection equivalence tests and baseline comparisons.
async fn read_projection(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    project_id: Uuid,
    requested_at: Option<DateTime<Utc>>,
    requested_seq: Option<i64>,
    include_changes: bool,
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
    let changes = if include_changes {
        sqlx::query_as::<_, PlanChange>(
            "SELECT seq, kind, applied_at AS at, 1::bigint AS count FROM processed_ops
             WHERE project_id=$1 AND workspace_id=$2 AND kind=ANY($3) AND applied_at <= $4 ORDER BY seq",
        ).bind(project_id).bind(workspace_id).bind(PLAN_KINDS).bind(now).fetch_all(&mut *tx).await?
    } else {
        Vec::new()
    };
    let genesis = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT MIN(applied_at) FROM processed_ops WHERE project_id=$1 AND workspace_id=$2 AND kind=ANY($3) AND applied_at <= $4",
    ).bind(project_id).bind(workspace_id).bind(PLAN_KINDS).bind(now).fetch_one(&mut *tx).await?;
    let mut at = requested_at.unwrap_or(now).min(now);
    if let Some(start) = genesis {
        at = at.max(start);
    }
    if let Some(seq) = requested_seq {
        at = sqlx::query_scalar::<_, DateTime<Utc>>(
            "SELECT applied_at FROM processed_ops WHERE seq=$1 AND project_id=$2 AND workspace_id=$3 AND kind=ANY($4) AND applied_at <= $5",
        ).bind(seq).bind(project_id).bind(workspace_id).bind(PLAN_KINDS).bind(now).fetch_optional(&mut *tx).await?
            .ok_or_else(|| ApiError::BadRequest("Revision is not in this project's history".into()))?;
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
