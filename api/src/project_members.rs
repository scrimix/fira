//! Single-user membership commands. Clients never supply the membership set.
use crate::{
    auth::AuthCtx,
    db,
    error::{ApiError, ApiResult},
    models::ProjectMember,
    ops, AppState,
};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct SetRole {
    pub role: String,
}

enum Change {
    Add,
    Remove,
    Role(String),
}

pub async fn add(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path((project, user)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Vec<ProjectMember>>> {
    change(&s, &ctx, project, user, Change::Add).await.map(Json)
}

pub async fn remove(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path((project, user)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Vec<ProjectMember>>> {
    change(&s, &ctx, project, user, Change::Remove)
        .await
        .map(Json)
}

pub async fn set_role(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path((project, user)): Path<(Uuid, Uuid)>,
    Json(body): Json<SetRole>,
) -> ApiResult<Json<Vec<ProjectMember>>> {
    if !matches!(
        body.role.as_str(),
        "owner" | "lead" | "member" | "dev" | "inactive"
    ) {
        return Err(ApiError::BadRequest("invalid project role".into()));
    }
    change(&s, &ctx, project, user, Change::Role(body.role))
        .await
        .map(Json)
}

async fn change(
    s: &AppState,
    ctx: &AuthCtx,
    project: Uuid,
    user: Uuid,
    change: Change,
) -> ApiResult<Vec<ProjectMember>> {
    let mut tx = s.pool.begin().await?;
    // Serialize commands for a project, including their snapshot events. A
    // second editor changes only their target and sees the preceding commit.
    let workspace: Option<Uuid> =
        sqlx::query_scalar("SELECT workspace_id FROM projects WHERE id=$1 FOR UPDATE")
            .bind(project)
            .fetch_optional(&mut *tx)
            .await?;
    if workspace != Some(ctx.workspace_id) {
        return Err(ApiError::NotFound);
    }
    let workspace_role: Option<String> = sqlx::query_scalar("SELECT role FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 AND removed_at IS NULL")
        .bind(ctx.workspace_id).bind(ctx.user.id).fetch_optional(&mut *tx).await?;
    let is_owner = workspace_role.as_deref() == Some("owner");
    let is_lead: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM project_members WHERE project_id=$1 AND user_id=$2 AND removed_at IS NULL AND role IN ('owner','lead'))")
        .bind(project).bind(ctx.user.id).fetch_one(&mut *tx).await?;
    if workspace_role.is_none() || (!is_owner && !is_lead) {
        return Err(ApiError::Forbidden);
    }
    match change {
        Change::Remove => {
            if user == ctx.user.id {
                return Err(ApiError::BadRequest(
                    "you can't remove yourself from this editor".into(),
                ));
            }
            let target_is_owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 AND role='owner' AND removed_at IS NULL)")
                .bind(ctx.workspace_id).bind(user).fetch_one(&mut *tx).await?;
            if target_is_owner {
                return Err(ApiError::BadRequest(
                    "the workspace owner can't be removed from a project".into(),
                ));
            }
            sqlx::query("UPDATE project_members SET removed_at=now() WHERE project_id=$1 AND user_id=$2 AND removed_at IS NULL")
                .bind(project).bind(user).execute(&mut *tx).await?;
        }
        Change::Add => {
            let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 AND removed_at IS NULL)")
                .bind(ctx.workspace_id).bind(user).fetch_one(&mut *tx).await?;
            if !active {
                return Err(ApiError::BadRequest(
                    "user must be an active workspace member".into(),
                ));
            }
            // Repeated adds preserve an active member's role. Rejoining users
            // start as members; restoring an old privileged role needs an owner.
            sqlx::query("INSERT INTO project_members (project_id,user_id,role) VALUES ($1,$2,'member') ON CONFLICT (project_id,user_id) DO UPDATE SET removed_at=NULL, role=CASE WHEN project_members.removed_at IS NULL THEN project_members.role ELSE 'member' END")
                .bind(project).bind(user).execute(&mut *tx).await?;
        }
        Change::Role(role) => {
            if !is_owner {
                return Err(ApiError::Forbidden);
            }
            let result = sqlx::query("UPDATE project_members SET role=$3 WHERE project_id=$1 AND user_id=$2 AND removed_at IS NULL")
                .bind(project).bind(user).bind(role).execute(&mut *tx).await?;
            if result.rows_affected() == 0 {
                return Err(ApiError::NotFound);
            }
        }
    }
    let members = db::list_project_members_tx(&mut tx, project).await?;
    // The server publishes its resulting state; this is never client input.
    ops::record_synthesized_op(
        &mut tx,
        ctx.user.id,
        ctx.workspace_id,
        "project.set_members",
        serde_json::json!({"kind":"project.set_members","project_id":project,"members":members}),
        Some(project),
    )
    .await?;
    tx.commit().await?;
    Ok(members)
}
