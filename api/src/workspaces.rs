// HTTP handlers for the workspace surface.
//
// `/workspaces` is the only authed-without-context route — it lists the
// caller's workspaces so the client knows which `X-Workspace-Id` to send on
// the rest of the API. Everything else takes an `AuthCtx`, meaning the
// caller is already known to be in the workspace they're naming.
//
// Roles:
//   - owner: full control of the workspace
//   - lead:  create projects in the workspace, edit any project
//   - member: read-only on the workspace; works tasks via project membership
//
// Personal workspaces are immutable post-creation: their title can be
// renamed by the owner, but membership operations are no-ops.

use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{AuthCtx, AuthUser};
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::ops;
use crate::AppState;

#[derive(Deserialize)]
pub struct CreateWorkspace {
    pub title: String,
}

pub async fn list_my(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<crate::models::Workspace>>> {
    Ok(Json(db::list_user_workspaces(&s.pool, user.id).await?))
}

pub async fn create(
    State(s): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateWorkspace>,
) -> Result<(StatusCode, Json<crate::models::Workspace>), ApiError> {
    let title = body.title.trim();
    if title.is_empty() {
        return Err(ApiError::BadRequest("title is required".into()));
    }
    if title.len() > 80 {
        return Err(ApiError::BadRequest("title is too long".into()));
    }
    let mut tx = s.pool.begin().await?;
    let ws = db::create_workspace_tx(&mut tx, user.id, title, false).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(ws)))
}

#[derive(Deserialize)]
pub struct UpdateWorkspace {
    pub title: String,
}

pub async fn rename(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateWorkspace>,
) -> ApiResult<Json<crate::models::Workspace>> {
    if ctx.workspace_id != id || !ctx.is_owner() {
        return Err(ApiError::BadRequest("only workspace owners can rename".into()));
    }
    let title = body.title.trim();
    if title.is_empty() || title.len() > 80 {
        return Err(ApiError::BadRequest("invalid title".into()));
    }
    let mut tx = s.pool.begin().await?;
    let ws = db::rename_workspace_tx(&mut tx, id, title)
        .await?
        .ok_or(ApiError::NotFound)?;
    let payload = serde_json::json!({ "kind": "workspace.update", "workspace": &ws });
    ops::record_workspace_op(&mut tx, ctx.user.id, "workspace.update", payload, id).await?;
    tx.commit().await?;
    Ok(Json(ws))
}

#[derive(Deserialize)]
pub struct SetMembersBody {
    pub members: Vec<MemberSpec>,
}

#[derive(Deserialize, Clone)]
pub struct MemberSpec {
    pub user_id: Uuid,
    pub role: String,
}

pub async fn set_members(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<SetMembersBody>,
) -> ApiResult<Json<crate::models::Workspace>> {
    if ctx.workspace_id != id || !ctx.is_owner() {
        return Err(ApiError::BadRequest("only workspace owners can edit membership".into()));
    }
    for m in &body.members {
        validate_role(&m.role)?;
    }
    let desired: Vec<(Uuid, String)> = body.members.iter().map(|m| (m.user_id, m.role.clone())).collect();
    let mut tx = s.pool.begin().await?;
    let ws = db::set_workspace_members_tx(&mut tx, id, ctx.user.id, &desired)
        .await?
        .ok_or(ApiError::NotFound)?;
    let payload = serde_json::json!({
        "kind": "workspace.set_members",
        "workspace_id": id,
        "members": &ws.members,
    });
    ops::record_workspace_op(&mut tx, ctx.user.id, "workspace.set_members", payload, id).await?;
    tx.commit().await?;
    Ok(Json(ws))
}

#[derive(Deserialize)]
pub struct SetRoleBody {
    pub role: String,
}

pub async fn set_member_role(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<SetRoleBody>,
) -> ApiResult<Json<crate::models::Workspace>> {
    if ctx.workspace_id != id || !ctx.is_owner() {
        return Err(ApiError::BadRequest("only workspace owners can change roles".into()));
    }
    validate_role(&body.role)?;
    let mut tx = s.pool.begin().await?;
    let ws = db::set_workspace_member_role_tx(&mut tx, id, user_id, &body.role)
        .await?
        .ok_or(ApiError::NotFound)?;
    let payload = serde_json::json!({
        "kind": "workspace.set_member_role",
        "workspace_id": id,
        "user_id": user_id,
        "role": &body.role,
    });
    ops::record_workspace_op(&mut tx, ctx.user.id, "workspace.set_member_role", payload, id).await?;
    tx.commit().await?;
    Ok(Json(ws))
}

pub async fn list_users(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<Vec<crate::models::User>>> {
    Ok(Json(db::list_users_in_workspace(&s.pool, ctx.workspace_id).await?))
}

/// Full user directory — the picker the workspace owner uses to add a
/// teammate who isn't in the workspace yet (e.g. someone who just signed
/// in with Google for the first time). Owner-only; everyone else gets the
/// scoped `list_users` endpoint.
pub async fn list_all_users(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<Vec<crate::models::User>>> {
    if !ctx.is_owner() {
        return Err(ApiError::BadRequest("only workspace owners can list all users".into()));
    }
    Ok(Json(db::list_all_users(&s.pool).await?))
}

fn validate_role(role: &str) -> Result<(), ApiError> {
    match role {
        "owner" | "member" => Ok(()),
        _ => Err(ApiError::BadRequest("role must be owner|member".into())),
    }
}
