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
    // Nudge the creator's other devices/sockets so their workspace list
    // shows the new workspace immediately.
    let _ = s.hub.notify_user(&s.pool, user.id).await;
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
    // Title appears in every member's workspace list — fan out a refetch.
    for uid in active_member_ids(&s.pool, id).await.unwrap_or_default() {
        let _ = s.hub.notify_user(&s.pool, uid).await;
    }
    Ok(Json(ws))
}

/// Owner-only hard delete. Personal workspaces are off-limits — the
/// `is_personal` row is the user's permanent home for unsynced work.
///
/// Cascade handles the entity tree. There is no synthesized
/// `workspace.delete` op on the workspace's change feed: that feed scopes
/// by `workspace_role`, which is gone the instant the cascade fires. We
/// notify (former) members via the per-user channel (pubsub::Hub::notify_user)
/// so their clients refetch listMyWorkspaces and reconcile.
pub async fn delete(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if ctx.workspace_id != id || !ctx.is_owner() {
        return Err(ApiError::BadRequest("only workspace owners can delete".into()));
    }
    let row: Option<(bool,)> = sqlx::query_as("SELECT is_personal FROM workspaces WHERE id = $1")
        .bind(id)
        .fetch_optional(&s.pool)
        .await?;
    let (is_personal,) = row.ok_or(ApiError::NotFound)?;
    if is_personal {
        return Err(ApiError::BadRequest(
            "personal workspaces can't be deleted".into(),
        ));
    }
    let member_ids = active_member_ids(&s.pool, id).await?;
    let mut tx = s.pool.begin().await?;
    let deleted = db::delete_workspace_tx(&mut tx, id).await?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    for uid in member_ids {
        let _ = s.hub.notify_user(&s.pool, uid).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn active_member_ids(
    pool: &sqlx::PgPool,
    workspace_id: Uuid,
) -> sqlx::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM workspace_members
         WHERE workspace_id = $1 AND removed_at IS NULL",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(u,)| u).collect())
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
    // Snapshot pre-mutation membership so removed users still get nudged.
    let pre = active_member_ids(&s.pool, id).await.unwrap_or_default();
    let mut tx = s.pool.begin().await?;
    let ws = db::set_workspace_members_tx(&mut tx, id, ctx.user.id, &desired)
        .await?
        .ok_or(ApiError::NotFound)?;
    // Tasks and time blocks stay — that's true history; the user did
    // do that work, even if they're no longer in the workspace.
    // Project memberships, on the other hand, would still show the
    // ex-member as a project member because workspace_members is
    // soft-deleted (so the FK ON DELETE CASCADE never fires). Soft-
    // delete those rows here.
    let post_ids: std::collections::BTreeSet<Uuid> =
        ws.members.iter().map(|m| m.user_id).collect();
    let removed: Vec<Uuid> = pre.iter().copied().filter(|u| !post_ids.contains(u)).collect();
    db::soft_remove_project_members_tx(&mut tx, id, &removed).await?;
    let payload = serde_json::json!({
        "kind": "workspace.set_members",
        "workspace_id": id,
        "members": &ws.members,
    });
    ops::record_workspace_op(&mut tx, ctx.user.id, "workspace.set_members", payload, id).await?;
    tx.commit().await?;
    // pre ∪ post: covers added (post-only), removed (pre-only), and
    // retained (both) — all need a refetch because someone's row in the
    // member list changed.
    let mut targets: std::collections::BTreeSet<Uuid> = pre.into_iter().collect();
    for m in &ws.members { targets.insert(m.user_id); }
    for uid in targets {
        let _ = s.hub.notify_user(&s.pool, uid).await;
    }
    Ok(Json(ws))
}

#[derive(Deserialize)]
pub struct SetRoleBody {
    pub role: String,
}

pub async fn remove_member(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<crate::models::Workspace>> {
    if ctx.workspace_id != id || !ctx.is_owner() {
        return Err(ApiError::BadRequest(
            "only workspace owners can remove members".into(),
        ));
    }
    if user_id == ctx.user.id {
        return Err(ApiError::BadRequest(
            "owners can't remove themselves; transfer ownership first".into(),
        ));
    }
    // Snapshot pre-state so the removed user gets a nudge too — they
    // won't be in the post-set, and we want their workspace switcher
    // to drop the workspace they no longer belong to.
    let pre = active_member_ids(&s.pool, id).await.unwrap_or_default();
    let mut tx = s.pool.begin().await?;
    let (ws, affected_projects) = db::remove_workspace_member_tx(&mut tx, id, user_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let payload = serde_json::json!({
        "kind": "workspace.set_members",
        "workspace_id": id,
        "members": &ws.members,
    });
    ops::record_workspace_op(&mut tx, ctx.user.id, "workspace.set_members", payload, id).await?;
    // Each affected project also got its member set changed (the user
    // was soft-removed from it). Emit a `project.set_members` op per
    // project so workspace clients pick up the project-side change
    // through the normal change feed.
    for pid in affected_projects {
        let members = db::list_project_members_tx(&mut tx, pid).await?;
        let payload = serde_json::json!({
            "kind": "project.set_members",
            "project_id": pid,
            "members": &members,
        });
        ops::record_synthesized_op(
            &mut tx, ctx.user.id, id, "project.set_members", payload, Some(pid),
        ).await?;
    }
    tx.commit().await?;
    let mut targets: std::collections::BTreeSet<Uuid> = pre.into_iter().collect();
    for m in &ws.members { targets.insert(m.user_id); }
    for uid in targets {
        let _ = s.hub.notify_user(&s.pool, uid).await;
    }
    Ok(Json(ws))
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
    // Role appears in every member's view of the member list.
    for uid in active_member_ids(&s.pool, id).await.unwrap_or_default() {
        let _ = s.hub.notify_user(&s.pool, uid).await;
    }
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
