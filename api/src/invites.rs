// Workspace invites surface.
//
// Replaces the "search a global user list and add them" flow for
// workspace membership. Owners send invites by email; recipients see a
// sticky modal — same shape as account linking — with Accept / Decline.
//
// Like links, invite events are inherently cross-workspace: a recipient
// might not currently belong to any workspace at all when the invite
// arrives. We deliver state changes through the per-user pubsub channel
// (`Hub::notify_user`) so the receiver sees the modal regardless of
// which workspace they have open. There is no workspace-scoped op for
// `workspace_invite.*` — same model as link.*.
//
// Authorization:
//   - create: caller must be owner of the workspace they're inviting to.
//   - cancel: original inviter, or any current owner of the workspace.
//   - accept: caller's email must match the invite's email (canonical).
//   - decline: same as accept (the invitee is the only one who can
//     refuse).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct CreateInvite {
    pub workspace_id: Uuid,
    pub email: String,
    /// Optional. Defaults to "member". The UI doesn't expose `lead` at
    /// invite time today (per design — promote separately) but the API
    /// accepts it for forward compat.
    pub role: Option<String>,
}

/// List the caller's pending invites (sent and received). Mirrors
/// `links::list_my`. Bootstrap also surfaces these but a direct GET is
/// useful for resync after errors.
pub async fn list_my(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<Vec<crate::models::WorkspaceInvite>>> {
    Ok(Json(
        db::list_workspace_invites(&s.pool, ctx.user.id, &ctx.user.email).await?,
    ))
}

pub async fn create(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Json(body): Json<CreateInvite>,
) -> Result<(StatusCode, Json<crate::models::WorkspaceInvite>), ApiError> {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::BadRequest("a valid email is required".into()));
    }
    let role = body.role.unwrap_or_else(|| "member".to_string());
    if role != "member" && role != "lead" {
        return Err(ApiError::BadRequest("role must be member or lead".into()));
    }

    // Owner-only on the target workspace. Mirrors the existing
    // set_members guard. (Note arg order: workspace_id first, user_id
    // second — easy to swap.)
    let owner = db::is_workspace_owner(&s.pool, body.workspace_id, ctx.user.id).await?;
    if !owner {
        return Err(ApiError::Forbidden);
    }

    // Already a member → friendly error rather than a no-op invite the
    // user will spend time wondering about.
    if db::email_is_workspace_member(&s.pool, body.workspace_id, &email).await? {
        return Err(ApiError::BadRequest(
            "that email is already a workspace member".into(),
        ));
    }

    let mut tx = s.pool.begin().await?;
    let (id, _newly_created) = db::create_workspace_invite_tx(
        &mut tx,
        body.workspace_id,
        &email,
        &role,
        ctx.user.id,
    )
    .await?;
    tx.commit().await?;

    // Notify the inviter (so their pending list updates) and any user
    // whose registered email matches the invitee. The recipient may not
    // exist yet — that's fine, the row sits and lights up the next time
    // someone with that email logs in (load_bootstrap reads invites by
    // email).
    let _ = s.hub.notify_user(&s.pool, ctx.user.id).await;
    if let Some(target_id) = lookup_user_id_by_email(&s.pool, &email).await? {
        let _ = s.hub.notify_user(&s.pool, target_id).await;
    }

    let invite = invite_for(&s.pool, ctx.user.id, &ctx.user.email, id).await?;
    Ok((StatusCode::CREATED, Json(invite)))
}

pub async fn cancel(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<crate::models::WorkspaceInvite>> {
    let row = db::get_invite_for_action(&s.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (workspace_id, email, status, invited_by, _role) = row;
    if status != "pending" {
        return Err(ApiError::BadRequest("invite is not pending".into()));
    }
    let is_owner = db::is_workspace_owner(&s.pool, workspace_id, ctx.user.id).await?;
    if invited_by != ctx.user.id && !is_owner {
        return Err(ApiError::Forbidden);
    }

    let mut tx = s.pool.begin().await?;
    let ok = db::cancel_workspace_invite_tx(&mut tx, id).await?;
    if !ok {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;

    // Inviter and recipient both need to refresh; the recipient's modal
    // disappears in real-time.
    let _ = s.hub.notify_user(&s.pool, invited_by).await;
    if let Some(target_id) = lookup_user_id_by_email(&s.pool, &email).await? {
        let _ = s.hub.notify_user(&s.pool, target_id).await;
    }

    let invite = invite_for(&s.pool, ctx.user.id, &ctx.user.email, id).await?;
    Ok(Json(invite))
}

pub async fn accept(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<crate::models::WorkspaceInvite>> {
    let row = db::get_invite_for_action(&s.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (workspace_id, email, status, invited_by, _role) = row;
    if status != "pending" {
        return Err(ApiError::BadRequest("invite is not pending".into()));
    }
    if db::canonical_email(&ctx.user.email) != db::canonical_email(&email) {
        return Err(ApiError::Forbidden);
    }

    let mut tx = s.pool.begin().await?;
    let ok = db::accept_workspace_invite_tx(&mut tx, id, ctx.user.id).await?;
    if !ok {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;

    // Fan out: the inviter gets a refresh, every existing workspace
    // member gets a refresh so their member list shows the new person,
    // and the accepting user gets one for their own pending list +
    // workspace surface (so the workspace shows up in their switcher).
    let _ = s.hub.notify_user(&s.pool, invited_by).await;
    let _ = s.hub.notify_user(&s.pool, ctx.user.id).await;
    if let Ok(member_ids) = db::list_workspace_member_ids(&s.pool, workspace_id).await {
        for uid in member_ids {
            if uid != invited_by && uid != ctx.user.id {
                let _ = s.hub.notify_user(&s.pool, uid).await;
            }
        }
    }

    let invite = invite_for(&s.pool, ctx.user.id, &ctx.user.email, id).await?;
    Ok(Json(invite))
}

pub async fn decline(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<crate::models::WorkspaceInvite>> {
    let row = db::get_invite_for_action(&s.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (_workspace_id, email, status, invited_by, _role) = row;
    if status != "pending" {
        return Err(ApiError::BadRequest("invite is not pending".into()));
    }
    if db::canonical_email(&ctx.user.email) != db::canonical_email(&email) {
        return Err(ApiError::Forbidden);
    }

    let mut tx = s.pool.begin().await?;
    let ok = db::decline_workspace_invite_tx(&mut tx, id).await?;
    if !ok {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;

    // Inviter sees declined disappear from their pending list; the
    // decliner sees the modal close.
    let _ = s.hub.notify_user(&s.pool, invited_by).await;
    let _ = s.hub.notify_user(&s.pool, ctx.user.id).await;

    let invite = invite_for(&s.pool, ctx.user.id, &ctx.user.email, id).await?;
    Ok(Json(invite))
}

// ── helpers ────────────────────────────────────────────────────────────

async fn lookup_user_id_by_email(
    pool: &sqlx::PgPool,
    email: &str,
) -> sqlx::Result<Option<Uuid>> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE lower(email) = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// Re-fetch a single invite from the caller's perspective. `list_my`'s
/// query is reused — we filter the returned list. After a state change
/// the row may no longer be `pending`, in which case it's not in the
/// list and we return a synthetic "resolved" view by reading the row
/// directly. The handlers above only call this on the rows they just
/// touched, so a NotFound here is genuinely unexpected.
async fn invite_for(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    user_email: &str,
    invite_id: Uuid,
) -> ApiResult<crate::models::WorkspaceInvite> {
    let mut all = db::list_workspace_invites(pool, user_id, user_email).await?;
    if let Some(idx) = all.iter().position(|i| i.id == invite_id) {
        return Ok(all.swap_remove(idx));
    }
    // Resolved invite — synthesize a row so the caller can read the
    // terminal state. Direction is computed off the actor.
    let row: (Uuid, Uuid, String, String, String, String, Uuid, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as(
            "SELECT i.id, i.workspace_id, w.title, i.email, i.role, i.status,
                    i.invited_by, i.created_at
             FROM workspace_invites i
             JOIN workspaces w ON w.id = i.workspace_id
             WHERE i.id = $1",
        )
        .bind(invite_id)
        .fetch_one(pool)
        .await?;
    let (id, workspace_id, workspace_title, email, role, status, invited_by, created_at) = row;
    let inviter: (String, String) = sqlx::query_as(
        "SELECT name, email FROM users WHERE id = $1",
    )
    .bind(invited_by)
    .fetch_one(pool)
    .await?;
    let direction = if invited_by == user_id { "sent" } else { "received" };
    Ok(crate::models::WorkspaceInvite {
        id,
        workspace_id,
        workspace_title,
        email,
        role,
        status,
        direction: direction.to_string(),
        invited_by,
        invited_by_name: inviter.0,
        invited_by_email: inviter.1,
        created_at,
    })
}
