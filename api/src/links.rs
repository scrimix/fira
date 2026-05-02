// Account-link surface.
//
// A link pairs two user accounts so each sees the other's tasks and time
// blocks read-only on the calendar. Pending requests live as
// `user_links` rows with status='pending'; once accepted, both parties
// become mutually visible.
//
// Link events are inherently cross-workspace: the two parties might
// only share one workspace (the one the request was sent from), or
// nothing at all once unlinked. We deliver state changes through the
// per-user pubsub channel (Hub::notify_user) so a partner who's looking
// at a different workspace still gets the update. There is no
// workspace-scoped op for link.* — same model as workspace.delete.
//
// Authorization:
//   - Create a request: caller types the partner's email; server looks
//     up the user. No workspace co-membership required — linking is
//     consent between two account owners regardless of which workspaces
//     they share, if any.
//   - Accept: only the non-requester side of a pending link.
//   - Cancel / unlink: either party (mirrors how workspace member
//     removals work — both ends can sever).

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
pub struct CreateLink {
    pub email: String,
}

pub async fn list_my(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<Vec<crate::models::UserLink>>> {
    Ok(Json(db::list_user_links(&s.pool, ctx.user.id).await?))
}

pub async fn create(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Json(body): Json<CreateLink>,
) -> Result<(StatusCode, Json<crate::models::UserLink>), ApiError> {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(ApiError::BadRequest("email is required".into()));
    }
    // Look up the partner by email. We don't pre-validate the format —
    // if it isn't a real account, the lookup just misses.
    let target: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE lower(email) = $1",
    )
    .bind(&email)
    .fetch_optional(&s.pool)
    .await?;
    let Some((target_user_id,)) = target else {
        return Err(ApiError::BadRequest(
            "no Fira account found for that email".into(),
        ));
    };
    if target_user_id == ctx.user.id {
        return Err(ApiError::BadRequest("can't link to yourself".into()));
    }

    // One link per user — reject if either side already has one in any
    // state. Server-side enforcement so the UI's empty-state assumption
    // holds even with concurrent requests.
    if has_any_link(&s.pool, ctx.user.id).await? {
        return Err(ApiError::BadRequest(
            "you already have a link or pending request".into(),
        ));
    }
    if has_any_link(&s.pool, target_user_id).await? {
        return Err(ApiError::BadRequest(
            "the other account already has a link or pending request".into(),
        ));
    }

    let mut tx = s.pool.begin().await?;
    let id = db::create_link_request_tx(&mut tx, ctx.user.id, target_user_id)
        .await?
        .ok_or_else(|| ApiError::BadRequest("link already exists".into()))?;
    tx.commit().await?;
    // Both parties refresh: requester sees the pending-sent state, target
    // sees the pending-received call to action.
    let _ = s.hub.notify_user(&s.pool, ctx.user.id).await;
    let _ = s.hub.notify_user(&s.pool, target_user_id).await;
    let link = link_for(&s.pool, ctx.user.id, id).await?;
    Ok((StatusCode::CREATED, Json(link)))
}

pub async fn accept(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<crate::models::UserLink>> {
    let parties = db::get_link_parties(&s.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (a, b, requested_by, status) = parties;
    if status != "pending" {
        return Err(ApiError::BadRequest("link is not pending".into()));
    }
    if ctx.user.id == requested_by || (ctx.user.id != a && ctx.user.id != b) {
        return Err(ApiError::BadRequest(
            "only the request recipient can accept".into(),
        ));
    }
    let mut tx = s.pool.begin().await?;
    let ok = db::accept_link_tx(&mut tx, id).await?;
    if !ok {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    let _ = s.hub.notify_user(&s.pool, a).await;
    let _ = s.hub.notify_user(&s.pool, b).await;
    let link = link_for(&s.pool, ctx.user.id, id).await?;
    Ok(Json(link))
}

pub async fn delete(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let parties = db::get_link_parties(&s.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (a, b, _requested_by, _status) = parties;
    if ctx.user.id != a && ctx.user.id != b {
        return Err(ApiError::BadRequest(
            "only a party to the link can cancel it".into(),
        ));
    }
    let mut tx = s.pool.begin().await?;
    let deleted = db::delete_link_tx(&mut tx, id).await?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    let _ = s.hub.notify_user(&s.pool, a).await;
    let _ = s.hub.notify_user(&s.pool, b).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct LinkedCalendarResponse {
    pub partner_id: Uuid,
    pub blocks: Vec<crate::models::TimeBlock>,
    pub tasks: Vec<crate::models::LinkedTask>,
    pub gcal: Vec<crate::models::GcalEvent>,
}

/// The accepted partner's calendar overlay — blocks + minimal task
/// projection + gcal events. Read-only; the UI never sends ops back
/// against these IDs. Cross-workspace by design (linking is consent).
pub async fn linked_calendar(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<LinkedCalendarResponse>> {
    let partner = db::accepted_partner_id(&s.pool, ctx.user.id).await?;
    let Some(partner_id) = partner else {
        return Err(ApiError::BadRequest("no accepted link".into()));
    };
    // Re-check via the canonicalized table — defense in depth in case
    // accepted_partner_id ever drifts.
    if !db::are_linked(&s.pool, ctx.user.id, partner_id).await? {
        return Err(ApiError::BadRequest("not linked".into()));
    }
    let blocks = db::list_blocks_for_user(&s.pool, partner_id).await?;
    let tasks = db::list_linked_tasks_for_blocks(&s.pool, partner_id).await?;
    let gcal = db::list_gcal_for_user(&s.pool, partner_id).await?;
    Ok(Json(LinkedCalendarResponse { partner_id, blocks, tasks, gcal }))
}

#[derive(serde::Serialize)]
pub struct PersonalCalendarResponse {
    pub blocks: Vec<crate::models::TimeBlock>,
    pub tasks: Vec<crate::models::LinkedTask>,
}

/// Caller's personal-workspace blocks + task projection — used as a
/// read-only overlay when viewing a team workspace, so the user can see
/// their personal items without switching workspaces. Same work-life
/// balance angle as account linking, but within a single account.
/// Returns empty when the caller is already in their personal workspace
/// (the data is already in bootstrap there).
pub async fn personal_calendar(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<PersonalCalendarResponse>> {
    let personal_ws = db::personal_workspace_id(&s.pool, ctx.user.id).await?;
    let Some(ws_id) = personal_ws else {
        return Ok(Json(PersonalCalendarResponse { blocks: vec![], tasks: vec![] }));
    };
    if ws_id == ctx.workspace_id {
        return Ok(Json(PersonalCalendarResponse { blocks: vec![], tasks: vec![] }));
    }
    let blocks = db::list_blocks_in_workspace_for_user(&s.pool, ws_id, ctx.user.id).await?;
    let tasks = db::list_linked_tasks_in_workspace_for_user(&s.pool, ws_id, ctx.user.id).await?;
    Ok(Json(PersonalCalendarResponse { blocks, tasks }))
}

async fn has_any_link(pool: &sqlx::PgPool, user_id: Uuid) -> sqlx::Result<bool> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM user_links WHERE user_a_id = $1 OR user_b_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

async fn link_for(
    pool: &sqlx::PgPool,
    viewer_id: Uuid,
    link_id: Uuid,
) -> ApiResult<crate::models::UserLink> {
    let mut all = db::list_user_links(pool, viewer_id).await?;
    let pos = all
        .iter()
        .position(|l| l.id == link_id)
        .ok_or(ApiError::NotFound)?;
    Ok(all.swap_remove(pos))
}
