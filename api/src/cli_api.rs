// task-cli support (sprint 34): automation tokens and the /api/cli/* API.
//
// Tokens are bearer secrets for non-browser clients. Each is pinned to one
// (user, workspace), stored only as a sha256 hash, and accepted *only* by
// the `/api/cli/*` routes through the `CliCtx` extractor — never by the
// cookie-session extractors that guard the rest of the API. That route
// restriction is what "scoped" means: a leaked token can read and edit
// tasks/sprints in its workspace through the narrow CLI surface, but it
// cannot bootstrap, change settings, manage members or mint more tokens.
//
// Writes go through the same `ops::apply_payload` seam as the web outbox,
// so an op means exactly the same thing from either client and lands in
// the same change log. What differs is the envelope: `/api/cli/apply`
// applies a whole batch in one transaction, guarded by revision
// preconditions, so a publish either lands completely against the state
// the user reviewed or not at all.

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use chrono::{DateTime, NaiveDate, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::ensure_scope::require_project_access;
use crate::error::{ApiError, ApiResult};
use crate::ops::{self, Op, OpEnvelope};
use crate::AppState;

const TOKEN_PREFIX: &str = "fira_";

/// Kinds the CLI may send. Everything is a create or an edit: the CLI
/// never deletes tasks or sprints remotely (sprint 34 "Removal and
/// deletion"), and it has no business touching time, goals or links.
/// Tags and tracks are only *used*: they're project structure, managed by
/// leads in Fira.
/// `subtask.delete` is allowed because subtasks are an ordered value list
/// on the task — removing a checklist line is an edit of the task.
const ALLOWED_KINDS: &[&str] = &[
    "task.create",
    "task.set_title",
    "task.set_description",
    "task.set_status",
    "task.set_assignee",
    "task.set_estimate",
    "task.set_tags",
    "task.set_sprint",
    "subtask.create",
    "subtask.tick",
    "subtask.set_title",
    "subtask.delete",
    "subtask.reorder",
    "sprint.create",
    "sprint.set_title",
    "sprint.set_dates",
    "sprint.set_track",
    "sprint.set_defaults",
];

pub fn hash_token(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn generate_token() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    )
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ---- extractor ----

/// Caller of a `/api/cli/*` route, authenticated by automation token.
#[derive(Clone, Debug)]
pub struct CliCtx {
    pub token_id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub can_write: bool,
}

#[async_trait]
impl<S> FromRequestParts<S> for CliCtx
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| t.starts_with(TOKEN_PREFIX))
            .ok_or_else(|| {
                json_error(
                    StatusCode::UNAUTHORIZED,
                    "automation token required (Authorization: Bearer fira_…)",
                )
            })?;
        match load_token_ctx(&app.pool, token).await {
            Ok(Some(ctx)) => Ok(ctx),
            Ok(None) => Err(json_error(
                StatusCode::UNAUTHORIZED,
                "token is invalid, revoked, or its user is no longer a workspace member",
            )),
            // Same posture as session lookup: a DB blip is not an auth
            // failure, so don't make the client discard its credential.
            Err(e) => {
                tracing::warn!("token lookup transient error: {e:?}");
                Err(json_error(StatusCode::SERVICE_UNAVAILABLE, "token lookup unavailable"))
            }
        }
    }
}

/// Resolve a plaintext token. Membership is re-checked here on every
/// request, so a user removed from the workspace loses access at once.
pub async fn load_token_ctx(pool: &PgPool, token: &str) -> sqlx::Result<Option<CliCtx>> {
    let row: Option<(Uuid, Uuid, Uuid, bool)> = sqlx::query_as(
        "UPDATE automation_tokens t SET last_used_at = now()
         WHERE t.token_hash = $1 AND t.revoked_at IS NULL
           AND EXISTS (SELECT 1 FROM workspace_members wm
                       WHERE wm.workspace_id = t.workspace_id AND wm.user_id = t.user_id
                         AND wm.removed_at IS NULL)
         RETURNING t.id, t.user_id, t.workspace_id, t.can_write",
    )
    .bind(hash_token(token))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(token_id, user_id, workspace_id, can_write)| CliCtx {
        token_id,
        user_id,
        workspace_id,
        can_write,
    }))
}

// ---- token management (cookie session only) ----

#[derive(Serialize, sqlx::FromRow)]
pub struct TokenSummary {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub can_write: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub async fn list_tokens(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<Vec<TokenSummary>>> {
    let rows = sqlx::query_as(
        "SELECT id, name, token_prefix, can_write, created_at, last_used_at
         FROM automation_tokens
         WHERE user_id = $1 AND workspace_id = $2 AND revoked_at IS NULL
         ORDER BY created_at DESC",
    )
    .bind(ctx.user.id)
    .bind(ctx.workspace_id)
    .fetch_all(&s.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct CreateToken {
    pub name: String,
    #[serde(default)]
    pub can_write: bool,
}

#[derive(Serialize)]
pub struct CreatedToken {
    #[serde(flatten)]
    pub summary: TokenSummary,
    /// Plaintext, returned exactly once.
    pub token: String,
}

pub async fn create_token(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Json(body): Json<CreateToken>,
) -> Result<(StatusCode, Json<CreatedToken>), ApiError> {
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(ApiError::BadRequest(
            "token name is required (at most 80 characters)".into(),
        ));
    }
    let token = generate_token();
    let prefix: String = token.chars().take(TOKEN_PREFIX.len() + 6).collect();
    let summary: TokenSummary = sqlx::query_as(
        "INSERT INTO automation_tokens (id, user_id, workspace_id, name, token_hash, token_prefix, can_write)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, name, token_prefix, can_write, created_at, last_used_at",
    )
    .bind(Uuid::new_v4())
    .bind(ctx.user.id)
    .bind(ctx.workspace_id)
    .bind(name)
    .bind(hash_token(&token))
    .bind(&prefix)
    .bind(body.can_write)
    .fetch_one(&s.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(CreatedToken { summary, token })))
}

pub async fn revoke_token(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let res = sqlx::query(
        "UPDATE automation_tokens SET revoked_at = now()
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(ctx.user.id)
    .execute(&s.pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---- GET /api/cli/whoami ----

#[derive(Serialize)]
pub struct WhoAmI {
    pub user: CliUser,
    pub workspace: CliNamed,
    pub can_write: bool,
    pub projects: Vec<CliNamed>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CliNamed {
    pub id: Uuid,
    pub title: String,
}

#[derive(Serialize, sqlx::FromRow, Clone)]
pub struct CliUser {
    pub id: Uuid,
    pub email: String,
    pub name: String,
}

pub async fn whoami(State(s): State<AppState>, ctx: CliCtx) -> ApiResult<Json<WhoAmI>> {
    let user: CliUser = sqlx::query_as("SELECT id, email, name FROM users WHERE id = $1")
        .bind(ctx.user_id)
        .fetch_one(&s.pool)
        .await?;
    let workspace: CliNamed = sqlx::query_as("SELECT id, title FROM workspaces WHERE id = $1")
        .bind(ctx.workspace_id)
        .fetch_one(&s.pool)
        .await?;
    let scope = crate::db::project_scope(&s.pool, ctx.user_id, ctx.workspace_id).await?;
    let projects: Vec<CliNamed> =
        sqlx::query_as("SELECT id, title FROM projects WHERE id = ANY($1) ORDER BY title")
            .bind(&scope)
            .fetch_all(&s.pool)
            .await?;
    Ok(Json(WhoAmI {
        user,
        workspace,
        can_write: ctx.can_write,
        projects,
    }))
}

// ---- POST /api/cli/fetch ----

#[derive(Deserialize)]
pub struct FetchRequest {
    pub project_id: Uuid,
    #[serde(default)]
    pub sprint_ids: Vec<Uuid>,
    #[serde(default)]
    pub task_ids: Vec<Uuid>,
    /// Also return every sprint in the project (without their tasks).
    /// Used to map a task's sprint membership to a local file, and by
    /// `import` to tell a sprint id from a task id.
    #[serde(default)]
    pub all_sprints: bool,
}

#[derive(Serialize)]
pub struct FetchResponse {
    pub project: CliNamed,
    /// The project's owner and members, plus users referenced by the
    /// returned rows. `active` = may be assigned.
    pub users: Vec<CliMember>,
    pub tags: Vec<CliNamed>,
    pub tracks: Vec<CliNamed>,
    pub sprints: Vec<CliSprint>,
    pub tasks: Vec<CliTask>,
    pub missing: Vec<Missing>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CliMember {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    /// May be newly assigned (owner or active member).
    pub active: bool,
    /// Currently in the project (any role). The CLI derives its short
    /// assignee handles from members only, so a former member who is
    /// merely referenced by an old task can't change anyone's handle.
    pub member: bool,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CliSprint {
    pub id: Uuid,
    pub title: String,
    pub starts_on: Option<NaiveDate>,
    pub ends_on: Option<NaiveDate>,
    pub track_id: Option<Uuid>,
    pub default_assignee_id: Option<Uuid>,
    pub default_tag_ids: Vec<Uuid>,
    pub revision: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CliTask {
    pub id: Uuid,
    pub sprint_id: Option<Uuid>,
    pub title: String,
    pub description_md: String,
    pub status: String,
    pub section: String,
    pub assignee_id: Option<Uuid>,
    pub estimate_min: Option<i32>,
    pub tag_ids: Vec<Uuid>,
    #[sqlx(skip)]
    pub subtasks: Vec<CliSubtask>,
    /// Sprint 35. Compared by filename + sha256; written through
    /// `/api/cli/tasks/:id/attachments/:filename`.
    #[sqlx(skip)]
    pub attachments: Vec<crate::cli_attachments::CliAttachment>,
    pub revision: i64,
    pub sort_key: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CliSubtask {
    #[serde(skip)]
    pub task_id: Uuid,
    pub id: Uuid,
    pub title: String,
    pub done: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Missing {
    pub id: Uuid,
    pub kind: &'static str,
    /// `deleted`: a delete op for it is in this project's history.
    /// `other_project`: it exists in another project the caller can see.
    /// `never`: no trace the caller is allowed to see.
    pub state: &'static str,
}

pub async fn fetch(
    State(s): State<AppState>,
    ctx: CliCtx,
    Json(req): Json<FetchRequest>,
) -> ApiResult<Json<FetchResponse>> {
    Ok(Json(fetch_state(&s.pool, &s.storage, &ctx, &req).await?))
}

pub async fn fetch_state(
    pool: &PgPool,
    storage: &crate::storage::StorageBackend,
    ctx: &CliCtx,
    req: &FetchRequest,
) -> ApiResult<FetchResponse> {
    {
        let mut tx = pool.begin().await?;
        if require_project_access(&mut tx, ctx.user_id, ctx.workspace_id, req.project_id)
            .await
            .is_err()
        {
            return Err(ApiError::NotFound);
        }
        tx.rollback().await?;
    }
    let project: CliNamed = sqlx::query_as("SELECT id, title FROM projects WHERE id = $1")
        .bind(req.project_id)
        .fetch_one(pool)
        .await?;
    let tags: Vec<CliNamed> =
        sqlx::query_as("SELECT id, title FROM tags WHERE project_id = $1 ORDER BY title, id")
            .bind(req.project_id)
            .fetch_all(pool)
            .await?;
    let tracks: Vec<CliNamed> =
        sqlx::query_as("SELECT id, title FROM tracks WHERE project_id = $1 ORDER BY sort_key, title")
            .bind(req.project_id)
            .fetch_all(pool)
            .await?;
    let sprints: Vec<CliSprint> = sqlx::query_as(
        "SELECT id, title, starts_on, ends_on, track_id, default_assignee_id, revision,
                ARRAY(SELECT tag_id FROM sprint_default_tags WHERE sprint_id = sprints.id ORDER BY tag_id) AS default_tag_ids
         FROM sprints
         WHERE project_id = $1 AND ($2 OR id = ANY($3))
         ORDER BY starts_on NULLS LAST, sort_key, created_at",
    )
    .bind(req.project_id)
    .bind(req.all_sprints)
    .bind(&req.sprint_ids)
    .fetch_all(pool)
    .await?;
    let mut tasks: Vec<CliTask> = sqlx::query_as(
        "SELECT id, sprint_id, title, description_md, status, section, assignee_id,
                estimate_min, revision, sort_key,
                ARRAY(SELECT tag_id FROM task_tags WHERE task_id = tasks.id ORDER BY tag_id) AS tag_ids
         FROM tasks
         WHERE project_id = $1 AND (id = ANY($2) OR sprint_id = ANY($3))
         ORDER BY sort_key, created_at, id",
    )
    .bind(req.project_id)
    .bind(&req.task_ids)
    .bind(&req.sprint_ids)
    .fetch_all(pool)
    .await?;
    let task_ids: Vec<Uuid> = tasks.iter().map(|t| t.id).collect();
    let subtasks: Vec<CliSubtask> = sqlx::query_as(
        "SELECT task_id, id, title, done FROM subtasks
         WHERE task_id = ANY($1) ORDER BY sort_key, id",
    )
    .bind(&task_ids)
    .fetch_all(pool)
    .await?;
    for sub in subtasks {
        if let Some(t) = tasks.iter_mut().find(|t| t.id == sub.task_id) {
            t.subtasks.push(sub);
        }
    }
    for a in crate::cli_attachments::attachments_for_tasks(pool, storage, &task_ids).await? {
        if let Some(t) = tasks.iter_mut().find(|t| t.id == a.task_id) {
            t.attachments.push((&a).into());
        }
    }

    // Everyone who can be assigned, plus anyone the returned rows already
    // point at (e.g. a former member still assigned to an old task), so the
    // CLI can show every assignee by name. Only `active` users may be newly
    // assigned.
    let mut referenced: Vec<Uuid> = tasks.iter().filter_map(|t| t.assignee_id).collect();
    referenced.extend(sprints.iter().filter_map(|s| s.default_assignee_id));
    let users: Vec<CliMember> = sqlx::query_as(
        "SELECT u.id, u.email, u.name,
                (u.id = p.owner_id OR EXISTS (
                    SELECT 1 FROM project_members m
                    WHERE m.project_id = p.id AND m.user_id = u.id
                      AND m.removed_at IS NULL AND m.role <> 'inactive')) AS active,
                (u.id = p.owner_id OR EXISTS (
                    SELECT 1 FROM project_members m
                    WHERE m.project_id = p.id AND m.user_id = u.id
                      AND m.removed_at IS NULL)) AS member
         FROM users u JOIN projects p ON p.id = $1
         WHERE u.id = p.owner_id
            OR u.id IN (SELECT user_id FROM project_members WHERE project_id = $1 AND removed_at IS NULL)
            OR u.id = ANY($2)
         ORDER BY u.email",
    )
    .bind(req.project_id)
    .bind(&referenced)
    .fetch_all(pool)
    .await?;

    let mut missing = Vec::new();
    let scope = crate::db::project_scope(pool, ctx.user_id, ctx.workspace_id).await?;
    for id in &req.sprint_ids {
        if !sprints.iter().any(|s| s.id == *id) {
            missing.push(Missing {
                id: *id,
                kind: "sprint",
                state: existence(pool, "sprints", "sprint.delete", "sprint_id", *id, &scope).await?,
            });
        }
    }
    for id in &req.task_ids {
        if !tasks.iter().any(|t| t.id == *id) {
            missing.push(Missing {
                id: *id,
                kind: "task",
                state: existence(pool, "tasks", "task.delete", "task_id", *id, &scope).await?,
            });
        }
    }

    Ok(FetchResponse {
        project,
        users,
        tags,
        tracks,
        sprints,
        tasks,
        missing,
    })
}

/// Why an id the caller asked about is not in the requested project.
/// Only projects in the caller's scope are consulted, so this never
/// reveals anything about rows the caller couldn't otherwise see.
async fn existence(
    pool: &PgPool,
    table: &str,
    delete_kind: &str,
    id_field: &str,
    id: Uuid,
    scope: &[Uuid],
) -> sqlx::Result<&'static str> {
    let elsewhere: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {table} WHERE id = $1 AND project_id = ANY($2))"
    ))
    .bind(id)
    .bind(scope)
    .fetch_one(pool)
    .await?;
    if elsewhere {
        return Ok("other_project");
    }
    let deleted: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM processed_ops
                       WHERE kind = $1 AND payload->>$2 = $3 AND project_id = ANY($4))",
    )
    .bind(delete_kind)
    .bind(id_field)
    .bind(id.to_string())
    .bind(scope)
    .fetch_one(pool)
    .await?;
    Ok(if deleted { "deleted" } else { "never" })
}

// ---- POST /api/cli/apply ----

#[derive(Deserialize)]
pub struct ApplyRequest {
    pub project_id: Uuid,
    #[serde(default)]
    pub preconditions: Vec<Precondition>,
    pub ops: Vec<OpEnvelope>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Precondition {
    /// `task` or `sprint`.
    pub kind: String,
    pub id: Uuid,
    /// The revision the client previewed; `None` = "must not exist yet".
    pub revision: Option<i64>,
}

#[derive(Serialize, Debug)]
pub struct Conflict {
    pub kind: String,
    pub id: Uuid,
    pub expected: Option<i64>,
    pub actual: Option<i64>,
}

#[derive(Serialize, Debug)]
pub struct ApplyResponse {
    pub applied: usize,
    /// Ops whose op_id was already in the log (a retried request).
    pub already_applied: usize,
}

#[derive(Debug)]
pub enum ApplyError {
    Forbidden(String),
    NotFound,
    Conflicts(Vec<Conflict>),
    /// A specific op was rejected; nothing in the batch was applied.
    Rejected { index: usize, op_id: String, message: String },
    Db(sqlx::Error),
}

impl From<sqlx::Error> for ApplyError {
    fn from(e: sqlx::Error) -> Self {
        ApplyError::Db(e)
    }
}

impl IntoResponse for ApplyError {
    fn into_response(self) -> Response {
        match self {
            ApplyError::Forbidden(m) => json_error(StatusCode::FORBIDDEN, &m),
            ApplyError::NotFound => json_error(StatusCode::NOT_FOUND, "project not found"),
            ApplyError::Conflicts(conflicts) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "remote state changed since the preview; nothing was applied",
                    "conflicts": conflicts,
                })),
            )
                .into_response(),
            ApplyError::Rejected { index, op_id, message } => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("op {index} ({op_id}) rejected: {message}; nothing was applied"),
                    "index": index,
                    "op_id": op_id,
                })),
            )
                .into_response(),
            ApplyError::Db(e) => {
                tracing::warn!("cli apply db error: {e:?}");
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database unavailable; nothing was applied, retry the command",
                )
            }
        }
    }
}

pub async fn apply(
    State(s): State<AppState>,
    ctx: CliCtx,
    Json(req): Json<ApplyRequest>,
) -> Result<Json<ApplyResponse>, ApplyError> {
    Ok(Json(apply_batch(&s.pool, &ctx, req, &s.storage).await?))
}

/// All-or-nothing: lock and check every precondition, apply every op, log
/// them, commit. Any failure rolls the whole batch back.
pub async fn apply_batch(
    pool: &PgPool,
    ctx: &CliCtx,
    req: ApplyRequest,
    storage: &crate::storage::StorageBackend,
) -> Result<ApplyResponse, ApplyError> {
    if !ctx.can_write {
        return Err(ApplyError::Forbidden(
            "this token is read-only; create a write token in Fira account settings".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    if require_project_access(&mut tx, ctx.user_id, ctx.workspace_id, req.project_id)
        .await
        .is_err()
    {
        return Err(ApplyError::NotFound);
    }

    // Lock in a stable order so two concurrent publishes can't deadlock.
    let mut pres = req.preconditions.clone();
    pres.sort_by_key(|p| (p.kind.clone(), p.id));
    let mut conflicts = Vec::new();
    for p in &pres {
        let table = match p.kind.as_str() {
            "task" => "tasks",
            "sprint" => "sprints",
            other => {
                return Err(ApplyError::Rejected {
                    index: 0,
                    op_id: String::new(),
                    message: format!("unknown precondition kind {other:?}"),
                })
            }
        };
        let actual: Option<i64> = sqlx::query_scalar(&format!(
            "SELECT revision FROM {table} WHERE id = $1 AND project_id = $2 FOR UPDATE"
        ))
        .bind(p.id)
        .bind(req.project_id)
        .fetch_optional(&mut *tx)
        .await?;
        if actual != p.revision {
            conflicts.push(Conflict {
                kind: p.kind.clone(),
                id: p.id,
                expected: p.revision,
                actual,
            });
        }
    }
    if !conflicts.is_empty() {
        return Err(ApplyError::Conflicts(conflicts));
    }

    let mut applied = 0;
    let mut already_applied = 0;
    for (index, env) in req.ops.into_iter().enumerate() {
        let reject = |message: String| ApplyError::Rejected {
            index,
            op_id: env.op_id.clone(),
            message,
        };
        let op: Op = serde_json::from_value(env.payload.clone())
            .map_err(|e| reject(format!("invalid op: {e}")))?;
        let kind = op.kind_str();
        if !ALLOWED_KINDS.contains(&kind) {
            return Err(reject(format!("{kind} is not allowed through the CLI API")));
        }
        // A retried request: this op is already in the log, so its effect
        // is already in the database. Skip it rather than re-applying.
        let seen: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM processed_ops WHERE op_id = $1)")
                .bind(&env.op_id)
                .fetch_one(&mut *tx)
                .await?;
        if seen {
            already_applied += 1;
            continue;
        }
        let mut project_id = None;
        ops::apply_payload(&mut tx, ctx.user_id, ctx.workspace_id, op, &mut project_id, storage)
            .await
            .map_err(|e| match e.downcast_ref::<sqlx::Error>() {
                Some(sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed) => {
                    ApplyError::Db(e.downcast::<sqlx::Error>().expect("checked above"))
                }
                _ => reject(format!("{e:#}")),
            })?;
        if project_id != Some(req.project_id) {
            return Err(reject("op targets a different project".into()));
        }
        ops::log_op(
            &mut tx,
            &env.op_id,
            ctx.user_id,
            kind,
            &env.payload,
            project_id,
            ctx.workspace_id,
            None,
        )
        .await?;
        applied += 1;
    }
    tx.commit().await?;
    Ok(ApplyResponse {
        applied,
        already_applied,
    })
}
