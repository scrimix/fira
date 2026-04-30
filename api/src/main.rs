use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, patch, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

mod auth;
mod db;
mod error;
mod models;
mod ops;
mod seed;

use auth::{AuthConfig, AuthUser};
use error::ApiResult;
use models::*;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth: AuthConfig,
}

#[derive(Serialize)]
struct Bootstrap {
    users: Vec<User>,
    projects: Vec<Project>,
    epics: Vec<Epic>,
    sprints: Vec<Sprint>,
    tasks: Vec<Task>,
    blocks: Vec<TimeBlock>,
    gcal: Vec<GcalEvent>,
    /// Initial cursor for the change feed. Clients should poll
    /// `/changes?since=cursor` from this watermark forward.
    cursor: i64,
}

async fn bootstrap(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Bootstrap>> {
    let scope = db::project_scope(&s.pool, user.id).await?;
    let (users, projects, epics, sprints, tasks, blocks, gcal, cursor) = tokio::try_join!(
        db::list_users_in_scope(&s.pool, &scope, user.id),
        db::list_projects_in_scope(&s.pool, &scope),
        db::list_epics_in_scope(&s.pool, &scope),
        db::list_sprints_in_scope(&s.pool, &scope),
        db::list_tasks_in_scope(&s.pool, &scope),
        db::list_blocks_in_scope(&s.pool, &scope),
        db::list_gcal_for_user(&s.pool, user.id),
        ops::current_cursor(&s.pool),
    )?;
    Ok(Json(Bootstrap { users, projects, epics, sprints, tasks, blocks, gcal, cursor }))
}

async fn projects(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<Project>>> {
    let scope = db::project_scope(&s.pool, user.id).await?;
    Ok(Json(db::list_projects_in_scope(&s.pool, &scope).await?))
}

// All users in the system, used by the project editor's Members picker so
// owners can add teammates they haven't worked with yet. Auth is required
// (no anonymous user enumeration) but no scope filter — the picker needs
// the full directory.
async fn all_users(
    State(s): State<AppState>,
    _user: AuthUser,
) -> ApiResult<Json<Vec<User>>> {
    Ok(Json(db::list_all_users(&s.pool).await?))
}

#[derive(Deserialize)]
struct CreateProject {
    title: String,
    icon: String,
    color: String,
}

async fn create_project(
    State(s): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateProject>,
) -> Result<(StatusCode, Json<Project>), error::ApiError> {
    let title = body.title.trim();
    validate_title(title)?;
    if !is_hex_color(&body.color) {
        return Err(error::ApiError::BadRequest("color must be a hex string".into()));
    }
    validate_icon(&body.icon)?;
    let mut tx = s.pool.begin().await?;
    let project = db::create_project_tx(&mut tx, user.id, title, &body.icon, &body.color).await?;
    // Log so peers viewing the same project see the new project show up in
    // their next /changes poll. The synthesized op kind matches what the
    // client knows how to apply.
    let payload = serde_json::json!({ "kind": "project.create", "project": &project });
    ops::record_synthesized_op(&mut tx, user.id, "project.create", payload, Some(project.id)).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(project)))
}

#[derive(Deserialize)]
struct UpdateProject {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    color: Option<String>,
    /// Three-state: absent = leave alone, null = clear, string = set.
    /// `serde_with::rust::double_option` would be cleaner but we don't pull
    /// that crate in; the manual deserializer below does the same job.
    #[serde(default, deserialize_with = "deserialize_explicit_option")]
    external_url_template: Option<Option<String>>,
}

// Disambiguates "field missing" (None) from "field is JSON null"
// (Some(None)) so PATCH can leave a nullable column alone vs. clear it.
fn deserialize_explicit_option<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Option<String> = Option::deserialize(d)?;
    Ok(Some(v))
}

async fn update_project(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateProject>,
) -> ApiResult<Json<Project>> {
    let title = match body.title.as_deref().map(str::trim) {
        Some(t) => { validate_title(t)?; Some(t) }
        None => None,
    };
    if let Some(c) = body.color.as_deref() {
        if !is_hex_color(c) {
            return Err(error::ApiError::BadRequest("color must be a hex string".into()));
        }
    }
    if let Some(i) = body.icon.as_deref() {
        validate_icon(i)?;
    }
    // Trim + collapse empty-string-to-null so the UI can clear the field
    // by sending "" without the client knowing about JSON null.
    let eut: Option<Option<&str>> = body.external_url_template.as_ref().map(|v| {
        v.as_deref().map(str::trim).filter(|s| !s.is_empty())
    });
    if let Some(Some(t)) = eut {
        validate_url_template(t)?;
    }
    let mut tx = s.pool.begin().await?;
    let project = db::update_project_tx(
        &mut tx,
        user.id,
        id,
        title,
        body.icon.as_deref(),
        body.color.as_deref(),
        eut,
    )
    .await?
    .ok_or(error::ApiError::NotFound)?;
    let payload = serde_json::json!({ "kind": "project.update", "project": &project });
    ops::record_synthesized_op(&mut tx, user.id, "project.update", payload, Some(project.id)).await?;
    tx.commit().await?;
    Ok(Json(project))
}

fn validate_url_template(t: &str) -> Result<(), error::ApiError> {
    if t.len() > 512 {
        return Err(error::ApiError::BadRequest("url template is too long".into()));
    }
    if !(t.starts_with("http://") || t.starts_with("https://")) {
        return Err(error::ApiError::BadRequest(
            "url template must start with http:// or https://".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct SetMembers {
    members: Vec<uuid::Uuid>,
}

// Replace project membership wholesale. Member changes are their own op
// (`project.set_members`) — separate from visual edits — so clients can
// apply the two concerns independently and ex-members can drop the project
// from local state on receiving the removal op.
async fn set_project_members(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<SetMembers>,
) -> ApiResult<Json<Project>> {
    let mut tx = s.pool.begin().await?;
    let project = db::set_project_members_tx(&mut tx, user.id, id, &body.members)
        .await?
        .ok_or(error::ApiError::NotFound)?;
    let payload = serde_json::json!({
        "kind": "project.set_members",
        "project_id": project.id,
        "members": &project.members,
    });
    ops::record_synthesized_op(
        &mut tx, user.id, "project.set_members", payload, Some(project.id),
    ).await?;
    tx.commit().await?;
    Ok(Json(project))
}

fn validate_title(t: &str) -> Result<(), error::ApiError> {
    if t.is_empty() {
        return Err(error::ApiError::BadRequest("title is required".into()));
    }
    if t.len() > 80 {
        return Err(error::ApiError::BadRequest("title is too long".into()));
    }
    Ok(())
}

fn validate_icon(i: &str) -> Result<(), error::ApiError> {
    // Either a Lucide name (alphanumeric, ≤32 chars) or a short legacy
    // unicode glyph (≤4 chars). The picker writes Lucide names exclusively;
    // this only protects against junk on the wire.
    if i.chars().count() > 32 {
        return Err(error::ApiError::BadRequest("icon is too long".into()));
    }
    Ok(())
}

fn is_hex_color(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'#') {
        return false;
    }
    let rest = &bytes[1..];
    matches!(rest.len(), 3 | 6 | 8) && rest.iter().all(|b| b.is_ascii_hexdigit())
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://fira:fira@localhost:5432/fira".into());
    let bind = std::env::var("API_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());

    let pool = wait_for_pool(&database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let auth_cfg = AuthConfig::from_env();
    if auth_cfg.dev_auth {
        tracing::warn!("DEV_AUTH=1 — /auth/dev-login is enabled. Do not use in production.");
    }
    let state = AppState { pool, auth: auth_cfg };

    // CORS: the web SPA hits the API same-origin in dev (via Vite's /api proxy)
    // and in prod (served behind the same domain). Keep it permissive for read
    // routes but allow credentials so cookies travel on auth routes.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/me", get(auth::me))
        .route("/auth/config", get(auth::config))
        .route("/auth/google/login", get(auth::google_login))
        .route("/auth/google/callback", get(auth::google_callback))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/dev-login", get(auth::dev_login))
        .route("/auth/dev-seed", post(auth::dev_seed))
        .route("/bootstrap", get(bootstrap))
        .route("/projects", get(projects).post(create_project))
        .route("/projects/:id", patch(update_project))
        .route("/projects/:id/members", put(set_project_members))
        .route("/users", get(all_users))
        .route("/ops", post(ops::post_ops))
        .route("/changes", get(ops::get_changes))
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("fira-api listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn wait_for_pool(url: &str) -> anyhow::Result<PgPool> {
    let mut attempts = 0;
    loop {
        match PgPool::connect(url).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                attempts += 1;
                if attempts >= 30 {
                    return Err(e.into());
                }
                tracing::warn!("postgres not ready ({e}), retry {attempts}/30");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
