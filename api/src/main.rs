use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, patch, post, put},
    Router,
};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use fira_api::{
    auth::{self, AuthConfig, AuthCtx},
    db, error,
    error::ApiResult,
    load_bootstrap,
    models::*,
    ops, pubsub,
    pubsub::Hub,
    workspaces, ws, AppState, Bootstrap,
};

async fn bootstrap(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<Bootstrap>> {
    let data = load_bootstrap(&s.pool, ctx.workspace_id, ctx.user.id)
        .await
        .map_err(error::ApiError::from)?;
    Ok(Json(data))
}

async fn projects(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> ApiResult<Json<Vec<Project>>> {
    let scope = db::project_scope(&s.pool, ctx.user.id, ctx.workspace_id).await?;
    Ok(Json(db::list_projects_in_scope(&s.pool, &scope).await?))
}

#[derive(Deserialize)]
struct CreateProject {
    title: String,
    icon: String,
    color: String,
}

async fn create_project(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Json(body): Json<CreateProject>,
) -> Result<(StatusCode, Json<Project>), error::ApiError> {
    if !ctx.is_owner() {
        return Err(error::ApiError::BadRequest(
            "only workspace owners can create projects".into(),
        ));
    }
    let title = body.title.trim();
    validate_title(title)?;
    if !is_hex_color(&body.color) {
        return Err(error::ApiError::BadRequest("color must be a hex string".into()));
    }
    validate_icon(&body.icon)?;
    let mut tx = s.pool.begin().await?;
    let project = db::create_project_tx(
        &mut tx, ctx.workspace_id, ctx.user.id, title, &body.icon, &body.color,
    ).await?;
    let payload = serde_json::json!({ "kind": "project.create", "project": &project });
    ops::record_synthesized_op(
        &mut tx, ctx.user.id, ctx.workspace_id, "project.create", payload, Some(project.id),
    ).await?;
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
    ctx: AuthCtx,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateProject>,
) -> ApiResult<Json<Project>> {
    authorize_project_edit(&s.pool, &ctx, id).await?;
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
        id,
        title,
        body.icon.as_deref(),
        body.color.as_deref(),
        eut,
    )
    .await?
    .ok_or(error::ApiError::NotFound)?;
    let payload = serde_json::json!({ "kind": "project.update", "project": &project });
    ops::record_synthesized_op(
        &mut tx, ctx.user.id, ctx.workspace_id, "project.update", payload, Some(project.id),
    ).await?;
    tx.commit().await?;
    Ok(Json(project))
}

/// Project edits are allowed for the workspace owner OR any project
/// `lead`. Returns 404 if the project doesn't exist or sits in a
/// different workspace from the caller's `X-Workspace-Id`.
async fn authorize_project_edit(
    pool: &sqlx::PgPool,
    ctx: &AuthCtx,
    project_id: uuid::Uuid,
) -> Result<(), error::ApiError> {
    let info = db::project_owner_and_workspace(pool, project_id)
        .await?
        .ok_or(error::ApiError::NotFound)?;
    let (workspace_id, _owner_id) = info;
    if workspace_id != ctx.workspace_id {
        return Err(error::ApiError::NotFound);
    }
    if db::has_project_lead_authority(pool, ctx.workspace_id, project_id, ctx.user.id).await? {
        Ok(())
    } else {
        Err(error::ApiError::BadRequest(
            "project edits require project lead or workspace owner".into(),
        ))
    }
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
    members: Vec<MemberSpec>,
}

#[derive(Deserialize, Clone)]
struct MemberSpec {
    user_id: uuid::Uuid,
    role: String,
}

// Replace project membership wholesale. Member changes are their own op
// (`project.set_members`) — separate from visual edits — so clients can
// apply the two concerns independently and ex-members can drop the project
// from local state on receiving the removal op.
async fn set_project_members(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<SetMembers>,
) -> ApiResult<Json<Project>> {
    authorize_project_edit(&s.pool, &ctx, id).await?;
    let info = db::project_owner_and_workspace(&s.pool, id)
        .await?
        .ok_or(error::ApiError::NotFound)?;
    for m in &body.members {
        if m.role != "lead" && m.role != "member" {
            return Err(error::ApiError::BadRequest("role must be lead|member".into()));
        }
    }
    // Only workspace owners may set/promote roles. Project leads can change
    // the membership set but can't reshuffle roles.
    let allow_role_change = ctx.is_owner();
    let desired: Vec<(uuid::Uuid, String)> = body.members.iter()
        .map(|m| (m.user_id, m.role.clone())).collect();
    let mut tx = s.pool.begin().await?;
    let project = db::set_project_members_tx(&mut tx, id, info.1, &desired, allow_role_change)
        .await?
        .ok_or(error::ApiError::NotFound)?;
    let payload = serde_json::json!({
        "kind": "project.set_members",
        "project_id": project.id,
        "members": &project.members,
    });
    ops::record_synthesized_op(
        &mut tx, ctx.user.id, ctx.workspace_id, "project.set_members", payload, Some(project.id),
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
    // Pre-tracing breadcrumb so `docker logs` shows *something* even if
    // tracing init panics or the process dies before we reach .init().
    eprintln!("fira-api: starting");
    dotenvy::dotenv().ok();

    // Default filter: everything from this crate at trace, everything else
    // at info. Keeps app logs maximally verbose by default; library noise
    // (sqlx query plans, hyper internals) stays at info. Override with
    // RUST_LOG, e.g. `RUST_LOG=fira_api=info,sqlx=warn`.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("fira_api=trace,info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://fira:fira@localhost:5432/fira".into());
    let bind = std::env::var("API_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let static_root = std::env::var("STATIC_ROOT").unwrap_or_else(|_| "dist".into());
    tracing::info!(
        bind = %bind,
        static_root = %static_root,
        db_host = %redact_db_host(&database_url),
        "resolved config"
    );

    // Lazy pool: never blocks startup, opens connections on first query.
    // Combined with the background migration loop below, this lets /health
    // come up immediately so Fly's healthcheck succeeds even if Postgres is
    // briefly unreachable (cold start, restart, network blip).
    let pool = PgPoolOptions::new().connect_lazy(&database_url)?;
    {
        let pool = pool.clone();
        tokio::spawn(async move {
            loop {
                match sqlx::migrate!("./migrations").run(&pool).await {
                    Ok(()) => {
                        tracing::info!("migrations applied");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("migrations failed ({e}), retrying in 5s");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    let auth_cfg = AuthConfig::from_env();
    if auth_cfg.dev_auth {
        tracing::warn!("DEV_AUTH=1 — /auth/dev-login is enabled. Do not use in production.");
    }
    let hub = Hub::new();
    pubsub::start_listener_task(pool.clone(), hub.clone());
    let state = AppState { pool, auth: auth_cfg, hub };

    // Same-origin in both dev (Vite proxy) and prod (api serves the SPA).
    // No CorsLayer needed; re-add scoped to the prod domain if a non-browser
    // caller appears.

    // SPA static fallback: any request that doesn't match an /api route falls
    // through to ServeDir, which serves files under STATIC_ROOT and rewrites
    // unknown paths to index.html so React Router can handle client-side
    // routing. In dev, STATIC_ROOT defaults to "dist" which doesn't exist —
    // ServeDir returns 404 and the developer is hitting Vite on :5173 anyway.
    let static_root = std::env::var("STATIC_ROOT").unwrap_or_else(|_| "dist".into());
    let serve_index = ServeFile::new(format!("{static_root}/index.html"));
    let static_svc = ServeDir::new(&static_root).not_found_service(serve_index);

    // All JSON / auth routes live under `/api`. The SPA's fetch wrapper
    // hard-codes `BASE = '/api'`; in dev, Vite proxies `/api/*` to the api on
    // :3000 unchanged (no strip); in prod, the api serves itself and routes
    // `/api/*` here. `/health` stays at the root for Fly's healthcheck.
    let api = Router::new()
        .route("/me", get(auth::me))
        .route("/auth/config", get(auth::config))
        .route("/auth/google/login", get(auth::google_login))
        .route("/auth/google/callback", get(auth::google_callback))
        .route("/auth/logout", post(auth::logout))
        .route("/bootstrap", get(bootstrap))
        .route("/projects", get(projects).post(create_project))
        .route("/projects/:id", patch(update_project))
        .route("/projects/:id/members", put(set_project_members))
        .route("/workspaces", get(workspaces::list_my).post(workspaces::create))
        .route("/workspaces/:id", patch(workspaces::rename))
        .route("/workspaces/:id/members", put(workspaces::set_members))
        .route("/workspaces/:id/members/:user_id", patch(workspaces::set_member_role))
        .route("/workspaces/:id/users", get(workspaces::list_users))
        .route("/workspaces/:id/all-users", get(workspaces::list_all_users))
        .route("/ops", post(ops::post_ops))
        .route("/changes", get(ops::get_changes))
        .route("/ws", get(ws::ws_handler));

    #[cfg(feature = "dev_auth")]
    let api = api
        .route("/auth/dev-login", get(auth::dev_login))
        .route("/auth/dev-seed", post(auth::dev_seed));

    let app = Router::new()
        .route("/health", get(health))
        .nest("/api", api)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .fallback_service(static_svc);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("fira-api listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Strip credentials and surface only `host[:port]/db` from the
/// connection string — safe to log, useful for "did the env var land".
fn redact_db_host(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("?");
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            let db = u.path().trim_start_matches('/');
            format!("{host}{port}/{db}")
        }
        Err(_) => "<unparseable>".into(),
    }
}

