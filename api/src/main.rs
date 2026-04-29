use axum::{extract::State, response::Json, routing::get, Router};
use serde::Serialize;
use sqlx::PgPool;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

mod db;
mod error;
mod models;

use error::ApiResult;
use models::*;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
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
}

async fn bootstrap(State(s): State<AppState>) -> ApiResult<Json<Bootstrap>> {
    let (users, projects, epics, sprints, tasks, blocks, gcal) = tokio::try_join!(
        db::list_users(&s.pool),
        db::list_projects(&s.pool),
        db::list_epics(&s.pool),
        db::list_sprints(&s.pool),
        db::list_tasks(&s.pool),
        db::list_time_blocks(&s.pool),
        db::list_gcal_events(&s.pool),
    )?;
    Ok(Json(Bootstrap { users, projects, epics, sprints, tasks, blocks, gcal }))
}

async fn users(State(s): State<AppState>) -> ApiResult<Json<Vec<User>>> {
    Ok(Json(db::list_users(&s.pool).await?))
}
async fn projects(State(s): State<AppState>) -> ApiResult<Json<Vec<Project>>> {
    Ok(Json(db::list_projects(&s.pool).await?))
}
async fn epics(State(s): State<AppState>) -> ApiResult<Json<Vec<Epic>>> {
    Ok(Json(db::list_epics(&s.pool).await?))
}
async fn sprints(State(s): State<AppState>) -> ApiResult<Json<Vec<Sprint>>> {
    Ok(Json(db::list_sprints(&s.pool).await?))
}
async fn tasks(State(s): State<AppState>) -> ApiResult<Json<Vec<Task>>> {
    Ok(Json(db::list_tasks(&s.pool).await?))
}
async fn blocks(State(s): State<AppState>) -> ApiResult<Json<Vec<TimeBlock>>> {
    Ok(Json(db::list_time_blocks(&s.pool).await?))
}
async fn gcal(State(s): State<AppState>) -> ApiResult<Json<Vec<GcalEvent>>> {
    Ok(Json(db::list_gcal_events(&s.pool).await?))
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

    let state = AppState { pool };

    let app = Router::new()
        .route("/health", get(health))
        .route("/bootstrap", get(bootstrap))
        .route("/users", get(users))
        .route("/projects", get(projects))
        .route("/epics", get(epics))
        .route("/sprints", get(sprints))
        .route("/tasks", get(tasks))
        .route("/blocks", get(blocks))
        .route("/gcal", get(gcal))
        .with_state(state)
        .layer(CorsLayer::permissive())
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
