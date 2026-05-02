// Library entry point. Exposes the modules so all three binaries (the API
// server, the seed CLI, and the dump-bootstrap CLI) share one source of
// truth instead of compiling their own copies via `#[path = ...]`.
//
// `seed` is no longer gated on the `dev_auth` feature: the HTTP endpoint
// that uses it (`/auth/dev-seed`) still is, but the module itself is
// always available so out-of-process consumers (the dump-bootstrap bin)
// can call it regardless of feature flags.

pub mod auth;
pub mod db;
pub mod error;
pub mod links;
pub mod models;
pub mod ops;
pub mod pubsub;
pub mod seed;
pub mod workspaces;
pub mod ws;

use auth::AuthConfig;
use pubsub::Hub;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth: AuthConfig,
    pub hub: Arc<Hub>,
}

/// The shape `/api/bootstrap` returns. Lifted out of `main.rs` so the
/// dump-bootstrap bin can serialize the same struct without re-declaring
/// the schema.
#[derive(serde::Serialize)]
pub struct Bootstrap {
    pub users: Vec<models::User>,
    pub projects: Vec<models::Project>,
    pub epics: Vec<models::Epic>,
    pub sprints: Vec<models::Sprint>,
    pub tasks: Vec<models::Task>,
    pub blocks: Vec<models::TimeBlock>,
    pub gcal: Vec<models::GcalEvent>,
    /// All links involving the caller (pending sent / received +
    /// accepted). Bootstrapping with this means the link icon in the
    /// topbar can render the right state on first paint.
    pub links: Vec<models::UserLink>,
    /// Initial cursor for the change feed. Clients should poll
    /// `/changes?since=cursor` from this watermark forward.
    pub cursor: i64,
}

/// Run the same set of queries `/api/bootstrap` runs, scoped to the given
/// (workspace, user). Used by the HTTP handler and by the snapshot dumper.
pub async fn load_bootstrap(
    pool: &PgPool,
    workspace_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> anyhow::Result<Bootstrap> {
    let scope = db::project_scope(pool, user_id, workspace_id).await?;
    let (users, projects, epics, sprints, tasks, blocks, gcal, links, cursor) = tokio::try_join!(
        db::list_users_in_scope(pool, workspace_id, user_id),
        db::list_projects_in_scope(pool, &scope),
        db::list_epics_in_scope(pool, &scope),
        db::list_sprints_in_scope(pool, &scope),
        db::list_tasks_in_scope(pool, &scope),
        db::list_blocks_in_scope(pool, &scope),
        db::list_gcal_for_user(pool, user_id),
        db::list_user_links(pool, user_id),
        ops::current_cursor(pool),
    )?;
    Ok(Bootstrap { users, projects, epics, sprints, tasks, blocks, gcal, links, cursor })
}
