// Library entry point. Exposes the modules so all three binaries (the API
// server, the seed CLI, and the dump-bootstrap CLI) share one source of
// truth instead of compiling their own copies via `#[path = ...]`.
//
// `seed` is no longer gated on the `dev_auth` feature: the HTTP endpoint
// that uses it (`/auth/dev-seed`) still is, but the module itself is
// always available so out-of-process consumers (the dump-bootstrap bin)
// can call it regardless of feature flags.

pub mod attachments;
pub mod auth;
pub mod db;
pub mod ensure_scope;
pub mod error;
pub mod gcal;
pub mod invites;
pub mod links;
pub mod models;
pub mod ops;
pub mod pubsub;
pub mod seed;
pub mod storage;
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
    pub storage: storage::StorageBackend,
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
    pub tags: Vec<models::Tag>,
    pub blocks: Vec<models::TimeBlock>,
    pub gcal: Vec<models::GcalEvent>,
    /// All links involving the caller (pending sent / received +
    /// accepted). Bootstrapping with this means the link icon in the
    /// topbar can render the right state on first paint.
    pub links: Vec<models::UserLink>,
    /// Pending workspace invites involving the caller (sent or
    /// addressed to caller's email). Drives the receive-side modal and
    /// the sender's "pending invites" list.
    pub workspace_invites: Vec<models::WorkspaceInvite>,
    /// Initial cursor for the change feed. Clients should poll
    /// `/changes?since=cursor` from this watermark forward.
    pub cursor: i64,
    /// Caller's account-scoped settings (personal/work badge, etc.).
    /// Always present — empty defaults if the user has never saved any.
    pub settings: models::UserSettings,
}

/// Run the same set of queries `/api/bootstrap` runs, scoped to the given
/// (workspace, user). Used by the HTTP handler and by the snapshot dumper.
pub async fn load_bootstrap(
    pool: &PgPool,
    workspace_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> anyhow::Result<Bootstrap> {
    let scope = db::project_scope(pool, user_id, workspace_id).await?;
    // Fetch the caller's email for the invite query — invites are keyed
    // by canonical email, not user_id, so the recipient side of a
    // pending invite needs an email lookup.
    let user_email: (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    // Run the hydrate queries sequentially rather than fanning out 12
    // concurrent `tokio::try_join!` branches. Each branch acquired its own
    // pool connection, so one bootstrap peaked at 12 connections at once —
    // ~8 concurrent bootstraps exhausted a 100-connection pool and every
    // other request started failing on `acquire_timeout`. Sequential keeps
    // a bootstrap to one connection at a time. The latency cost is
    // negligible: the `tasks` query dominates and the other 11 are
    // sub-millisecond.
    let users = db::list_users_in_scope(pool, workspace_id, user_id).await?;
    let projects = db::list_projects_in_scope(pool, &scope).await?;
    let epics = db::list_epics_in_scope(pool, &scope).await?;
    let sprints = db::list_sprints_in_scope(pool, &scope).await?;
    let tasks = db::list_tasks_in_scope(pool, &scope).await?;
    let tags = db::list_tags_in_scope(pool, &scope).await?;
    let blocks = db::list_blocks_in_scope(pool, &scope).await?;
    let gcal = db::list_gcal_for_user(pool, user_id).await?;
    let links = db::list_user_links(pool, user_id).await?;
    let workspace_invites = db::list_workspace_invites(pool, user_id, &user_email.0).await?;
    let cursor = ops::current_cursor(pool).await?;
    let settings = db::get_user_settings(pool, user_id).await?;
    Ok(Bootstrap {
        users,
        projects,
        epics,
        sprints,
        tasks,
        tags,
        blocks,
        gcal,
        links,
        workspace_invites,
        cursor,
        settings,
    })
}
