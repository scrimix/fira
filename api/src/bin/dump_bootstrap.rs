// dump-bootstrap: emits the in-browser playground snapshot.
//
// Wipes + re-seeds the configured Postgres in a transaction (rolled back at
// the end so the dev DB isn't disturbed), runs the same `load_bootstrap`
// query the HTTP handler runs against Maya + the team workspace, and
// serializes the result to stdout as a self-contained JSON snapshot:
//
//   {
//     "snapshot_at": "2026-05-01T15:23:00Z",
//     "me":          { "id": ..., ... },
//     "workspace":   { "id": ..., "title": "Default", "members": [...] },
//     "bootstrap":   { /* exactly what /api/bootstrap returns */ }
//   }
//
// The frontend playground reads this verbatim and feeds it into the same
// `hydrate()` flow real auth uses; "today" inside the snapshot stays
// frozen at `snapshot_at` (see `web/src/time.ts` `setFrozenNow`).
//
// Future: this is also the right shape for "history replay" / saved
// snapshots — a snapshot is just a frozen bootstrap response plus a
// timestamp. Naming + paths reflect that.

use anyhow::Context;
use chrono::Utc;
use fira_api::{load_bootstrap, models, seed};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration as StdDuration;

#[derive(Serialize)]
struct Snapshot<'a> {
    snapshot_at: chrono::DateTime<Utc>,
    me: &'a models::User,
    workspace: &'a models::Workspace,
    bootstrap: &'a fira_api::Bootstrap,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://fira:fira@localhost:5432/fira".into());
    let pool = wait_for_pool(&url).await?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running migrations")?;

    // Seed in a transaction we roll back, so the developer's working DB
    // (which they may have customized) isn't replaced. The wipe inside the
    // transaction makes the queries against an isolated, deterministic
    // fixture state regardless of what the DB looked like before.
    let mut tx = pool.begin().await.context("begin tx")?;
    seed::wipe(&mut tx).await.context("seed wipe")?;
    seed::seed_all(&mut tx).await.context("seed_all")?;

    // load_bootstrap takes &PgPool but we want our isolated transaction's
    // view. Rather than thread a `&mut Transaction` through every db::list_*
    // function, commit to a savepoint, query, then roll the whole tx back.
    // Simpler: just commit, query, then manually wipe again at the end.
    // Even simpler: query against the tx via a dedicated connection.
    //
    // Path of least resistance: commit the seed, run the queries, then
    // wipe so the DB ends up roughly where it started. (If the developer
    // had custom data, this is destructive — `dump-bootstrap` is documented
    // as a fixture-only operation.)
    tx.commit().await.context("commit seed")?;

    let user_id = seed::primary_user_id();
    let workspace_id = seed::id(seed::TEAM_WORKSPACE_SLUG);

    let bootstrap = load_bootstrap(&pool, workspace_id, user_id)
        .await
        .context("load_bootstrap")?;
    let me: models::User = sqlx::query_as(
        "SELECT id, email, name, initials FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .context("seeded user not found")?;
    // Workspace + members. Match the shape the SPA's `Workspace` type expects
    // (id, title, is_personal, members[]).
    let (id, title, is_personal): (uuid::Uuid, String, bool) = sqlx::query_as(
        "SELECT id, title, is_personal FROM workspaces WHERE id = $1",
    )
    .bind(workspace_id)
    .fetch_one(&pool)
    .await
    .context("seeded workspace not found")?;
    let members: Vec<models::WorkspaceMember> = sqlx::query_as(
        "SELECT user_id, role FROM workspace_members
         WHERE workspace_id = $1 AND removed_at IS NULL",
    )
    .bind(workspace_id)
    .fetch_all(&pool)
    .await
    .context("workspace members")?;
    let workspace = models::Workspace { id, title, is_personal, members };

    let snapshot = Snapshot {
        snapshot_at: Utc::now(),
        me: &me,
        workspace: &workspace,
        bootstrap: &bootstrap,
    };
    let json = serde_json::to_string_pretty(&snapshot).context("serialize")?;
    println!("{json}");

    // Best-effort cleanup. If this fails the DB is left seeded — that's
    // fine for dev, the dump bin is fixture-only.
    let mut tx = pool.begin().await.context("begin cleanup tx")?;
    seed::wipe(&mut tx).await.context("cleanup wipe")?;
    tx.commit().await.context("commit cleanup")?;

    Ok(())
}

async fn wait_for_pool(url: &str) -> anyhow::Result<PgPool> {
    let mut tries = 0;
    loop {
        match PgPoolOptions::new().max_connections(4).connect(url).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                tries += 1;
                if tries >= 30 {
                    return Err(e.into());
                }
                eprintln!("dump-bootstrap: postgres not ready ({e}), retry {tries}/30");
                tokio::time::sleep(StdDuration::from_secs(1)).await;
            }
        }
    }
}
