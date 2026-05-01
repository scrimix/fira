// CLI seeder. Thin wrapper around the shared `seed` module — running
// `cargo run --bin seed` does the same wipe+seed the dev-only HTTP
// endpoint does, just without authenticating anyone.
//
// Pass `--drop` (or set `SEED_DROP=1`) to nuke and recreate the public
// schema before migrating. Useful when a migration's preconditions stop
// matching the current DB (e.g. the workspace migration TRUNCATEs project
// rows on a freshly-migrated DB but is a no-op if 0008 already ran).

use fira_api::seed;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration as StdDuration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://fira:fira@localhost:5432/fira".into());
    let drop = std::env::args().any(|a| a == "--drop")
        || std::env::var("SEED_DROP").map(|v| v == "1").unwrap_or(false);

    let pool = wait_for_pool(&url).await?;

    if drop {
        println!("seed: --drop set, dropping all tables in the public schema");
        // List every user table in `public` and drop it. Doing it
        // table-by-table (rather than `DROP SCHEMA public CASCADE`) sidesteps
        // permissions weirdness with extension-owned objects and means
        // sqlx's prepared-statement protocol stays happy. CASCADE on each
        // drop knocks out FKs without us having to topo-sort.
        let tables: Vec<(String,)> = sqlx::query_as(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
        )
        .fetch_all(&pool)
        .await?;
        for (t,) in &tables {
            sqlx::query(&format!("DROP TABLE IF EXISTS public.\"{t}\" CASCADE"))
                .execute(&pool)
                .await?;
        }
        // Stored functions (e.g. project_members_set_workspace_id) live
        // outside pg_tables — drop them too so a re-migrate doesn't trip on
        // CREATE FUNCTION already existing.
        let funcs: Vec<(String, String)> = sqlx::query_as(
            "SELECT n.nspname, p.proname
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public'",
        )
        .fetch_all(&pool)
        .await?;
        for (schema, fname) in &funcs {
            sqlx::query(&format!(
                "DROP FUNCTION IF EXISTS \"{schema}\".\"{fname}\" CASCADE"
            ))
            .execute(&pool)
            .await?;
        }
        println!("seed: dropped {} tables, {} functions", tables.len(), funcs.len());
    }

    sqlx::migrate!("./migrations").run(&pool).await?;

    let mut tx = pool.begin().await?;
    seed::wipe(&mut tx).await?;
    seed::seed_all(&mut tx).await?;
    tx.commit().await?;

    // Print what's actually in the workspaces table so it's obvious whether
    // the new code ran. If you still see a stale name, your *running* api
    // process has older code compiled in — restart `cargo watch` / the
    // api container to pick up changes.
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT title, is_personal FROM workspaces ORDER BY is_personal, title",
    )
    .fetch_all(&pool)
    .await?;
    println!("seed: workspaces in db now:");
    for (title, is_personal) in &rows {
        println!("  - {title}{}", if *is_personal { " (personal)" } else { "" });
    }
    println!("seed: done — restart the api process if it was running");
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
                eprintln!("seed: postgres not ready ({e}), retry {tries}/30");
                tokio::time::sleep(StdDuration::from_secs(1)).await;
            }
        }
    }
}
