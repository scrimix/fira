// CLI seeder. Thin wrapper around the shared `seed` module — running
// `cargo run --bin seed` does the same wipe+seed the dev-only HTTP
// endpoint does, just without authenticating anyone.

use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration as StdDuration;

#[path = "../seed.rs"]
mod seed;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://fira:fira@localhost:5432/fira".into());
    let pool = wait_for_pool(&url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let mut tx = pool.begin().await?;
    seed::wipe(&mut tx).await?;
    seed::seed_all(&mut tx).await?;
    tx.commit().await?;

    println!("seed: done");
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
