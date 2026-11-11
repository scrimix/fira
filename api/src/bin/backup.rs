//! Daily logical backup of the Fira database to S3-compatible storage
//! (Tigris in production). Runs as a scheduled Fly machine; see
//! `ops/backup/README.md`.
//!
//! ```text
//! fira-backup                 dump → verify → upload → verify size → prune old dumps
//! fira-backup list            list stored dumps
//! fira-backup fetch <key> [out-file]
//! ```
//!
//! Env: `DATABASE_URL`, `BUCKET_NAME`, and the `AWS_*` variables that
//! `fly storage create` sets (`AWS_REGION`, `AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT_URL_S3`), read through the same
//! `storage::S3Storage` the API uses. Optional: `BACKUP_KEY` (object key
//! override), `RETENTION_DAYS` (default 30), `BACKUP_DRY_RUN=1` (dump and
//! verify only; no storage access).
//!
//! Needs `pg_dump` and `pg_restore` on PATH, same major version as the server.

use anyhow::{bail, Context, Result};
use fira_api::storage::S3Storage;
use sqlx::Connection;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const KEY_PREFIX: &str = "fira-";
const KEY_SUFFIX: &str = ".dump";
/// Tables whose data must be in every dump; a dump without them is broken.
const REQUIRED_TABLES: &[&str] = &[
    "tasks",
    "subtasks",
    "sprints",
    "projects",
    "users",
    "_sqlx_migrations",
];

macro_rules! log {
    ($($arg:tt)*) => { eprintln!("fira-backup: {}", format!($($arg)*)) };
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None | Some("run") => run().await,
        Some("list") => list().await,
        Some("fetch") => match args.get(1) {
            Some(key) => fetch(key, args.get(2).map(String::as_str).unwrap_or(key)).await,
            None => Err(anyhow::anyhow!("usage: fira-backup fetch <key> [out-file]")),
        },
        Some(other) => Err(anyhow::anyhow!(
            "unknown command {other:?}; use run, list or fetch <key> [out-file]"
        )),
    };
    if let Err(e) = result {
        log!("FAILED: {e:#}");
        std::process::exit(1);
    }
}

fn storage() -> Result<S3Storage> {
    // Without an endpoint the SDK would talk to AWS S3 instead of Tigris.
    for var in ["BUCKET_NAME", "AWS_ENDPOINT_URL_S3"] {
        if std::env::var(var).map(|v| v.is_empty()).unwrap_or(true) {
            bail!("{var} is not set");
        }
    }
    S3Storage::from_env("AWS")
}

fn today_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

async fn run() -> Result<()> {
    let dry_run = std::env::var("BACKUP_DRY_RUN").as_deref() == Ok("1");
    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?;
    let retention_days: u64 = match std::env::var("RETENTION_DAYS") {
        Ok(v) => v.parse().context("RETENTION_DAYS must be a whole number of days")?,
        Err(_) => 30,
    };
    let key = std::env::var("BACKUP_KEY")
        .unwrap_or_else(|_| format!("{KEY_PREFIX}{}{KEY_SUFFIX}", today_utc()));
    // Build the client before dumping so a config error fails fast.
    let storage = if dry_run { None } else { Some(storage()?) };

    check_versions(&database_url).await?;

    let dump_path = std::env::temp_dir().join(format!("fira-backup-{}.dump", std::process::id()));
    let result = dump_and_upload(&database_url, &dump_path, &key, storage.as_ref()).await;
    let _ = std::fs::remove_file(&dump_path);
    result?;

    if let Some(storage) = &storage {
        prune(storage, &key, retention_days).await?;
    }
    log!("done: {key}");
    Ok(())
}

/// pg_dump refuses servers newer than itself; an older server works, but the
/// image is meant to match, so a mismatch is logged loudly.
async fn check_versions(database_url: &str) -> Result<()> {
    let mut conn = sqlx::PgConnection::connect(database_url)
        .await
        .context("connecting to DATABASE_URL")?;
    let server_num: i32 =
        sqlx::query_scalar("select current_setting('server_version_num')::int")
            .fetch_one(&mut conn)
            .await?;
    conn.close().await.ok();
    let server_major = server_num / 10000;

    let out = Command::new("pg_dump")
        .arg("--version")
        .output()
        .context("running pg_dump --version (is pg_dump on PATH?)")?;
    let version = String::from_utf8_lossy(&out.stdout);
    let client_major: i32 = version
        .split_whitespace()
        .find_map(|w| w.split('.').next()?.parse().ok())
        .with_context(|| format!("cannot parse pg_dump version from {version:?}"))?;

    log!("server postgres {server_major}, pg_dump {client_major}");
    if server_major != client_major {
        log!("WARNING: pg_dump major ({client_major}) != server major ({server_major}); rebuild with --build-arg PG_MAJOR={server_major}");
    }
    Ok(())
}

async fn dump_and_upload(
    database_url: &str,
    dump_path: &std::path::Path,
    key: &str,
    storage: Option<&S3Storage>,
) -> Result<()> {
    log!("dumping");
    let status = Command::new("pg_dump")
        .args(["-Fc", "--no-owner", "--no-privileges", "-f"])
        .arg(dump_path)
        .arg(database_url)
        .status()
        .context("running pg_dump")?;
    if !status.success() {
        bail!("pg_dump exited with {status}");
    }

    // The archive must be readable and contain the core tables.
    let out = Command::new("pg_restore")
        .arg("--list")
        .arg(dump_path)
        .output()
        .context("running pg_restore --list")?;
    if !out.status.success() {
        bail!(
            "pg_restore --list failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let toc = String::from_utf8_lossy(&out.stdout);
    for table in REQUIRED_TABLES {
        let needle = format!("TABLE DATA public {table} ");
        if !toc.lines().any(|l| l.contains(&needle)) {
            bail!("dump is missing table data for {table:?}");
        }
    }
    let data = std::fs::read(dump_path).context("reading dump file")?;
    let size = data.len() as i64;
    log!("dump ok: {size} bytes");

    let Some(storage) = storage else {
        log!("dry run: not uploading {key}");
        return Ok(());
    };

    log!(
        "endpoint: {}, bucket: {}",
        std::env::var("AWS_ENDPOINT_URL_S3").unwrap_or_default(),
        storage.bucket_name
    );
    log!("uploading {key}");
    storage.upload_file(key, data).await?;

    let head = storage
        .s3_client
        .head_object()
        .bucket(&storage.bucket_name)
        .key(key)
        .send()
        .await
        .with_context(|| format!("checking uploaded object {key}"))?;
    let remote_size = head.content_length().unwrap_or(-1);
    if remote_size != size {
        bail!("uploaded size {remote_size} != local size {size}");
    }
    Ok(())
}

/// One stored dump: key, size in bytes, last-modified as unix seconds.
async fn list_dumps(storage: &S3Storage) -> Result<Vec<(String, i64, i64)>> {
    let mut dumps = Vec::new();
    let mut pages = storage
        .s3_client
        .list_objects_v2()
        .bucket(&storage.bucket_name)
        .prefix(KEY_PREFIX)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        let page = page.context("listing bucket")?;
        for obj in page.contents() {
            let (Some(key), Some(modified)) = (obj.key(), obj.last_modified()) else {
                continue;
            };
            if key.ends_with(KEY_SUFFIX) {
                dumps.push((key.to_string(), obj.size().unwrap_or(0), modified.secs()));
            }
        }
    }
    dumps.sort();
    Ok(dumps)
}

/// Deletes `fira-*.dump` objects older than `retention_days`. Runs only after
/// a successful upload and never deletes the dump just written, so a broken
/// backup job leaves old dumps in place instead of emptying the bucket.
async fn prune(storage: &S3Storage, just_uploaded: &str, retention_days: u64) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let cutoff = now - (retention_days as i64) * 86_400;
    for (key, _, modified) in list_dumps(storage).await? {
        if key != just_uploaded && modified < cutoff {
            log!("pruning {key} (older than {retention_days} days)");
            storage.delete_file(&key).await?;
        }
    }
    Ok(())
}

async fn list() -> Result<()> {
    let storage = storage()?;
    for (key, size, modified) in list_dumps(&storage).await? {
        let when = chrono::DateTime::from_timestamp(modified, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_default();
        println!("{key}\t{size}\t{when}");
    }
    Ok(())
}

async fn fetch(key: &str, out: &str) -> Result<()> {
    let storage = storage()?;
    let data = storage.download_file(key).await?;
    std::fs::write(out, &data).with_context(|| format!("writing {out}"))?;
    log!("fetched {key} -> {out} ({} bytes)", data.len());
    Ok(())
}
