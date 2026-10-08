//! Opt-in performance characterization against an isolated sqlx test database.
//! Run: cargo test --release --test plan_history_perf -- --ignored --nocapture
//! Measures the real authorized service + JSON serialization, without HTTP,
//! compression or browser rendering. Never seeds or modifies the dev database.
use chrono::{DateTime, Duration, Utc};
use fira_api::{
    plan::{project_at, LoggedOp, PLAN_KINDS},
    plan_history::{read_history, read_snapshot},
    seed,
};
use serde::Serialize;
use sqlx::PgPool;
use std::time::Instant;
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Serialize)]
struct Latencies {
    samples: usize,
    p50_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}
fn latencies(mut values: Vec<f64>) -> Latencies {
    values.sort_by(f64::total_cmp);
    let percentile = |fraction: f64| {
        values[((values.len() as f64 * fraction).ceil() as usize - 1).min(values.len() - 1)]
    };
    Latencies {
        samples: values.len(),
        p50_ms: percentile(0.5),
        p95_ms: percentile(0.95),
        max_ms: *values.last().unwrap(),
    }
}
async fn read(pool: &PgPool, project: Uuid, at: DateTime<Utc>) -> f64 {
    let start = Instant::now();
    let history = read_snapshot(
        pool,
        seed::primary_user_id(),
        seed::id(seed::TEAM_WORKSPACE_SLUG),
        project,
        Some(at),
        None,
    )
    .await
    .unwrap();
    let json = serde_json::to_vec(&history).unwrap();
    std::hint::black_box(json);
    start.elapsed().as_secs_f64() * 1000.0
}

#[sqlx::test]
#[ignore = "opt-in performance test; creates a disposable database with up to 100,000 plan ops"]
async fn plan_history_scaling(pool: PgPool) {
    // sqlx's test wrapper uses a single-thread runtime. Run the load itself
    // on four workers so concurrent replay does not block all other reads.
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_suite(pool))
    })
    .await
    .unwrap();
}

async fn run_suite(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    seed::seed_all(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let project = seed::id("p_atlas");
    let workspace = seed::id(seed::TEAM_WORKSPACE_SLUG);
    let user = seed::primary_user_id();
    let base =
        DateTime::from_timestamp_micros((Utc::now() - Duration::days(365)).timestamp_micros())
            .unwrap();
    println!(
        "PLAN_HISTORY_PERF_CONFIG {}",
        serde_json::json!({
            "optimized": !cfg!(debug_assertions), "pool_connections": pool.options().get_max_connections(),
            "concurrency": 8, "runtime_workers": 4, "timings": "authorized DB read + replay + JSON serialization; no HTTP/compression"
        })
    );
    for (ops, tasks) in [
        (1_000_i64, 100_i64),
        (10_000, 1_000),
        (100_000, 1_000),
        (100_000, 10_000),
    ] {
        // Only the disposable test database is touched. Other seeded projects
        // remain present to exercise project/workspace query predicates.
        sqlx::query("DELETE FROM processed_ops WHERE project_id = $1")
            .bind(project)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO processed_ops (op_id,user_id,workspace_id,project_id,kind,payload,applied_at)
             SELECT gen_random_uuid()::text,$1,$2,$3,
               CASE WHEN n <= $5 THEN 'task.create' WHEN n % 4 = 0 THEN 'task.tick' ELSE 'task.set_title' END,
               CASE WHEN n <= $5 THEN jsonb_build_object('kind','task.create','task',jsonb_build_object(
                 'id',md5('history-perf-' || ((n-1) % $5)::text)::uuid,'project_id',$3,
                 'title','Task ' || n::text,'section','later','status','todo','source','local'))
               WHEN n % 4 = 0 THEN jsonb_build_object('kind','task.tick','task_id',md5('history-perf-' || ((n-1) % $5)::text)::uuid,'done',n % 8 = 0)
               ELSE jsonb_build_object('kind','task.set_title','task_id',md5('history-perf-' || ((n-1) % $5)::text)::uuid,'title','Revision ' || n::text) END,
               $6::timestamptz + n * interval '1 second'
             FROM generate_series(1,$4::bigint) AS n ORDER BY n"
        ).bind(user).bind(workspace).bind(project).bind(ops).bind(tasks).bind(base).execute(&pool).await.unwrap();
        sqlx::query("VACUUM (ANALYZE) processed_ops")
            .execute(&pool)
            .await
            .unwrap();
        let log_relation_bytes: i64 =
            sqlx::query_scalar("SELECT pg_total_relation_size('processed_ops')")
                .fetch_one(&pool)
                .await
                .unwrap();
        let end = base + Duration::seconds(ops);
        let first_read = read(&pool, project, end).await;
        let full = read_snapshot(&pool, user, workspace, project, Some(end), None)
            .await
            .unwrap();
        let metadata = read_history(&pool, user, workspace, project, None)
            .await
            .unwrap();
        assert_eq!(metadata.changes.len(), ops as usize);
        assert_eq!(full.state.tasks.len(), tasks as usize);
        let response_bytes = serde_json::to_vec(&full).unwrap().len();
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap().len();
        let snapshot_bytes = serde_json::to_vec(&full.state).unwrap().len();
        drop(full);
        let middle = base + Duration::seconds(ops / 2);
        let mut repeated = Vec::new();
        let mut scrub = Vec::new();
        for i in 0..12 {
            repeated.push(read(&pool, project, middle).await);
            scrub.push(
                read(
                    &pool,
                    project,
                    base + Duration::seconds(ops * (30 + i * 5) / 100),
                )
                .await,
            );
        }
        let concurrent_start = Instant::now();
        let mut workers = JoinSet::new();
        for worker in 0..8 {
            let pool = pool.clone();
            workers.spawn(async move {
                let mut samples = Vec::new();
                for i in 0..4 {
                    samples.push(
                        read(
                            &pool,
                            project,
                            base + Duration::seconds(ops * (30 + worker * 5 + i * 3) / 100),
                        )
                        .await,
                    );
                }
                samples
            });
        }
        let mut concurrent = Vec::new();
        while let Some(result) = workers.join_next().await {
            concurrent.extend(result.unwrap());
        }
        let concurrent_seconds = concurrent_start.elapsed().as_secs_f64();
        // Separately measure the fold to distinguish replay CPU from DB and
        // response serialization. Keep loading/parsing rows out of this timer.
        let rows: Vec<(i64, DateTime<Utc>, String, serde_json::Value)> = sqlx::query_as(
            "SELECT seq, applied_at, kind, payload FROM processed_ops WHERE project_id = $1 AND workspace_id = $2 AND kind = ANY($3) ORDER BY seq"
        ).bind(project).bind(workspace).bind(PLAN_KINDS).fetch_all(&pool).await.unwrap();
        let log: Vec<_> = rows
            .into_iter()
            .map(|(seq, applied_at, kind, payload)| LoggedOp {
                seq,
                applied_at,
                kind,
                payload,
            })
            .collect();
        let mut fold = Vec::new();
        for _ in 0..12 {
            let start = Instant::now();
            let state = project_at(&log, end);
            assert_eq!(state.tasks.len(), tasks as usize);
            std::hint::black_box(&state);
            fold.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        println!(
            "PLAN_HISTORY_PERF {}",
            serde_json::json!({
                "ops":ops,"tasks":tasks,"first_full_read_ms":first_read,"log_relation_bytes":log_relation_bytes,
                "response_bytes":response_bytes,"metadata_bytes":metadata_bytes,"snapshot_bytes":snapshot_bytes,
                "repeated_middle":latencies(repeated),"scrub":latencies(scrub),"concurrent":latencies(concurrent),
                "concurrent_reads_per_second":32.0/concurrent_seconds,"full_fold_only":latencies(fold)
            })
        );
    }
}
