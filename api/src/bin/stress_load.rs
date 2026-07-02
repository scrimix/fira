// Stress-test load client. Drives the API at /api with up to 1000
// concurrent virtual users, each replaying a realistic usage pattern
// (~70% reads / ~30% writes) against the seeded `fira_stress` dataset.
//
// Reads loadtest/loadtest-map.json (produced by stress_seed) for the
// pre-minted session tokens. Each virtual user bootstraps once, caches
// the project/task/tag ids it sees, then loops through ~21 sample
// operations until the deadline, recording per-operation latency.
//
// Run (after stress_seed + a fira_stress API on :3100):
//   cargo run --release --bin stress_load
// Tunable via env:
//   LOAD_URL (http://localhost:3100)  LOAD_CONCURRENCY (1000)
//   LOAD_DURATION_SECS (60)           LOAD_RAMP_SECS (20)

use chrono::{Duration as ChronoDuration, Utc};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone)]
struct Session {
    token: String,
    user_id: Uuid,
    workspace_id: Uuid,
}

/// (operation label, weight). Weights are relative; ~63/95 reads.
const OPS: &[(&str, u32)] = &[
    // reads
    ("changes", 30),
    ("projects", 16),
    ("me", 16),
    // bootstrap is a 31 MB workspace dump — every user already does one
    // mandatory hydrate at start; in-loop it stays rare on purpose.
    ("bootstrap", 1),
    // task writes
    ("task.tick", 5),
    ("task.set_status", 3),
    ("task.set_section", 2),
    ("task.create", 3),
    ("task.set_title", 2),
    ("task.set_assignee", 2),
    ("task.set_estimate", 2),
    ("task.set_description", 1),
    ("task.reorder", 2),
    ("task.delete", 1),
    // subtask writes
    ("subtask.create", 2),
    ("subtask.tick", 1),
    // block writes
    ("block.create", 2),
    ("block.update", 1),
    ("block.delete", 1),
    // tag writes
    ("tag.create", 1),
    ("task.set_tags", 1),
];

#[derive(Default, Clone)]
struct Stat {
    lat_ms: Vec<u32>, // latency of every attempt, whatever the outcome
    ok: u64,
    err: u64,     // HTTP 4xx or per-op status:"error"
    unavail: u64, // HTTP 503 (pool exhaustion / transient)
    fail: u64,    // transport error / no response
}

impl Stat {
    fn merge(&mut self, o: &Stat) {
        self.lat_ms.extend_from_slice(&o.lat_ms);
        self.ok += o.ok;
        self.err += o.err;
        self.unavail += o.unavail;
        self.fail += o.fail;
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
    Ok,
    Err,
    Unavail,
    Fail,
}

/// Per-virtual-user mutable state, hydrated from the initial bootstrap.
struct UserState {
    projects: Vec<Uuid>,
    project_tasks: HashMap<Uuid, Vec<Uuid>>, // sampled, per project
    project_tags: HashMap<Uuid, Vec<Uuid>>,  // tags grouped by their project
    seed_tasks: Vec<Uuid>,                   // flat sample across projects
    created_tasks: Vec<Uuid>,
    created_subtasks: Vec<Uuid>,
    created_blocks: Vec<Uuid>,
    created_tags: Vec<Uuid>,
    cursor: i64,
    counter: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env_str("LOAD_URL", "http://localhost:3100");
    let concurrency: usize = env_str("LOAD_CONCURRENCY", "1000").parse()?;
    let duration_secs: u64 = env_str("LOAD_DURATION_SECS", "60").parse()?;
    let ramp_secs: u64 = env_str("LOAD_RAMP_SECS", "20").parse()?;

    // Discover the load-test sessions straight from the seeded DB — the
    // single source of truth. There is no map file to drift out of sync
    // with what stress_seed actually wrote.
    let db_url = env_str(
        "LOAD_DB_URL",
        "postgres://fira:fira@postgres:5432/fira_stress",
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&db_url)
        .await?;
    let rows: Vec<(String, Uuid, Uuid)> = sqlx::query_as(
        "SELECT s.id, s.user_id, wm.workspace_id
         FROM sessions s
         JOIN workspace_members wm ON wm.user_id = s.user_id
         WHERE s.user_agent = 'loadtest' AND wm.removed_at IS NULL
         ORDER BY s.id",
    )
    .fetch_all(&pool)
    .await?;
    pool.close().await;
    let sessions: Vec<Session> = rows
        .into_iter()
        .map(|(token, user_id, workspace_id)| Session {
            token,
            user_id,
            workspace_id,
        })
        .collect();
    if sessions.is_empty() {
        anyhow::bail!("no load-test sessions in {db_url} — run stress_seed first");
    }
    println!(
        "stress_load: {} sessions from DB, target={url}, concurrency={concurrency}, \
         duration={duration_secs}s, ramp={ramp_secs}s",
        sessions.len()
    );

    let client = Arc::new(
        reqwest::Client::builder()
            .pool_max_idle_per_host(concurrency + 64)
            .timeout(Duration::from_secs(30))
            .build()?,
    );
    let base = Arc::new(url);

    let wall_start = Instant::now();
    // Deadline is measured from the end of the ramp so every user gets the
    // full steady-state window.
    let deadline = wall_start + Duration::from_secs(ramp_secs + duration_secs);

    let mut handles = Vec::with_capacity(concurrency);
    for i in 0..concurrency {
        let session = sessions[i % sessions.len()].clone();
        let client = client.clone();
        let base = base.clone();
        let ramp_delay = Duration::from_millis(
            (ramp_secs * 1000).saturating_mul(i as u64) / concurrency.max(1) as u64,
        );
        handles.push(tokio::spawn(async move {
            run_user(client, base, session, deadline, ramp_delay, i as u64).await
        }));
    }

    // Heartbeat while the test runs.
    let total = handles.len();
    let hb = tokio::spawn(async move {
        let mut t = 0u64;
        while wall_start.elapsed() < Duration::from_secs(ramp_secs + duration_secs) {
            tokio::time::sleep(Duration::from_secs(5)).await;
            t += 5;
            println!("stress_load:   ...{t}s elapsed");
        }
    });

    let mut merged: HashMap<String, Stat> = HashMap::new();
    for h in handles {
        if let Ok(stats) = h.await {
            for (k, v) in stats {
                merged.entry(k.to_string()).or_default().merge(&v);
            }
        }
    }
    hb.abort();
    let elapsed = wall_start.elapsed().as_secs_f64();

    report(&merged, elapsed, total);
    Ok(())
}

async fn run_user(
    client: Arc<reqwest::Client>,
    base: Arc<String>,
    session: Session,
    deadline: Instant,
    ramp_delay: Duration,
    seed: u64,
) -> HashMap<&'static str, Stat> {
    let mut stats: HashMap<&'static str, Stat> = HashMap::new();
    let mut rng = StdRng::seed_from_u64(0x10AD_0000 + seed);
    tokio::time::sleep(ramp_delay).await;

    // ---- initial bootstrap: hydrate this user's state ----
    let mut st = UserState {
        projects: vec![],
        project_tasks: HashMap::new(),
        project_tags: HashMap::new(),
        seed_tasks: vec![],
        created_tasks: vec![],
        created_subtasks: vec![],
        created_blocks: vec![],
        created_tags: vec![],
        cursor: 0,
        counter: 0,
    };
    let (lat, outcome, body) = get(&client, &base, &session, "/api/bootstrap").await;
    record(&mut stats, "bootstrap", lat, outcome);
    if let Some(bytes) = body {
        if let Ok(d) = serde_json::from_slice::<Value>(&bytes) {
            hydrate(&mut st, &d);
        }
    }
    // A user that never hydrated can't issue meaningful writes; still let
    // them exercise reads.
    let cum: Vec<u32> = OPS
        .iter()
        .scan(0, |a, (_, w)| {
            *a += w;
            Some(*a)
        })
        .collect();
    let total_w = *cum.last().unwrap();

    // ---- steady-state loop ----
    while Instant::now() < deadline {
        let r = rng.gen_range(0..total_w);
        let idx = cum.iter().position(|&c| r < c).unwrap();
        let op = OPS[idx].0;
        let (label, lat, outcome) = exec(&client, &base, &session, op, &mut st, &mut rng).await;
        record(&mut stats, label, lat, outcome);
        // think-time
        tokio::time::sleep(Duration::from_millis(rng.gen_range(150..900))).await;
    }
    stats
}

/// Dispatch one operation. Returns (stable label, latency ms, outcome).
async fn exec(
    client: &reqwest::Client,
    base: &str,
    s: &Session,
    op: &'static str,
    st: &mut UserState,
    rng: &mut StdRng,
) -> (&'static str, u32, Outcome) {
    match op {
        "bootstrap" => {
            let (l, o, _) = get(client, base, s, "/api/bootstrap").await;
            ("bootstrap", l, o)
        }
        "me" => {
            let (l, o, _) = get(client, base, s, "/api/me").await;
            ("me", l, o)
        }
        "projects" => {
            let (l, o, _) = get(client, base, s, "/api/projects").await;
            ("projects", l, o)
        }
        "changes" => {
            let path = format!("/api/changes?since={}", st.cursor);
            let (l, o, body) = get(client, base, s, &path).await;
            if let Some(b) = body {
                if let Ok(v) = serde_json::from_slice::<Value>(&b) {
                    if let Some(c) = v["cursor"].as_i64() {
                        st.cursor = c;
                    }
                }
            }
            ("changes", l, o)
        }
        // ---- writes: build a single-op /api/ops batch ----
        _ => {
            let payload = build_op(op, s, st, rng);
            match payload {
                Some(p) => {
                    let (l, o) = post_op(client, base, s, &p).await;
                    (op, l, o)
                }
                // Not enough local state yet (e.g. block.update with no
                // created block) — fall back to a cheap read so the slot
                // isn't wasted, attributed to the read.
                None => {
                    let (l, o, _) = get(client, base, s, "/api/me").await;
                    ("me", l, o)
                }
            }
        }
    }
}

/// Construct the op payload object for a write op, or None if the user
/// lacks the prerequisite state.
fn build_op(op: &str, s: &Session, st: &mut UserState, rng: &mut StdRng) -> Option<Value> {
    let pick = |v: &[Uuid], rng: &mut StdRng| v.choose(rng).copied();
    match op {
        "task.create" => {
            let pid = pick(&st.projects, rng)?;
            let id = Uuid::new_v4();
            st.created_tasks.push(id);
            st.project_tasks.entry(pid).or_default().push(id);
            Some(json!({"kind":"task.create","task":{
                "id":id,"project_id":pid,"title":"loadtest task",
                "section":"now","status":"todo","source":"local","spent_min":0}}))
        }
        "task.tick" => {
            let t = pick(&st.seed_tasks, rng)?;
            Some(json!({"kind":"task.tick","task_id":t,"done":rng.gen_bool(0.5)}))
        }
        "task.set_status" => {
            let t = pick(&st.seed_tasks, rng)?;
            let status = ["backlog", "todo", "in_progress", "done"][rng.gen_range(0..4)];
            Some(json!({"kind":"task.set_status","task_id":t,"status":status}))
        }
        "task.set_section" => {
            let t = pick(&st.seed_tasks, rng)?;
            let sec = ["now", "later", "done", "someday", "recurring"][rng.gen_range(0..5)];
            Some(json!({"kind":"task.set_section","task_id":t,"section":sec}))
        }
        "task.set_title" => {
            let t = pick(&st.seed_tasks, rng)?;
            st.counter += 1;
            Some(json!({"kind":"task.set_title","task_id":t,
                "title":format!("retitled {}",st.counter)}))
        }
        "task.set_assignee" => {
            let t = pick(&st.seed_tasks, rng)?;
            Some(json!({"kind":"task.set_assignee","task_id":t,"assignee_id":s.user_id}))
        }
        "task.set_estimate" => {
            let t = pick(&st.seed_tasks, rng)?;
            Some(json!({"kind":"task.set_estimate","task_id":t,
                "estimate_min":rng.gen_range(15..480)}))
        }
        "task.set_description" => {
            let t = pick(&st.seed_tasks, rng)?;
            Some(json!({"kind":"task.set_description","task_id":t,
                "description_md":"updated under load"}))
        }
        "task.reorder" => {
            let pid = pick(&st.projects, rng)?;
            let tasks = st.project_tasks.get(&pid)?;
            if tasks.len() < 3 {
                return None;
            }
            let mut sample: Vec<Uuid> = tasks.choose_multiple(rng, 8).copied().collect();
            sample.shuffle(rng);
            Some(json!({"kind":"task.reorder","project_id":pid,"ordered":sample}))
        }
        "task.delete" => {
            // Only ever delete tasks this user created, to keep the seed
            // dataset stable across the run.
            if st.created_tasks.is_empty() {
                return None;
            }
            let i = rng.gen_range(0..st.created_tasks.len());
            let id = st.created_tasks.swap_remove(i);
            Some(json!({"kind":"task.delete","task_id":id}))
        }
        "subtask.create" => {
            let t = pick(&st.seed_tasks, rng)?;
            let id = Uuid::new_v4();
            st.created_subtasks.push(id);
            Some(json!({"kind":"subtask.create","subtask":{
                "id":id,"task_id":t,"title":"loadtest subtask"}}))
        }
        "subtask.tick" => {
            let id = pick(&st.created_subtasks, rng)?;
            Some(json!({"kind":"subtask.tick","subtask_id":id,"done":rng.gen_bool(0.5)}))
        }
        "block.create" => {
            let t = pick(&st.seed_tasks, rng)?;
            let id = Uuid::new_v4();
            st.created_blocks.push(id);
            let start = Utc::now() + ChronoDuration::minutes(rng.gen_range(0..10_000));
            let end = start + ChronoDuration::minutes(rng.gen_range(15..120));
            Some(json!({"kind":"block.create","block":{
                "id":id,"task_id":t,"user_id":s.user_id,
                "start_at":start.to_rfc3339(),"end_at":end.to_rfc3339(),
                "state":"planned"}}))
        }
        "block.update" => {
            let id = pick(&st.created_blocks, rng)?;
            Some(json!({"kind":"block.update","block_id":id,
                "patch":{"state":if rng.gen_bool(0.5){"completed"}else{"planned"}}}))
        }
        "block.delete" => {
            if st.created_blocks.is_empty() {
                return None;
            }
            let i = rng.gen_range(0..st.created_blocks.len());
            let id = st.created_blocks.swap_remove(i);
            Some(json!({"kind":"block.delete","block_id":id}))
        }
        "tag.create" => {
            let pid = pick(&st.projects, rng)?;
            let id = Uuid::new_v4();
            st.created_tags.push(id);
            st.project_tags.entry(pid).or_default().push(id);
            // Title must be unique per project (case-insensitive). Derive it
            // from the tag's own UUID so it stays unique across reruns too.
            let title = format!("lt-{}", id.as_simple());
            Some(json!({"kind":"tag.create","tag":{
                "id":id,"project_id":pid,"title":title,"color":"#3b82f6"}}))
        }
        "task.set_tags" => {
            // Task and tags must share a project — the server rejects the
            // whole op if any tag crosses projects (ops.rs:584).
            let pid = pick(&st.projects, rng)?;
            let task = *st.project_tasks.get(&pid)?.choose(rng)?;
            let tags = st.project_tags.get(&pid)?;
            if tags.is_empty() {
                return None;
            }
            let sel: Vec<Uuid> = tags.choose_multiple(rng, 2).copied().collect();
            Some(json!({"kind":"task.set_tags","task_id":task,"tag_ids":sel}))
        }
        _ => None,
    }
}

fn hydrate(st: &mut UserState, d: &Value) {
    if let Some(arr) = d["projects"].as_array() {
        for p in arr {
            if let Some(id) = p["id"].as_str().and_then(|s| s.parse().ok()) {
                st.projects.push(id);
            }
        }
    }
    if let Some(arr) = d["tasks"].as_array() {
        // Sample up to 120 tasks per project + a flat 600-task pool.
        for t in arr {
            let (Some(id), Some(pid)) = (
                t["id"].as_str().and_then(|s| s.parse::<Uuid>().ok()),
                t["project_id"]
                    .as_str()
                    .and_then(|s| s.parse::<Uuid>().ok()),
            ) else {
                continue;
            };
            let v = st.project_tasks.entry(pid).or_default();
            if v.len() < 120 {
                v.push(id);
            }
            if st.seed_tasks.len() < 600 {
                st.seed_tasks.push(id);
            }
        }
    }
    if let Some(arr) = d["tags"].as_array() {
        for t in arr {
            let (Some(id), Some(pid)) = (
                t["id"].as_str().and_then(|s| s.parse::<Uuid>().ok()),
                t["project_id"]
                    .as_str()
                    .and_then(|s| s.parse::<Uuid>().ok()),
            ) else {
                continue;
            };
            st.project_tags.entry(pid).or_default().push(id);
        }
    }
    if let Some(c) = d["cursor"].as_i64() {
        st.cursor = c;
    }
}

/// GET a path, drain the body. Returns (latency ms, outcome, body bytes).
async fn get(
    client: &reqwest::Client,
    base: &str,
    s: &Session,
    path: &str,
) -> (u32, Outcome, Option<Vec<u8>>) {
    let t0 = Instant::now();
    let req = client
        .get(format!("{base}{path}"))
        .header("Cookie", format!("sid={}", s.token))
        .header("X-Workspace-Id", s.workspace_id.to_string());
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.bytes().await.ok().map(|b| b.to_vec());
            let ms = t0.elapsed().as_millis() as u32;
            let outcome = if status.as_u16() == 503 {
                Outcome::Unavail
            } else if status.is_success() {
                Outcome::Ok
            } else {
                Outcome::Err
            };
            (ms, outcome, body)
        }
        Err(_) => (t0.elapsed().as_millis() as u32, Outcome::Fail, None),
    }
}

/// POST a single-op batch to /api/ops. Returns (latency ms, outcome).
async fn post_op(
    client: &reqwest::Client,
    base: &str,
    s: &Session,
    payload: &Value,
) -> (u32, Outcome) {
    let body = json!({"ops":[{"op_id":Uuid::new_v4().to_string(),"payload":payload}]});
    let t0 = Instant::now();
    let req = client
        .post(format!("{base}/api/ops"))
        .header("Cookie", format!("sid={}", s.token))
        .header("X-Workspace-Id", s.workspace_id.to_string())
        .json(&body);
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let bytes = resp.bytes().await.ok();
            let ms = t0.elapsed().as_millis() as u32;
            if status.as_u16() == 503 {
                return (ms, Outcome::Unavail);
            }
            if !status.is_success() {
                return (ms, Outcome::Err);
            }
            // 200 — but a per-op rejection still counts as an error.
            let op_ok = bytes
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .and_then(|v| v["results"][0]["status"].as_str().map(|s| s == "ok"))
                .unwrap_or(false);
            (ms, if op_ok { Outcome::Ok } else { Outcome::Err })
        }
        Err(_) => (t0.elapsed().as_millis() as u32, Outcome::Fail),
    }
}

fn record(stats: &mut HashMap<&'static str, Stat>, label: &'static str, lat: u32, o: Outcome) {
    let e = stats.entry(label).or_default();
    e.lat_ms.push(lat);
    match o {
        Outcome::Ok => e.ok += 1,
        Outcome::Err => e.err += 1,
        Outcome::Unavail => e.unavail += 1,
        Outcome::Fail => e.fail += 1,
    }
}

fn pct(sorted: &[u32], p: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn report(merged: &HashMap<String, Stat>, elapsed: f64, users: usize) {
    let mut labels: Vec<&String> = merged.keys().collect();
    labels.sort();

    let (mut t_req, mut t_ok, mut t_err, mut t_un, mut t_fail) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut all_lat: Vec<u32> = vec![];

    println!("\n========== STRESS TEST RESULTS ==========");
    println!("virtual users: {users}   wall time: {elapsed:.1}s\n");
    println!(
        "{:<20} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>9}",
        "operation", "count", "p50ms", "p90ms", "p95ms", "p99ms", "maxms", "errors", "err%"
    );
    println!("{}", "-".repeat(96));
    for l in &labels {
        let s = &merged[*l];
        let mut lat = s.lat_ms.clone();
        lat.sort_unstable();
        let count = lat.len() as u64;
        let errs = s.err + s.unavail + s.fail;
        let errpct = if count > 0 {
            errs as f64 * 100.0 / count as f64
        } else {
            0.0
        };
        println!(
            "{:<20} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8.2}%",
            l,
            count,
            pct(&lat, 0.50),
            pct(&lat, 0.90),
            pct(&lat, 0.95),
            pct(&lat, 0.99),
            lat.last().copied().unwrap_or(0),
            errs,
            errpct
        );
        t_req += count;
        t_ok += s.ok;
        t_err += s.err;
        t_un += s.unavail;
        t_fail += s.fail;
        all_lat.extend_from_slice(&lat);
    }
    all_lat.sort_unstable();
    println!("{}", "-".repeat(96));
    println!(
        "{:<20} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "ALL",
        t_req,
        pct(&all_lat, 0.50),
        pct(&all_lat, 0.90),
        pct(&all_lat, 0.95),
        pct(&all_lat, 0.99),
        all_lat.last().copied().unwrap_or(0),
    );
    println!(
        "\ntotal requests: {t_req}   throughput: {:.0} req/s",
        t_req as f64 / elapsed
    );
    println!(
        "ok: {t_ok}   per-op/4xx errors: {t_err}   503 unavailable: {t_un}   transport failures: {t_fail}"
    );
    println!("=========================================");
}

fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}
