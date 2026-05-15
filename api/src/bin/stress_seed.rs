// Stress-test bulk seeder. Populates a *separate* `fira_stress` database
// with a large synthetic dataset via Postgres COPY:
//
//   20 workspaces  x  5 projects   = 100 projects
//   10,000 users   (~500 / workspace)
//   1,000,000 tasks (10,000 / project)
//   + epics / sprints / tags
//   + 1,000 pre-minted sessions for the load client
//
// The 20 "template tasks" are an in-code generator pool (TEMPLATES); every
// seeded task is a randomized clone of one of them.
//
// Run:
//   DATABASE_URL=postgres://fira:fira@postgres:5432/fira_stress \
//     cargo run --release --bin stress_seed
//
// Writes loadtest/loadtest-map.json (token -> user -> workspace) for the
// load client to consume.

use chrono::{Duration, Utc};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Instant;
use uuid::Uuid;

const WORKSPACES: usize = 20;
const PROJECTS_PER_WS: usize = 5;
const USERS_PER_WS: usize = 500;
const TAGS_PER_PROJECT: usize = 5;
const TASKS_PER_PROJECT: usize = 10_000;
const LOAD_USERS_PER_WS: usize = 50; // -> 1000 sessions total
const COPY_FLUSH_ROWS: usize = 50_000;

/// The 20 "template tasks": (title prefix, description, est-min lo, est-min hi).
const TEMPLATES: [(&str, &str, i32, i32); 20] = [
    ("Fix login redirect bug", "Session cookie dropped on cross-site redirect.", 30, 120),
    ("Write integration tests", "Cover the happy path and two failure modes.", 60, 240),
    ("Refactor auth module", "Split the 800-line file into extractor + service.", 120, 480),
    ("Update API docs", "Document the new /ops batch endpoint.", 30, 90),
    ("Design onboarding flow", "Three-step wizard, skippable.", 90, 300),
    ("Investigate slow query", "tasks_project_section index not used.", 45, 180),
    ("Add dark mode toggle", "Persist preference in user_settings.", 60, 150),
    ("Migrate to Postgres 16", "Test the upgrade on staging first.", 120, 360),
    ("Review PR #842", "Touches the pubsub hub - check the listener.", 20, 60),
    ("Plan Q3 roadmap", "Collect input from each squad lead.", 120, 480),
    ("Fix flaky CI job", "Race between the seeder and the API boot.", 45, 150),
    ("Implement rate limiting", "Token bucket per session on /ops.", 90, 300),
    ("Upgrade frontend deps", "Vite 5 -> 6, check the proxy config.", 30, 120),
    ("Write postmortem", "The Tuesday outage - timeline + action items.", 60, 120),
    ("Optimize bootstrap payload", "50k tasks per workspace is too much.", 90, 360),
    ("Add export to CSV", "Tasks list, respecting current filters.", 60, 180),
    ("Set up error tracking", "Wire Sentry into the API and web build.", 45, 120),
    ("Improve search relevance", "Title match should outrank description.", 90, 240),
    ("Schedule weekly 1:1", "Recurring - 30 min, calendar block.", 15, 30),
    ("Daily standup notes", "Recurring - capture blockers.", 10, 20),
];

/// Task sections, in weighted-bucket order (see the picker in the task loop).
const SECTIONS: [&str; 5] = ["now", "later", "done", "someday", "recurring"];
const PRIORITIES: [&str; 4] = ["p0", "p1", "p2", "p3"];
const TAG_COLORS: [&str; 6] = ["#ef4444", "#f59e0b", "#10b981", "#3b82f6", "#8b5cf6", "#ec4899"];
const PROJECT_COLORS: [&str; 6] =
    ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2"];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://fira:fira@postgres:5432/fira_stress".into());
    // Safety rail: never let this run against the dev fixture database.
    if !url.contains("fira_stress") {
        anyhow::bail!("DATABASE_URL must point at the `fira_stress` database, got: {url}");
    }
    let started = Instant::now();
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await?;

    println!("stress_seed: running migrations...");
    sqlx::migrate!("./migrations").run(&pool).await?;

    // Idempotent: wipe any prior stress data so reruns are clean.
    println!("stress_seed: truncating tenant tables...");
    sqlx::query(
        "TRUNCATE TABLE processed_ops, gcal_events, time_blocks, subtasks, task_tags,
         tags, tasks, sprints, epics, project_members, projects,
         workspace_members, workspaces, sessions, users RESTART IDENTITY CASCADE",
    )
    .execute(&pool)
    .await?;

    let mut rng = StdRng::seed_from_u64(0xF1A0_5EED_2026);

    // ---- generate ids in memory (FK order: users -> workspaces -> ...) ----
    let ws_ids: Vec<Uuid> = (0..WORKSPACES).map(|_| Uuid::new_v4()).collect();
    // ws_users[w] = the 500 user ids belonging to workspace w.
    let ws_users: Vec<Vec<Uuid>> = (0..WORKSPACES)
        .map(|_| (0..USERS_PER_WS).map(|_| Uuid::new_v4()).collect())
        .collect();
    // projects[p] = (project_id, workspace_index)
    let projects: Vec<(Uuid, usize)> = (0..WORKSPACES)
        .flat_map(|w| (0..PROJECTS_PER_WS).map(move |_| w))
        .map(|w| (Uuid::new_v4(), w))
        .collect();
    let proj_tags: Vec<Vec<Uuid>> = projects
        .iter()
        .map(|_| (0..TAGS_PER_PROJECT).map(|_| Uuid::new_v4()).collect())
        .collect();

    let now = Utc::now();

    // ---- users ----
    let mut buf = String::new();
    let mut uidx = 0;
    for users in &ws_users {
        for &uid in users {
            uidx += 1;
            let name = format!("User {uidx}");
            let initials = format!("U{}", uidx % 100);
            let created = (now - Duration::days(rng.gen_range(0..365))).to_rfc3339();
            buf.push_str(&format!(
                "{uid}\tuser{uidx}@stress.test\t{name}\t{initials}\t{created}\t\\N\t\\N\n"
            ));
        }
    }
    copy_in(&pool, "COPY users (id,email,name,initials,created_at,google_sub,avatar_url) FROM STDIN", buf).await?;
    println!("stress_seed: {} users", uidx);

    // ---- workspaces ----
    let mut buf = String::new();
    for (w, &wid) in ws_ids.iter().enumerate() {
        let owner = ws_users[w][0];
        let created = (now - Duration::days(365)).to_rfc3339();
        buf.push_str(&format!("{wid}\tWorkspace {}\tf\t{owner}\t{created}\n", w + 1));
    }
    copy_in(&pool, "COPY workspaces (id,title,is_personal,created_by,created_at) FROM STDIN", buf).await?;
    println!("stress_seed: {} workspaces", WORKSPACES);

    // ---- workspace_members (first user of each ws is owner) ----
    let mut buf = String::new();
    let mut wm_count = 0;
    for (w, users) in ws_users.iter().enumerate() {
        let wid = ws_ids[w];
        for (i, &uid) in users.iter().enumerate() {
            let role = if i == 0 { "owner" } else { "member" };
            buf.push_str(&format!("{wid}\t{uid}\t{role}\t\\N\n"));
            wm_count += 1;
        }
    }
    copy_in(&pool, "COPY workspace_members (workspace_id,user_id,role,removed_at) FROM STDIN", buf).await?;
    println!("stress_seed: {wm_count} workspace_members");

    // ---- projects ----
    let mut buf = String::new();
    for (p, &(pid, w)) in projects.iter().enumerate() {
        let wid = ws_ids[w];
        let owner = ws_users[w][0];
        let color = PROJECT_COLORS[p % PROJECT_COLORS.len()];
        let created = (now - Duration::days(300)).to_rfc3339();
        buf.push_str(&format!(
            "{pid}\tProject {}\t\t{color}\tlocal\t\\N\t{created}\t{owner}\t{wid}\t\\N\n",
            p + 1
        ));
    }
    copy_in(&pool, "COPY projects (id,title,icon,color,source,description,created_at,owner_id,workspace_id,external_url_template) FROM STDIN", buf).await?;
    println!("stress_seed: {} projects", projects.len());

    // ---- project_members (every user joins all 5 projects of their ws) ----
    let mut buf = String::new();
    let mut pm_count = 0;
    for (p, &(pid, w)) in projects.iter().enumerate() {
        let wid = ws_ids[w];
        for (i, &uid) in ws_users[w].iter().enumerate() {
            let role = if i == 0 { "owner" } else { "member" };
            buf.push_str(&format!("{pid}\t{uid}\t{wid}\t{role}\t\\N\n"));
            pm_count += 1;
        }
        if buf.len() > 8 * 1024 * 1024 {
            copy_in(&pool, "COPY project_members (project_id,user_id,workspace_id,role,removed_at) FROM STDIN", std::mem::take(&mut buf)).await?;
        }
        let _ = p;
    }
    copy_in(&pool, "COPY project_members (project_id,user_id,workspace_id,role,removed_at) FROM STDIN", buf).await?;
    println!("stress_seed: {pm_count} project_members");

    // ---- tags ----
    let mut buf = String::new();
    for (p, &(pid, _w)) in projects.iter().enumerate() {
        for (t, &tid) in proj_tags[p].iter().enumerate() {
            let color = TAG_COLORS[t % TAG_COLORS.len()];
            let created = now.to_rfc3339();
            buf.push_str(&format!("{tid}\t{pid}\ttag-{}-{}\t{color}\t{created}\n", p + 1, t + 1));
        }
    }
    copy_in(&pool, "COPY tags (id,project_id,title,color,created_at) FROM STDIN", buf).await?;
    println!("stress_seed: {} tags (epics/sprints skipped)", projects.len() * TAGS_PER_PROJECT);

    // ---- tasks (the big one: 1,000,000 rows, streamed via COPY) ----
    println!("stress_seed: seeding {} tasks...", projects.len() * TASKS_PER_PROJECT);
    let task_started = Instant::now();
    let mut conn = pool.acquire().await?;
    let mut copy = conn
        .copy_in_raw(
            "COPY tasks (id,project_id,epic_id,sprint_id,assignee_id,title,description_md,\
             section,status,priority,source,external_id,estimate_min,spent_min,sort_key,\
             created_at,updated_at,external_url,created_by,finished_at) FROM STDIN",
        )
        .await?;
    let mut buf = String::new();
    let mut rows_since_flush = 0usize;
    let mut total_tasks = 0usize;
    for &(pid, w) in projects.iter() {
        let users = &ws_users[w];
        for n in 0..TASKS_PER_PROJECT {
            let tid = Uuid::new_v4();
            let (prefix, desc, est_lo, est_hi) = TEMPLATES[rng.gen_range(0..TEMPLATES.len())];
            let assignee = users[rng.gen_range(0..users.len())];
            let creator = users[rng.gen_range(0..users.len())];

            // Weighted pick over SECTIONS: now/later/done/someday/recurring,
            // with `done` as the largest bucket.
            let roll: f64 = rng.gen();
            let section = SECTIONS[if roll < 0.15 {
                0
            } else if roll < 0.40 {
                1
            } else if roll < 0.80 {
                2
            } else if roll < 0.95 {
                3
            } else {
                4
            }];
            let status = match section {
                "done" => "done",
                "now" => ["todo", "in_progress"][rng.gen_range(0..2)],
                _ => ["backlog", "todo"][rng.gen_range(0..2)],
            };
            let finished_at = if status == "done" {
                (now - Duration::hours(rng.gen_range(1..4000))).to_rfc3339()
            } else {
                "\\N".to_string()
            };
            let priority = if rng.gen_bool(0.6) {
                PRIORITIES[rng.gen_range(0..4)]
            } else {
                "\\N"
            };
            let epic = "\\N";
            let sprint = "\\N";
            let estimate = if rng.gen_bool(0.7) {
                rng.gen_range(est_lo..=est_hi).to_string()
            } else {
                "\\N".to_string()
            };
            let spent = if status == "done" || status == "in_progress" {
                rng.gen_range(0..600).to_string()
            } else {
                "0".to_string()
            };
            let created = (now - Duration::hours(rng.gen_range(1..7000))).to_rfc3339();
            let sort_key = rand_sort_key(&mut rng);
            let title = esc(&format!("{prefix} #{}", n + 1));
            let desc = esc(desc);

            buf.push_str(&format!(
                "{tid}\t{pid}\t{epic}\t{sprint}\t{assignee}\t{title}\t{desc}\t{section}\t\
                 {status}\t{priority}\tlocal\t\\N\t{estimate}\t{spent}\t{sort_key}\t\
                 {created}\t{created}\t\\N\t{creator}\t{finished_at}\n"
            ));
            rows_since_flush += 1;
            total_tasks += 1;

            if rows_since_flush >= COPY_FLUSH_ROWS {
                copy.send(std::mem::take(&mut buf).into_bytes()).await?;
                rows_since_flush = 0;
                if total_tasks % 200_000 == 0 {
                    println!("stress_seed:   {total_tasks} tasks...");
                }
            }
        }
    }
    if !buf.is_empty() {
        copy.send(buf.into_bytes()).await?;
    }
    let inserted = copy.finish().await?;
    drop(conn);
    println!(
        "stress_seed: {inserted} tasks in {:.1}s",
        task_started.elapsed().as_secs_f64()
    );

    // ---- sessions for the load client (1000) ----
    let mut buf = String::new();
    let mut map = Vec::with_capacity(WORKSPACES * LOAD_USERS_PER_WS);
    let expires = (now + Duration::days(30)).to_rfc3339();
    for (w, users) in ws_users.iter().enumerate() {
        for &uid in users.iter().take(LOAD_USERS_PER_WS) {
            let token = rand_token(&mut rng);
            buf.push_str(&format!(
                "{token}\t{uid}\tloadtest\t{}\t{expires}\t\\N\n",
                now.to_rfc3339()
            ));
            map.push(serde_json::json!({
                "token": token,
                "user_id": uid.to_string(),
                "workspace_id": ws_ids[w].to_string(),
            }));
        }
    }
    copy_in(&pool, "COPY sessions (id,user_id,user_agent,created_at,expires_at,session_group_id) FROM STDIN", buf).await?;

    std::fs::create_dir_all("../loadtest").ok();
    std::fs::write(
        "../loadtest/loadtest-map.json",
        serde_json::to_string_pretty(&map)?,
    )?;
    println!(
        "stress_seed: {} sessions -> loadtest/loadtest-map.json",
        map.len()
    );

    println!(
        "stress_seed: DONE in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// COPY a fully-built text buffer into `stmt` in one shot.
async fn copy_in(pool: &PgPool, stmt: &str, data: String) -> anyhow::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut conn = pool.acquire().await?;
    let mut copy = conn.copy_in_raw(stmt).await?;
    copy.send(data.into_bytes()).await?;
    copy.finish().await?;
    Ok(())
}

/// Escape a field for COPY text format (tab/newline/backslash are delimiters).
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn rand_sort_key(rng: &mut StdRng) -> String {
    const CH: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    (0..6).map(|_| CH[rng.gen_range(0..CH.len())] as char).collect()
}

fn rand_token(rng: &mut StdRng) -> String {
    const CH: &[u8] = b"0123456789abcdef";
    (0..40).map(|_| CH[rng.gen_range(0..CH.len())] as char).collect()
}
