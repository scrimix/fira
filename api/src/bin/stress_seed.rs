// Stress-test bulk seeder. Populates a *separate* `fira_stress` database
// with a medium-sized synthetic dataset via Postgres COPY:
//
//   50 workspaces  x  3 projects    = 150 projects
//   2,000 users    (40 / workspace; each project has 10-15 members)
//   300,000 tasks  (2,000 / project; ~70% in the `done` section)
//   realistic per-project tags (UI / CORE / BUG / ...) linked to tasks
//   2,000 load-test sessions (user_agent='loadtest') + the Maya dev user
//
// The 20 "template tasks" are an in-code generator pool (TEMPLATES); every
// seeded task is a randomized clone of one of them.
//
// Run:
//   DATABASE_URL=postgres://fira:fira@postgres:5432/fira_stress \
//     cargo run --release --bin stress_seed
//   ... add `-- --maya` to (re)create just the Maya dev user, no reseed.
//
// stress_load discovers the load-test sessions straight from the DB — no
// map file, nothing to drift out of sync.

use chrono::{Duration, Utc};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Instant;
use uuid::Uuid;

const WORKSPACES: usize = 50;
const PROJECTS_PER_WS: usize = 3;
const USERS_PER_WS: usize = 40;
const PROJECT_MEMBERS_MIN: usize = 10;
const PROJECT_MEMBERS_MAX: usize = 15;
const TASKS_PER_PROJECT: usize = 2_000;
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
    ("Optimize bootstrap payload", "Workspace hydrate ships every task at once.", 90, 360),
    ("Add export to CSV", "Tasks list, respecting current filters.", 60, 180),
    ("Set up error tracking", "Wire Sentry into the API and web build.", 45, 120),
    ("Improve search relevance", "Title match should outrank description.", 90, 240),
    ("Schedule weekly 1:1", "Recurring - 30 min, calendar block.", 15, 30),
    ("Daily standup notes", "Recurring - capture blockers.", 10, 20),
];

/// Task sections, in weighted-bucket order (see the picker in the task loop).
const SECTIONS: [&str; 5] = ["now", "later", "done", "someday", "recurring"];
const PRIORITIES: [&str; 4] = ["p0", "p1", "p2", "p3"];

/// Realistic per-project tag vocabulary: (title, color). Every project gets
/// this full set, and each task is linked to a random 0-3 of them.
const TAG_VOCAB: [(&str, &str); 10] = [
    ("UI", "#3b82f6"),
    ("CORE", "#8b5cf6"),
    ("BUG", "#ef4444"),
    ("API", "#0891b2"),
    ("perf", "#f59e0b"),
    ("infra", "#64748b"),
    ("docs", "#10b981"),
    ("tech-debt", "#a16207"),
    ("v1", "#6366f1"),
    ("v2", "#14b8a6"),
];

const PROJECT_COLORS: [&str; 6] =
    ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2"];

/// Fixed ids for the "Maya" dev user — the stress-env equivalent of the
/// base-dev fixture user. Lets the login page's "Sign in as Maya" button
/// (dev-login by email) work against `fira_stress`. Fixed so reseeds and
/// the idempotent `--maya` mode always converge on the same rows.
const MAYA_ID: &str = "aaaaaaaa-1111-4aaa-8aaa-000000000001";
const MAYA_PERSONAL_WS: &str = "aaaaaaaa-1111-4aaa-8aaa-000000000002";
const MAYA_EMAIL: &str = "maya@fira.dev";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let url: String = "postgres://fira:fira@postgres:5432/fira_stress".into();
    // Safety rail: never let this run against the dev fixture database.
    if !url.contains("fira_stress") {
        anyhow::bail!("DATABASE_URL must point at the `fira_stress` database, got: {url}");
    }
    let started = Instant::now();
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await?;

    // `--maya`: just (re)create the Maya dev user against an already-seeded
    // DB, without a full reseed. Idempotent.
    if std::env::args().any(|a| a == "--maya") {
        ensure_maya(&pool).await?;
        println!("stress_seed: Maya dev user ensured ({MAYA_EMAIL}) — use 'Sign in as Maya'");
        return Ok(());
    }

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
    // ws_users[w] = the 40 user ids belonging to workspace w.
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
        .map(|_| (0..TAG_VOCAB.len()).map(|_| Uuid::new_v4()).collect())
        .collect();
    // proj_members[p] = the 10-15 users who belong to project p. Built by
    // round-robin (so every user lands in a project) then topped up to a
    // random per-project size.
    let proj_members: Vec<Vec<Uuid>> = {
        let mut all = Vec::with_capacity(projects.len());
        for users in &ws_users {
            let mut shuffled = users.clone();
            shuffled.shuffle(&mut rng);
            let mut pm: Vec<Vec<Uuid>> = vec![Vec::new(); PROJECTS_PER_WS];
            for (i, &u) in shuffled.iter().enumerate() {
                pm[i % PROJECTS_PER_WS].push(u);
            }
            for members in &mut pm {
                let target = rng.gen_range(PROJECT_MEMBERS_MIN..=PROJECT_MEMBERS_MAX);
                while members.len() < target {
                    let cand = users[rng.gen_range(0..users.len())];
                    if !members.contains(&cand) {
                        members.push(cand);
                    }
                }
            }
            all.extend(pm);
        }
        all
    };

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
    println!("stress_seed: {uidx} users");

    // ---- workspaces ----
    let mut buf = String::new();
    for (w, &wid) in ws_ids.iter().enumerate() {
        let owner = ws_users[w][0];
        let created = (now - Duration::days(365)).to_rfc3339();
        buf.push_str(&format!("{wid}\tWorkspace {}\tf\t{owner}\t{created}\n", w + 1));
    }
    copy_in(&pool, "COPY workspaces (id,title,is_personal,created_by,created_at) FROM STDIN", buf).await?;
    println!("stress_seed: {WORKSPACES} workspaces");

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

    // ---- project_members (10-15 per project) ----
    let mut buf = String::new();
    let mut pm_count = 0;
    for (p, &(pid, w)) in projects.iter().enumerate() {
        let wid = ws_ids[w];
        for &uid in &proj_members[p] {
            buf.push_str(&format!("{pid}\t{uid}\t{wid}\tmember\t\\N\n"));
            pm_count += 1;
        }
    }
    copy_in(&pool, "COPY project_members (project_id,user_id,workspace_id,role,removed_at) FROM STDIN", buf).await?;
    println!("stress_seed: {pm_count} project_members");

    // ---- tags (the realistic UI/CORE/BUG/... vocabulary, per project) ----
    let mut buf = String::new();
    for (p, &(pid, _w)) in projects.iter().enumerate() {
        for (t, &tid) in proj_tags[p].iter().enumerate() {
            let (title, color) = TAG_VOCAB[t];
            buf.push_str(&format!("{tid}\t{pid}\t{title}\t{color}\t{}\n", now.to_rfc3339()));
        }
    }
    copy_in(&pool, "COPY tags (id,project_id,title,color,created_at) FROM STDIN", buf).await?;
    println!("stress_seed: {} tags", projects.len() * TAG_VOCAB.len());

    // ---- tasks (300k rows, streamed via COPY) + task<->tag links ----
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
    let mut tag_links = String::new();
    let mut rows_since_flush = 0usize;
    let mut total_tasks = 0usize;
    let mut total_links = 0usize;
    for (p, &(pid, _w)) in projects.iter().enumerate() {
        let members = &proj_members[p];
        for n in 0..TASKS_PER_PROJECT {
            let tid = Uuid::new_v4();
            let (prefix, desc, est_lo, est_hi) = TEMPLATES[rng.gen_range(0..TEMPLATES.len())];
            let assignee = members[rng.gen_range(0..members.len())];
            let creator = members[rng.gen_range(0..members.len())];

            // Weighted pick over SECTIONS: `done` is ~70% — most tasks are
            // finished, as in a mature workspace.
            let roll: f64 = rng.gen();
            let section = SECTIONS[if roll < 0.10 {
                0 // now
            } else if roll < 0.22 {
                1 // later
            } else if roll < 0.92 {
                2 // done
            } else if roll < 0.97 {
                3 // someday
            } else {
                4 // recurring
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
                "{tid}\t{pid}\t\\N\t\\N\t{assignee}\t{title}\t{desc}\t{section}\t\
                 {status}\t{priority}\tlocal\t\\N\t{estimate}\t{spent}\t{sort_key}\t\
                 {created}\t{created}\t\\N\t{creator}\t{finished_at}\n"
            ));

            // Link the task to a random 0-3 of its project's tags.
            let k = rng.gen_range(0..=3);
            for &tag in proj_tags[p].choose_multiple(&mut rng, k) {
                tag_links.push_str(&format!("{tid}\t{tag}\n"));
                total_links += 1;
            }

            rows_since_flush += 1;
            total_tasks += 1;
            if rows_since_flush >= COPY_FLUSH_ROWS {
                copy.send(std::mem::take(&mut buf).into_bytes()).await?;
                rows_since_flush = 0;
                if total_tasks % 100_000 == 0 {
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

    // task_tags must wait until the tasks COPY has committed (FK).
    copy_in(&pool, "COPY task_tags (task_id,tag_id) FROM STDIN", tag_links).await?;
    println!("stress_seed: {total_links} task-tag links");

    // ---- load-test sessions (one per user, tagged user_agent='loadtest') ----
    // stress_load discovers exactly these by querying the DB — there is no
    // map file to drift out of sync with the seeded rows.
    let mut buf = String::new();
    let mut session_count = 0;
    let expires = (now + Duration::days(30)).to_rfc3339();
    for users in &ws_users {
        for &uid in users {
            let token = rand_token(&mut rng);
            buf.push_str(&format!(
                "{token}\t{uid}\tloadtest\t{}\t{expires}\t\\N\n",
                now.to_rfc3339()
            ));
            session_count += 1;
        }
    }
    copy_in(&pool, "COPY sessions (id,user_id,user_agent,created_at,expires_at,session_group_id) FROM STDIN", buf).await?;
    println!("stress_seed: {session_count} load-test sessions (user_agent='loadtest')");

    // ---- Maya dev user (browse the stress env without Google auth) ----
    ensure_maya(&pool).await?;
    println!("stress_seed: Maya dev user ensured ({MAYA_EMAIL})");

    println!("stress_seed: DONE in {:.1}s", started.elapsed().as_secs_f64());
    Ok(())
}

/// Idempotently create the "Maya" dev user: a real account that owns her
/// personal workspace plus the first two shared workspaces (so she can
/// browse a couple of medium workspaces without the localStorage quota
/// blowing up). Safe to re-run.
async fn ensure_maya(pool: &PgPool) -> anyhow::Result<()> {
    let maya: Uuid = MAYA_ID.parse()?;
    let personal_ws: Uuid = MAYA_PERSONAL_WS.parse()?;

    sqlx::query(
        "INSERT INTO users (id, email, name, initials)
         VALUES ($1, $2, 'Maya Chen', 'MC')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(maya)
    .bind(MAYA_EMAIL)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO workspaces (id, title, is_personal, created_by)
         VALUES ($1, 'Maya', true, $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(personal_ws)
    .bind(maya)
    .execute(pool)
    .await?;

    // Owner of her personal workspace + the first two shared workspaces.
    // The workspace-owner role is a project-access wildcard, so this alone
    // gives her every project in those workspaces.
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, role)
         SELECT id, $1, 'owner' FROM workspaces
         WHERE id = $2 OR title IN ('Workspace 1', 'Workspace 2')
         ON CONFLICT (workspace_id, user_id)
         DO UPDATE SET role = 'owner', removed_at = NULL",
    )
    .bind(maya)
    .bind(personal_ws)
    .execute(pool)
    .await?;
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
