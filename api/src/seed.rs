// Seed data for the dev fixture project. Shared between the `seed` CLI
// binary and the dev-only HTTP endpoint that re-seeds on demand.
//
// IDs are deterministic UUID-v5 derived from slug strings ("u_maya",
// "t_atlas_oauth", ...) so reseeding produces stable IDs across runs.
//
// Time blocks are stored as real timestamps anchored to Monday 00:00 UTC of
// the *current* week. Block states are recomputed against the wall clock at
// seed time so the demo always shows a believable "morning done, rest
// planned" snapshot regardless of which day of the week the seeder runs on.

use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const NS: Uuid = Uuid::from_bytes([
    0x6f, 0x9b, 0x4e, 0xa1, 0x12, 0x3d, 0x4a, 0x8e, 0xb1, 0x77, 0xc2, 0x91, 0x05, 0xe6, 0xfa, 0x42,
]);

/// Slug of the primary fixture user — owns every project and is the
/// assignee/calendar-owner used for non-task tables.
pub const PRIMARY_USER_SLUG: &str = "u_maya";
pub const PRIMARY_USER_EMAIL: &str = "maya@fira.dev";

pub fn id(slug: &str) -> Uuid {
    Uuid::new_v5(&NS, slug.as_bytes())
}

pub fn primary_user_id() -> Uuid {
    id(PRIMARY_USER_SLUG)
}

fn week_anchor() -> DateTime<Utc> {
    // Monday 00:00 UTC of the current week.
    let today = Utc::now().date_naive();
    let monday = today - Duration::days(today.weekday().num_days_from_monday() as i64);
    Utc.from_utc_datetime(&monday.and_hms_opt(0, 0, 0).unwrap())
}

fn ts(day: i64, start_min: i64) -> DateTime<Utc> {
    week_anchor() + Duration::days(day) + Duration::minutes(start_min)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn fmt_md(d: NaiveDate) -> String {
    format!("{} {}", MONTHS[d.month0() as usize], d.day())
}

fn sprint_dates(start_offset: i64, end_offset: i64) -> String {
    let anchor = week_anchor().date_naive();
    let start = anchor + Duration::days(start_offset);
    let end = anchor + Duration::days(end_offset);
    format!("{} – {}", fmt_md(start), fmt_md(end))
}

/// Wipe the per-tenant fixture tables. Leaves auth-only tables (`sessions`,
/// `processed_ops`) alone so the calling user's session survives a reseed.
pub async fn wipe(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    // Truncate the change-log too: replaying ops that target IDs we just
    // deleted would fail or resurrect stale state on other clients.
    for table in [
        "processed_ops",
        "gcal_events",
        "time_blocks",
        "subtasks",
        "tasks",
        "sprints",
        "epics",
        "project_members",
        "projects",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut **tx)
            .await?;
    }
    // Only delete the fixture users (those with a `dev-*` google_sub
    // placeholder). Real Google-authenticated users keep their row, and
    // their sessions (which we left untouched above) keep working.
    sqlx::query("DELETE FROM users WHERE google_sub LIKE 'dev-%'")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Insert all fixture data. Caller is responsible for opening/committing
/// the transaction and for any preceding wipe.
pub async fn seed_all(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    // ---- Users ----
    // google_sub is filled with a stable `dev-*` placeholder so a real Google
    // login doesn't collide with these fixture users (real subs are numeric
    // strings; the index treats nulls as distinct).
    for (slug, name, initials, email) in [
        (PRIMARY_USER_SLUG, "Maya Chen", "MC", PRIMARY_USER_EMAIL),
        ("u_anna", "Anna Park", "AP", "anna@fira.dev"),
        ("u_bob", "Bob Reyes", "BR", "bob@fira.dev"),
        ("u_jin", "Jin Okafor", "JO", "jin@fira.dev"),
    ] {
        sqlx::query(
            "INSERT INTO users (id, email, name, initials, google_sub) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id(slug))
        .bind(email)
        .bind(name)
        .bind(initials)
        .bind(format!("dev-{slug}"))
        .execute(&mut **tx)
        .await?;
    }

    // ---- Projects ----
    let projects = [
        ("p_atlas", "Atlas", "◆", "#0F766E", "jira", "Core platform. Auth, billing, infra."),
        ("p_relay", "Relay", "▲", "#B45309", "notion", "Internal tooling — sync engine."),
        ("p_helix", "Helix", "◇", "#6D28D9", "local", "Personal R&D — embedding experiments."),
    ];
    for (slug, title, icon, color, source, desc) in projects {
        sqlx::query(
            "INSERT INTO projects (id, title, icon, color, source, description, owner_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id(slug))
        .bind(title)
        .bind(icon)
        .bind(color)
        .bind(source)
        .bind(desc)
        .bind(primary_user_id())
        .execute(&mut **tx)
        .await?;
    }

    // ---- Project members ----
    let members: &[(&str, &[&str])] = &[
        ("p_atlas", &["u_maya", "u_anna", "u_bob"]),
        ("p_relay", &["u_maya", "u_jin"]),
        ("p_helix", &["u_maya"]),
    ];
    for (proj, users) in members {
        for u in *users {
            sqlx::query(
                "INSERT INTO project_members (project_id, user_id) VALUES ($1,$2)",
            )
            .bind(id(proj))
            .bind(id(u))
            .execute(&mut **tx)
            .await?;
        }
    }

    // ---- Epics ----
    let epics = [
        ("e_auth_v2", "p_atlas", "Auth v2 (refresh + SSO)"),
        ("e_billing", "p_atlas", "Billing reliability"),
        ("e_perf", "p_atlas", "Perf + observability"),
        ("e_sync_engine", "p_relay", "Sync engine v1"),
        ("e_onboarding", "p_relay", "Source onboarding"),
        ("e_search", "p_helix", "Semantic task search"),
        ("e_explore", "p_helix", "Misc exploration"),
    ];
    for (slug, proj, title) in epics {
        sqlx::query(
            "INSERT INTO epics (id, project_id, title) VALUES ($1,$2,$3)",
        )
        .bind(id(slug))
        .bind(id(proj))
        .bind(title)
        .execute(&mut **tx)
        .await?;
    }

    // ---- Sprints ----
    // Dates are computed relative to this week's Monday so the active sprint
    // always brackets "today". Offsets in days from week_anchor.
    let anchor_date = week_anchor().date_naive();
    let q_start = anchor_date;
    let q_end = anchor_date + Duration::days(60);
    let sprints = [
        ("s_apr27", "p_atlas",
         format!("Atlas · {}", fmt_md(anchor_date)),
         sprint_dates(0, 11), true),
        ("s_may11", "p_atlas",
         format!("Atlas · {}", fmt_md(anchor_date + Duration::days(14))),
         sprint_dates(14, 25), false),
        ("s_relay9", "p_relay",
         "Relay · Sprint 9".to_string(),
         sprint_dates(-5, 8), true),
        ("s_relay10", "p_relay",
         "Relay · Sprint 10".to_string(),
         sprint_dates(9, 22), false),
        ("s_helix_q2", "p_helix",
         "Helix · Q2".to_string(),
         format!("{} – {}", MONTHS[q_start.month0() as usize], MONTHS[q_end.month0() as usize]),
         true),
    ];
    for (slug, proj, title, dates, active) in &sprints {
        let (slug, proj, title, dates, active) = (*slug, *proj, title.as_str(), dates.as_str(), *active);
        sqlx::query(
            "INSERT INTO sprints (id, project_id, title, dates, active)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id(slug))
        .bind(id(proj))
        .bind(title)
        .bind(dates)
        .bind(active)
        .execute(&mut **tx)
        .await?;
    }

    // ---- Tasks ----
    seed_tasks(tx).await?;

    // ---- Time blocks ----
    seed_blocks(tx).await?;

    // ---- GCal events ----
    let gcals = [
        (0, 11 * 60 + 30, 30, "1:1 with Anna"),
        (1, 13 * 60, 60, "Atlas standup"),
        (2, 10 * 60 + 30, 30, "Standup"),
        (2, 14 * 60 + 30, 30, "Design review"),
        (3, 13 * 60, 60, "Atlas standup"),
        (4, 11 * 60 + 30, 30, "Demo prep"),
    ];
    for (i, (day, start_min, dur, title)) in gcals.iter().enumerate() {
        sqlx::query(
            "INSERT INTO gcal_events (id, user_id, title, start_at, end_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id(&format!("gcal_{i}")))
        .bind(primary_user_id())
        .bind(*title)
        .bind(ts(*day as i64, *start_min as i64))
        .bind(ts(*day as i64, (*start_min + *dur) as i64))
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

struct TaskSpec {
    slug: &'static str,
    project: &'static str,
    epic: Option<&'static str>,
    sprint: Option<&'static str>,
    assignee: &'static str,
    title: &'static str,
    description: &'static str,
    section: &'static str,
    status: &'static str,
    priority: Option<&'static str>,
    source: &'static str,
    external_id: Option<&'static str>,
    estimate_min: Option<i32>,
    spent_min: i32,
    tags: &'static [&'static str],
    subtasks: &'static [(&'static str, bool)], // (title, done)
}

async fn seed_tasks(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    let tasks: &[TaskSpec] = &[
        // ---- ATLAS Now ----
        TaskSpec {
            slug: "t_atlas_oauth", project: "p_atlas", epic: Some("e_auth_v2"), sprint: Some("s_apr27"),
            assignee: "u_maya", title: "OAuth refresh token rotation",
            description: "Rotate refresh tokens on every use. Invalidate the old token within a 30-second grace window.\n\nFollow RFC 6749 §10.4 + §6 recommendations.",
            section: "now", status: "in_progress", priority: Some("p1"),
            source: "jira", external_id: Some("ATL-412"),
            estimate_min: Some(360), spent_min: 120, tags: &["auth", "security"],
            subtasks: &[
                ("Audit current refresh logic", true),
                ("Add rotation endpoint", true),
                ("Migrate existing tokens", false),
                ("Backfill metrics dashboard", false),
            ],
        },
        TaskSpec {
            slug: "t_atlas_billing", project: "p_atlas", epic: Some("e_billing"), sprint: Some("s_apr27"),
            assignee: "u_maya", title: "Stripe webhook idempotency",
            description: "Webhook delivery is at-least-once. Dedup by event id, store last 30 days.",
            section: "now", status: "in_progress", priority: Some("p1"),
            source: "jira", external_id: Some("ATL-433"),
            estimate_min: Some(240), spent_min: 60, tags: &["billing"],
            subtasks: &[
                ("Create dedup table", true),
                ("Wrap webhook handlers", false),
                ("Add metrics", false),
            ],
        },
        TaskSpec {
            slug: "t_atlas_review", project: "p_atlas", epic: Some("e_perf"), sprint: Some("s_apr27"),
            assignee: "u_maya", title: "Code review: rate-limit middleware",
            description: "Bob's PR. Token bucket per IP + per user. Check the redis fallback.",
            section: "now", status: "todo", priority: Some("p2"),
            source: "jira", external_id: Some("ATL-440"),
            estimate_min: Some(60), spent_min: 0, tags: &["review"],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_atlas_sso", project: "p_atlas", epic: Some("e_auth_v2"), sprint: Some("s_may11"),
            assignee: "u_anna", title: "SAML SSO for enterprise tier",
            description: "",
            section: "now", status: "todo", priority: Some("p1"),
            source: "jira", external_id: Some("ATL-451"),
            estimate_min: Some(480), spent_min: 0, tags: &["auth", "enterprise"],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_atlas_logs", project: "p_atlas", epic: Some("e_perf"), sprint: Some("s_may11"),
            assignee: "u_anna", title: "Audit log retention policy",
            description: "",
            section: "now", status: "todo", priority: Some("p2"),
            source: "jira", external_id: Some("ATL-446"),
            estimate_min: Some(180), spent_min: 0, tags: &["compliance"],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_atlas_perf", project: "p_atlas", epic: Some("e_perf"), sprint: Some("s_apr27"),
            assignee: "u_bob", title: "Investigate p99 spike on /sessions",
            description: "p99 went from 80ms → 320ms after the auth refactor merge. Bisect commits.",
            section: "now", status: "in_progress", priority: Some("p0"),
            source: "jira", external_id: Some("ATL-449"),
            estimate_min: Some(240), spent_min: 60, tags: &["perf"],
            subtasks: &[],
        },
        // ---- RELAY Now ----
        TaskSpec {
            slug: "t_relay_jira", project: "p_relay", epic: Some("e_sync_engine"), sprint: Some("s_relay9"),
            assignee: "u_maya", title: "Jira webhook → task upsert",
            description: "Receive Jira webhook, debounce 500ms, upsert task by external_id.",
            section: "now", status: "in_progress", priority: Some("p1"),
            source: "notion", external_id: Some("sync-engine/47"),
            estimate_min: Some(300), spent_min: 90, tags: &["sync"],
            subtasks: &[
                ("Webhook signature verification", true),
                ("Debounce queue", false),
                ("Conflict detection (source_updated_at > last_synced_at)", false),
            ],
        },
        TaskSpec {
            slug: "t_relay_diff", project: "p_relay", epic: Some("e_sync_engine"), sprint: Some("s_relay9"),
            assignee: "u_maya", title: "Diff viewer for diverged tasks",
            description: "When a task is diverged, show side-by-side diff so user picks a side.",
            section: "now", status: "todo", priority: Some("p2"),
            source: "notion", external_id: Some("sync-engine/52"),
            estimate_min: Some(240), spent_min: 0, tags: &["ui"],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_relay_notion", project: "p_relay", epic: Some("e_onboarding"), sprint: Some("s_relay10"),
            assignee: "u_jin", title: "Notion column-mapping flow",
            description: "",
            section: "now", status: "todo", priority: Some("p1"),
            source: "notion", external_id: Some("sync-engine/55"),
            estimate_min: Some(360), spent_min: 0, tags: &["onboarding"],
            subtasks: &[],
        },
        // ---- HELIX Now ----
        TaskSpec {
            slug: "t_helix_emb", project: "p_helix", epic: Some("e_search"), sprint: Some("s_helix_q2"),
            assignee: "u_maya", title: "Sentence embeddings for task search",
            description: "Try bge-small + qdrant, measure recall@10 on held-out set.",
            section: "now", status: "in_progress", priority: Some("p2"),
            source: "local", external_id: None,
            estimate_min: Some(240), spent_min: 30, tags: &["research"],
            subtasks: &[
                ("Spin up qdrant locally", true),
                ("Index 1k sample tasks", false),
                ("Build held-out eval", false),
            ],
        },
        TaskSpec {
            slug: "t_helix_idea", project: "p_helix", epic: Some("e_explore"), sprint: Some("s_helix_q2"),
            assignee: "u_maya", title: "Sketch: estimate-confidence band on tasks",
            description: "",
            section: "now", status: "todo", priority: Some("p3"),
            source: "local", external_id: None,
            estimate_min: Some(60), spent_min: 0, tags: &["design"],
            subtasks: &[],
        },
        // ---- LATER ----
        TaskSpec {
            slug: "t_atlas_later1", project: "p_atlas", epic: Some("e_auth_v2"), sprint: None,
            assignee: "u_maya", title: "Magic-link auth fallback",
            description: "",
            section: "later", status: "backlog", priority: Some("p2"),
            source: "jira", external_id: Some("ATL-501"),
            estimate_min: None, spent_min: 0, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_atlas_later2", project: "p_atlas", epic: Some("e_auth_v2"), sprint: None,
            assignee: "u_maya", title: "Admin UI: revoke session",
            description: "",
            section: "later", status: "backlog", priority: Some("p3"),
            source: "jira", external_id: Some("ATL-510"),
            estimate_min: Some(180), spent_min: 0, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_atlas_later3", project: "p_atlas", epic: Some("e_auth_v2"), sprint: None,
            assignee: "u_maya", title: "Investigate FIDO2 / passkeys",
            description: "",
            section: "later", status: "backlog", priority: Some("p3"),
            source: "jira", external_id: Some("ATL-515"),
            estimate_min: None, spent_min: 0, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_relay_later1", project: "p_relay", epic: Some("e_onboarding"), sprint: None,
            assignee: "u_maya", title: "GitHub Issues source adapter",
            description: "",
            section: "later", status: "backlog", priority: Some("p3"),
            source: "notion", external_id: Some("sync-engine/61"),
            estimate_min: None, spent_min: 0, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_relay_later2", project: "p_relay", epic: Some("e_sync_engine"), sprint: None,
            assignee: "u_maya", title: "Bug: Notion poll skips archived pages",
            description: "Spotted in standup 2026-04-28. Repro: archive a page, watch poll cycle.",
            section: "later", status: "backlog", priority: Some("p2"),
            source: "local", external_id: None,
            estimate_min: Some(60), spent_min: 0, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_helix_later1", project: "p_helix", epic: Some("e_explore"), sprint: None,
            assignee: "u_maya", title: "Read: \"Notion Calendar postmortem\" blog",
            description: "",
            section: "later", status: "backlog", priority: Some("p3"),
            source: "local", external_id: None,
            estimate_min: Some(30), spent_min: 0, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_helix_later2", project: "p_helix", epic: Some("e_explore"), sprint: None,
            assignee: "u_maya", title: "Try DuckDB for snapshot replay queries",
            description: "",
            section: "later", status: "backlog", priority: Some("p3"),
            source: "local", external_id: None,
            estimate_min: None, spent_min: 0, tags: &[],
            subtasks: &[],
        },
        // ---- DONE ----
        TaskSpec {
            slug: "t_atlas_done1", project: "p_atlas", epic: Some("e_auth_v2"), sprint: Some("s_apr27"),
            assignee: "u_maya", title: "Migrate session store to Redis 7",
            description: "",
            section: "done", status: "done", priority: None,
            source: "jira", external_id: Some("ATL-401"),
            estimate_min: Some(240), spent_min: 280, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_relay_done1", project: "p_relay", epic: Some("e_sync_engine"), sprint: Some("s_relay9"),
            assignee: "u_maya", title: "Initial Jira OAuth flow",
            description: "",
            section: "done", status: "done", priority: None,
            source: "notion", external_id: Some("sync-engine/40"),
            estimate_min: Some(360), spent_min: 420, tags: &[],
            subtasks: &[],
        },
        TaskSpec {
            slug: "t_helix_done1", project: "p_helix", epic: Some("e_search"), sprint: Some("s_helix_q2"),
            assignee: "u_maya", title: "Spike: pgvector vs qdrant benchmark",
            description: "",
            section: "done", status: "done", priority: None,
            source: "local", external_id: None,
            estimate_min: Some(180), spent_min: 240, tags: &[],
            subtasks: &[],
        },
    ];

    for t in tasks {
        sqlx::query(
            "INSERT INTO tasks (id, project_id, epic_id, sprint_id, assignee_id,
                title, description_md, section, status, priority,
                source, external_id, estimate_min, spent_min, tags)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(id(t.slug))
        .bind(id(t.project))
        .bind(t.epic.map(id))
        .bind(t.sprint.map(id))
        .bind(id(t.assignee))
        .bind(t.title)
        .bind(t.description)
        .bind(t.section)
        .bind(t.status)
        .bind(t.priority)
        .bind(t.source)
        .bind(t.external_id)
        .bind(t.estimate_min)
        .bind(t.spent_min)
        .bind(t.tags)
        .execute(&mut **tx)
        .await?;

        for (i, (title, done)) in t.subtasks.iter().enumerate() {
            sqlx::query(
                "INSERT INTO subtasks (id, task_id, title, done, sort_key)
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(id(&format!("{}_s{}", t.slug, i)))
            .bind(id(t.slug))
            .bind(*title)
            .bind(*done)
            .bind(format!("M{:03}", i))
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn seed_blocks(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    // (day, start_min, dur_min, task_slug). State is derived from the wall
    // clock at seed time: anything that has already ended is "completed",
    // anything still in the future is "planned". This way the demo always
    // shows a believable mix no matter which day the seeder runs on.
    let blocks: &[(i64, i64, i64, &str)] = &[
        // MON
        (0, 9 * 60, 90, "t_atlas_oauth"),
        (0, 10 * 60 + 30, 60, "t_atlas_review"),
        (0, 13 * 60, 120, "t_atlas_billing"),
        (0, 15 * 60 + 30, 90, "t_relay_jira"),
        // TUE
        (1, 9 * 60, 120, "t_atlas_oauth"),
        (1, 11 * 60 + 30, 90, "t_helix_emb"),
        (1, 14 * 60, 90, "t_relay_jira"),
        (1, 16 * 60, 60, "t_atlas_review"),
        // WED
        (2, 9 * 60, 90, "t_atlas_oauth"),
        (2, 11 * 60, 60, "t_atlas_billing"),
        (2, 13 * 60, 90, "t_relay_jira"),
        (2, 15 * 60, 60, "t_atlas_review"),
        (2, 16 * 60 + 30, 90, "t_helix_emb"),
        // THU
        (3, 9 * 60, 120, "t_atlas_oauth"),
        (3, 11 * 60 + 30, 60, "t_atlas_billing"),
        (3, 13 * 60, 90, "t_relay_jira"),
        (3, 15 * 60, 120, "t_relay_diff"),
        // FRI
        (4, 9 * 60, 90, "t_atlas_billing"),
        (4, 10 * 60 + 30, 60, "t_atlas_oauth"),
        (4, 13 * 60, 120, "t_helix_emb"),
        (4, 15 * 60 + 30, 90, "t_relay_jira"),
        // SAT
        (5, 10 * 60, 90, "t_helix_emb"),
    ];
    let now = Utc::now();
    for (i, (day, start_min, dur, slug)) in blocks.iter().enumerate() {
        let start_at = ts(*day, *start_min);
        let end_at = ts(*day, *start_min + *dur);
        let state = if end_at <= now { "completed" } else { "planned" };
        sqlx::query(
            "INSERT INTO time_blocks (id, task_id, user_id, start_at, end_at, state)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(id(&format!("b_{i}")))
        .bind(id(slug))
        .bind(primary_user_id())
        .bind(start_at)
        .bind(end_at)
        .bind(state)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
