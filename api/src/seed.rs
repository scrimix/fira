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

use anyhow::Context;
use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::ops::{
    BlockInput, GoalInput, Op, SprintInput, SubtaskInput, TagInput, TaskInput, TrackInput,
};
use crate::storage::{LocalStorage, StorageBackend};

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
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn fmt_md(d: NaiveDate) -> String {
    format!("{} {}", MONTHS[d.month0() as usize], d.day())
}

/// Wipe the per-tenant fixture tables. Leaves auth-only tables (`sessions`,
/// `processed_ops`) alone so the calling user's session survives a reseed.
pub async fn wipe(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    // Truncate the change-log too: replaying ops that target IDs we just
    // deleted would fail or resurrect stale state on other clients.
    for table in [
        "processed_ops",
        "gcal_events",
        // Before tags/tasks/projects: goals hold FKs into all three, and
        // an ON DELETE CASCADE would silently take goals with them.
        "goals",
        "time_blocks",
        "task_tags",
        "tags",
        "subtasks",
        "tasks",
        "sprints",
        "tracks",
        "project_members",
        "projects",
        "workspace_members",
        "workspaces",
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

/// Slug of the shared fixture workspace. Maya is `owner`, others are members
/// or leads — see seed_all.
pub const TEAM_WORKSPACE_SLUG: &str = "w_team";

/// Insert all fixture data. Caller is responsible for opening/committing
/// the transaction and for any preceding wipe.
pub async fn seed_all(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
    // ---- Users ----
    // google_sub is filled with a stable `dev-*` placeholder so a real Google
    // login doesn't collide with these fixture users (real subs are numeric
    // strings; the index treats nulls as distinct).
    let users: &[(&str, &str, &str, &str)] = &[
        (PRIMARY_USER_SLUG, "Maya Chen", "MC", PRIMARY_USER_EMAIL),
        ("u_anna", "Anna Park", "AP", "anna@fira.dev"),
        ("u_bob", "Bob Reyes", "BR", "bob@fira.dev"),
        ("u_jin", "Jin Okafor", "JO", "jin@fira.dev"),
    ];
    for (slug, name, initials, email) in users {
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

    // ---- Workspaces ----
    // One shared "Default" workspace for the team-style projects, plus a
    // personal workspace per user (empty by default — gives the dogfood
    // case somewhere to put solo tasks).
    sqlx::query(
        "INSERT INTO workspaces (id, title, is_personal, created_by)
         VALUES ($1, 'Default', false, $2)",
    )
    .bind(id(TEAM_WORKSPACE_SLUG))
    .bind(primary_user_id())
    .execute(&mut **tx)
    .await?;

    // Team workspace membership: Maya owns it; everyone else is a workspace
    // member. Per-project authority gets granted via the project_members.role
    // column further down.
    let team_roles: &[(&str, &str)] = &[
        (PRIMARY_USER_SLUG, "owner"),
        ("u_anna", "member"),
        ("u_bob", "member"),
        ("u_jin", "member"),
    ];
    for (slug, role) in team_roles {
        sqlx::query(
            "INSERT INTO workspace_members (workspace_id, user_id, role)
             VALUES ($1, $2, $3)",
        )
        .bind(id(TEAM_WORKSPACE_SLUG))
        .bind(id(slug))
        .bind(*role)
        .execute(&mut **tx)
        .await?;
    }

    for (slug, name, _initials, _email) in users {
        let ws_slug = format!("w_personal_{slug}");
        let first_name = name.split_whitespace().next().unwrap_or(name);
        sqlx::query(
            "INSERT INTO workspaces (id, title, is_personal, created_by)
             VALUES ($1, $2, true, $3)",
        )
        .bind(id(&ws_slug))
        .bind(format!("{first_name}'s workspace"))
        .bind(id(slug))
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "INSERT INTO workspace_members (workspace_id, user_id, role)
             VALUES ($1, $2, 'owner')",
        )
        .bind(id(&ws_slug))
        .bind(id(slug))
        .execute(&mut **tx)
        .await?;
    }

    // ---- Projects ----
    // Icon names match `PROJECT_ICONS` in web/src/components/ProjectIcon.tsx
    // so the seed appears in the same icon set the picker offers — not as
    // unicode-glyph fallbacks that can't be re-selected.
    let projects = [
        (
            "p_atlas",
            "Atlas",
            "Compass",
            "#0F766E",
            "jira",
            "Core platform. Auth, billing, infra.",
        ),
        (
            "p_relay",
            "Relay",
            "Zap",
            "#B45309",
            "notion",
            "Internal tooling — sync engine.",
        ),
        (
            "p_helix",
            "Helix",
            "Sparkles",
            "#6D28D9",
            "local",
            "Personal R&D — embedding experiments.",
        ),
    ];
    for (slug, title, icon, color, source, desc) in projects {
        sqlx::query(
            "INSERT INTO projects (id, workspace_id, title, icon, color, source, description, owner_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id(slug))
        .bind(id(TEAM_WORKSPACE_SLUG))
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
    // Each row carries a role: 'lead' or 'member'. The project's owner_id is
    // implicitly added as 'lead' by create_project_tx, but we're inserting
    // raw rows here, so spell out the role for everyone including Maya.
    let members: &[(&str, &[(&str, &str)])] = &[
        (
            "p_atlas",
            &[("u_maya", "lead"), ("u_anna", "lead"), ("u_bob", "member")],
        ),
        ("p_relay", &[("u_maya", "lead"), ("u_jin", "member")]),
        ("p_helix", &[("u_maya", "lead")]),
    ];
    for (proj, rows) in members {
        for (u, role) in *rows {
            sqlx::query(
                "INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,$3)",
            )
            .bind(id(proj))
            .bind(id(u))
            .bind(*role)
            .execute(&mut **tx)
            .await?;
        }
    }

    // ---- Content, as a backdated op log ----
    // Everything below tenancy goes through the real op handlers rather
    // than direct INSERTs, so the fixture's end state is by construction
    // what its history produces. See `Fixture`.
    let mut f = Fixture::new();
    fixture_tracks(&mut f);
    fixture_sprints(&mut f);
    fixture_tags(&mut f);
    fixture_tasks(&mut f);
    fixture_plan_history(&mut f);
    fixture_blocks(&mut f);
    fixture_goals(&mut f);
    f.apply(tx).await?;
    backdate_fixups(tx).await?;

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

// --- Content as ops ---
//
// Tenancy above is direct INSERT (there is no `user.create` op — users
// arrive via OAuth). Everything below it is a backdated op script fed
// through `ops::apply_payload`, which is the same seam production uses.
// Two payoffs: a reseed exercises every content op handler, and the dev
// DB gets a real `processed_ops` history for the plan view's version
// scrubber to replay.

/// Anchor-relative. `w(-8)` = Monday, eight weeks back.
fn w(weeks: i64) -> DateTime<Utc> {
    week_anchor() + Duration::weeks(weeks)
}

struct FixtureOp {
    when: DateTime<Utc>,
    /// Whoever "made" the change. `task.create` stamps `created_by` from
    /// it, so passing the assignee preserves the pre-conversion fixture.
    actor: Uuid,
    op: Op,
}

struct Fixture {
    ops: Vec<FixtureOp>,
    /// Only reached by `task.delete`, and the fixture has no
    /// attachments, so nothing ever touches the filesystem.
    storage: StorageBackend,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            ops: Vec::new(),
            storage: StorageBackend::Local(LocalStorage::new("/tmp/fira-seed-storage".into())),
        }
    }

    fn at(&mut self, when: DateTime<Utc>, actor: Uuid, op: Op) -> &mut Self {
        self.ops.push(FixtureOp { when, actor, op });
        self
    }

    /// One transaction, not one per op: production isolates ops so a bad
    /// one doesn't poison its neighbours, but a seeder wants
    /// all-or-nothing.
    async fn apply(mut self, tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
        // Chronological so `seq` agrees with `applied_at`, as in
        // production — the projection orders by `seq`. Stable, so ops
        // sharing a timestamp keep their emission order and a create
        // still precedes the tick that follows it.
        self.ops.sort_by_key(|o| o.when);
        let workspace_id = id(TEAM_WORKSPACE_SLUG);
        for FixtureOp { when, actor, op } in self.ops {
            let kind = op.kind_str();
            let payload = serde_json::to_value(&op)?;
            let mut project_id = None;
            crate::ops::apply_payload(tx, actor, workspace_id, op, &mut project_id, &self.storage)
                .await
                .with_context(|| format!("seed op {kind} at {when}"))?;
            crate::ops::record_fixture_op(
                tx,
                actor,
                workspace_id,
                kind,
                payload,
                project_id,
                when,
            )
            .await?;
        }
        Ok(())
    }
}

struct TaskSpec {
    slug: &'static str,
    /// Weeks before `week_anchor()` the task was created. Anything a
    /// time block references must predate the earliest block (week -5).
    created_w: i64,
    project: &'static str,
    track: Option<&'static str>,
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

static TASKS: &[TaskSpec] = &[
    // ---- ATLAS Now ----
    TaskSpec {
        slug: "t_atlas_oauth", created_w: -9, project: "p_atlas", track: Some("e_auth_v2"), sprint: Some("s_apr27"),
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
        slug: "t_atlas_billing", created_w: -9, project: "p_atlas", track: Some("e_billing"), sprint: Some("s_apr27"),
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
        slug: "t_atlas_review", created_w: -8, project: "p_atlas", track: Some("e_perf"), sprint: Some("s_apr27"),
        assignee: "u_maya", title: "Code review: rate-limit middleware",
        description: "Bob's PR. Token bucket per IP + per user. Check the redis fallback.",
        section: "now", status: "todo", priority: Some("p2"),
        source: "jira", external_id: Some("ATL-440"),
        estimate_min: Some(60), spent_min: 0, tags: &["review"],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_sso", created_w: -8, project: "p_atlas", track: Some("e_auth_v2"), sprint: Some("s_may11"),
        assignee: "u_anna", title: "SAML SSO for enterprise tier",
        description: "",
        section: "now", status: "todo", priority: Some("p1"),
        source: "jira", external_id: Some("ATL-451"),
        estimate_min: Some(480), spent_min: 0, tags: &["auth", "enterprise"],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_logs", created_w: -7, project: "p_atlas", track: Some("e_perf"), sprint: Some("s_may11"),
        assignee: "u_anna", title: "Audit log retention policy",
        description: "",
        section: "now", status: "todo", priority: Some("p2"),
        source: "jira", external_id: Some("ATL-446"),
        estimate_min: Some(180), spent_min: 0, tags: &["compliance"],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_perf", created_w: -8, project: "p_atlas", track: Some("e_perf"), sprint: Some("s_apr27"),
        assignee: "u_bob", title: "Investigate p99 spike on /sessions",
        description: "p99 went from 80ms → 320ms after the auth refactor merge. Bisect commits.",
        section: "now", status: "in_progress", priority: Some("p0"),
        source: "jira", external_id: Some("ATL-449"),
        estimate_min: Some(240), spent_min: 60, tags: &["perf"],
        subtasks: &[],
    },
    // ---- RELAY Now ----
    TaskSpec {
        slug: "t_relay_jira", created_w: -9, project: "p_relay", track: Some("e_sync_engine"), sprint: Some("s_relay9"),
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
        slug: "t_relay_diff", created_w: -7, project: "p_relay", track: Some("e_sync_engine"), sprint: Some("s_relay9"),
        assignee: "u_maya", title: "Diff viewer for diverged tasks",
        description: "When a task is diverged, show side-by-side diff so user picks a side.",
        section: "now", status: "todo", priority: Some("p2"),
        source: "notion", external_id: Some("sync-engine/52"),
        estimate_min: Some(240), spent_min: 0, tags: &["ui"],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_relay_notion", created_w: -7, project: "p_relay", track: Some("e_onboarding"), sprint: Some("s_relay10"),
        assignee: "u_jin", title: "Notion column-mapping flow",
        description: "",
        section: "now", status: "todo", priority: Some("p1"),
        source: "notion", external_id: Some("sync-engine/55"),
        estimate_min: Some(360), spent_min: 0, tags: &["onboarding"],
        subtasks: &[],
    },
    // ---- HELIX Now ----
    TaskSpec {
        slug: "t_helix_emb", created_w: -9, project: "p_helix", track: Some("e_search"), sprint: Some("s_helix_q2"),
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
        slug: "t_helix_idea", created_w: -7, project: "p_helix", track: Some("e_explore"), sprint: Some("s_helix_q2"),
        assignee: "u_maya", title: "Sketch: estimate-confidence band on tasks",
        description: "",
        section: "now", status: "todo", priority: Some("p3"),
        source: "local", external_id: None,
        estimate_min: Some(60), spent_min: 0, tags: &["design"],
        subtasks: &[],
    },
    // ---- RECURRING ----
    // Ongoing commitments — the task itself is the schedule, the
    // calendar blocks are the instances. Demoes the recurring-section
    // styling: completed blocks tint muted/strikethrough; planned
    // blocks stay normal (no "stale planned" warning).
    TaskSpec {
        slug: "t_atlas_standup", created_w: -10, project: "p_atlas", track: None, sprint: None,
        assignee: "u_maya", title: "Daily standup",
        description: "Atlas + Relay team. 30 min before OAuth kickoff. Skip Wednesdays — design review day.",
        section: "recurring", status: "in_progress", priority: None,
        source: "local", external_id: None,
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_codereview", created_w: -10, project: "p_atlas", track: None, sprint: None,
        assignee: "u_maya", title: "Weekly code review block",
        description: "Tue afternoon. Burn down the PR queue.",
        section: "recurring", status: "in_progress", priority: None,
        source: "local", external_id: None,
        estimate_min: None, spent_min: 0, tags: &["review"],
        subtasks: &[],
    },
    // ---- LATER ----
    TaskSpec {
        slug: "t_atlas_later1", created_w: -4, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Magic-link auth fallback",
        description: "",
        section: "later", status: "backlog", priority: Some("p2"),
        source: "jira", external_id: Some("ATL-501"),
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_later2", created_w: -5, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Admin UI: revoke session",
        description: "",
        section: "later", status: "backlog", priority: Some("p3"),
        source: "jira", external_id: Some("ATL-510"),
        estimate_min: Some(180), spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_later3", created_w: -4, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Investigate FIDO2 / passkeys",
        description: "",
        section: "later", status: "backlog", priority: Some("p3"),
        source: "jira", external_id: Some("ATL-515"),
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_relay_later1", created_w: -4, project: "p_relay", track: Some("e_onboarding"), sprint: None,
        assignee: "u_maya", title: "GitHub Issues source adapter",
        description: "",
        section: "later", status: "backlog", priority: Some("p3"),
        source: "notion", external_id: Some("sync-engine/61"),
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_relay_later2", created_w: -2, project: "p_relay", track: Some("e_sync_engine"), sprint: None,
        assignee: "u_maya", title: "Bug: Notion poll skips archived pages",
        description: "Spotted in standup 2026-04-28. Repro: archive a page, watch poll cycle.",
        section: "later", status: "backlog", priority: Some("p2"),
        source: "local", external_id: None,
        estimate_min: Some(60), spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_helix_later1", created_w: -3, project: "p_helix", track: Some("e_explore"), sprint: None,
        assignee: "u_maya", title: "Read: \"Notion Calendar postmortem\" blog",
        description: "",
        section: "later", status: "backlog", priority: Some("p3"),
        source: "local", external_id: None,
        estimate_min: Some(30), spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_helix_later2", created_w: -1, project: "p_helix", track: Some("e_explore"), sprint: None,
        assignee: "u_maya", title: "Try DuckDB for snapshot replay queries",
        description: "",
        section: "later", status: "backlog", priority: Some("p3"),
        source: "local", external_id: None,
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    // ---- SOMEDAY ----
    TaskSpec {
        slug: "t_atlas_someday1", created_w: -8, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Hardware token (YubiKey) onboarding flow",
        description: "",
        section: "someday", status: "backlog", priority: Some("p3"),
        source: "jira", external_id: Some("ATL-602"),
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_relay_someday1", created_w: -5, project: "p_relay", track: Some("e_onboarding"), sprint: None,
        assignee: "u_maya", title: "Linear source adapter",
        description: "",
        section: "someday", status: "backlog", priority: Some("p3"),
        source: "local", external_id: None,
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_helix_someday1", created_w: -4, project: "p_helix", track: Some("e_explore"), sprint: None,
        assignee: "u_maya", title: "Voice-input for quick-capture (research)",
        description: "",
        section: "someday", status: "backlog", priority: Some("p3"),
        source: "local", external_id: None,
        estimate_min: None, spent_min: 0, tags: &[],
        subtasks: &[],
    },
    // ---- DONE ----
    TaskSpec {
        slug: "t_atlas_done_today", created_w: -8, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Publish API rate-limit guide", description: "",
        section: "done", status: "done", priority: Some("p2"), source: "local", external_id: None,
        estimate_min: Some(60), spent_min: 45, tags: &["auth"], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_done_yesterday", created_w: -8, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Tighten billing export permissions", description: "",
        section: "done", status: "done", priority: Some("p1"), source: "local", external_id: None,
        estimate_min: Some(90), spent_min: 75, tags: &["billing"], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_done_recent", created_w: -7, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Clean up stale webhook subscriptions", description: "",
        section: "done", status: "done", priority: Some("p2"), source: "local", external_id: None,
        estimate_min: Some(120), spent_min: 110, tags: &[], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_done_last_week", created_w: -10, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Retire legacy OAuth callback", description: "",
        section: "done", status: "done", priority: Some("p3"), source: "local", external_id: None,
        estimate_min: Some(45), spent_min: 30, tags: &[], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_done_july_one", created_w: -10, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Document the recovery runbook", description: "",
        section: "done", status: "done", priority: Some("p2"), source: "local", external_id: None,
        estimate_min: Some(180), spent_min: 165, tags: &["security"], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_done_july_two", created_w: -12, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Replace the email delivery retry worker", description: "",
        section: "done", status: "done", priority: Some("p2"), source: "local", external_id: None,
        estimate_min: Some(240), spent_min: 210, tags: &[], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_done_older", created_w: -12, project: "p_atlas", track: Some("e_auth_v2"), sprint: None,
        assignee: "u_maya", title: "Audit infrastructure access grants", description: "",
        section: "done", status: "done", priority: Some("p1"), source: "local", external_id: None,
        estimate_min: Some(300), spent_min: 275, tags: &[], subtasks: &[],
    },
    // ---- DONE, AND NEVER PLANNED ----
    //
    // The retro band's whole case: work that got finished without going
    // through a sprint. Every other done task here is placed, so without
    // these the band is empty on a fresh seed and the feature can't be
    // seen — and "we kept working without sprints for a fortnight" is
    // the ordinary case it exists to answer, not an edge one.
    //
    // No `sprint`, recent enough to land inside the board's default
    // -6..+10 window, and spread over three fortnights so the band shows
    // more than one bucket.
    TaskSpec {
        slug: "t_atlas_loose1", created_w: -6, project: "p_atlas", track: None, sprint: None,
        assignee: "u_maya", title: "Swap the staging TLS certificate", description: "",
        section: "done", status: "done", priority: Some("p1"), source: "local", external_id: None,
        estimate_min: Some(60), spent_min: 50, tags: &["security"], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_loose2", created_w: -5, project: "p_atlas", track: None, sprint: None,
        assignee: "u_maya", title: "Unblock the finance CSV export", description: "",
        section: "done", status: "done", priority: Some("p1"), source: "local", external_id: None,
        estimate_min: Some(90), spent_min: 120, tags: &["billing"], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_loose3", created_w: -4, project: "p_atlas", track: None, sprint: None,
        assignee: "u_maya", title: "Answer the SOC2 evidence request", description: "",
        section: "done", status: "done", priority: Some("p2"), source: "local", external_id: None,
        estimate_min: Some(120), spent_min: 150, tags: &["compliance"], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_loose4", created_w: -3, project: "p_atlas", track: None, sprint: None,
        assignee: "u_maya", title: "Rotate the webhook signing secret", description: "",
        section: "done", status: "done", priority: Some("p2"), source: "local", external_id: None,
        estimate_min: Some(45), spent_min: 40, tags: &["security"], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_loose5", created_w: -2, project: "p_atlas", track: None, sprint: None,
        assignee: "u_maya", title: "Trim the noisy pager rule", description: "",
        section: "done", status: "done", priority: Some("p3"), source: "local", external_id: None,
        estimate_min: Some(30), spent_min: 25, tags: &[], subtasks: &[],
    },
    TaskSpec {
        slug: "t_atlas_done1", created_w: -8, project: "p_atlas", track: Some("e_auth_v2"), sprint: Some("s_apr27"),
        assignee: "u_maya", title: "Migrate session store to Redis 7",
        description: "",
        section: "done", status: "done", priority: None,
        source: "jira", external_id: Some("ATL-401"),
        estimate_min: Some(240), spent_min: 280, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_relay_done1", created_w: -8, project: "p_relay", track: Some("e_sync_engine"), sprint: Some("s_relay9"),
        assignee: "u_maya", title: "Initial Jira OAuth flow",
        description: "",
        section: "done", status: "done", priority: None,
        source: "notion", external_id: Some("sync-engine/40"),
        estimate_min: Some(360), spent_min: 420, tags: &[],
        subtasks: &[],
    },
    TaskSpec {
        slug: "t_helix_done1", created_w: -8, project: "p_helix", track: Some("e_search"), sprint: Some("s_helix_q2"),
        assignee: "u_maya", title: "Spike: pgvector vs qdrant benchmark",
        description: "",
        section: "done", status: "done", priority: None,
        source: "local", external_id: None,
        estimate_min: Some(180), spent_min: 240, tags: &[],
        subtasks: &[],
    },
];

fn fixture_tracks(f: &mut Fixture) {
    for (i, (slug, project, title, color)) in TRACKS.iter().enumerate() {
        // Before every sprint and task, so their track_id resolves.
        f.at(
            w(-13),
            primary_user_id(),
            track_create(slug, project, title, color, i),
        );
    }
}

/// `(slug, project, title, color)`.
const TRACKS: [(&str, &str, &str, &str); 7] = [
    ("e_auth_v2", "p_atlas", "Auth v2 (refresh + SSO)", "#0F766E"),
    ("e_billing", "p_atlas", "Billing reliability", "#B45309"),
    ("e_perf", "p_atlas", "Perf + observability", "#6D28D9"),
    ("e_sync_engine", "p_relay", "Sync engine v1", "#1D4ED8"),
    ("e_onboarding", "p_relay", "Source onboarding", "#BE123C"),
    ("e_search", "p_helix", "Semantic task search", "#4D7C0F"),
    ("e_explore", "p_helix", "Misc exploration", "#9333EA"),
];

/// Sprints the current-week fixture needs, with real week spans. The
/// ones bracketing `w(0)` are what makes "this sprint" meaningful in the
/// list; `fixture_plan_history` adds the past.
fn fixture_sprints(f: &mut Fixture) {
    let anchor = week_anchor().date_naive();
    let title_dated = |weeks: i64| format!("Atlas · {}", fmt_md(anchor + Duration::weeks(weeks)));
    let sprints: [(&str, &str, &str, String, i64, i64); 5] = [
        ("s_apr27", "p_atlas", "e_auth_v2", title_dated(0), 0, 2),
        ("s_may11", "p_atlas", "e_perf", title_dated(2), 2, 4),
        (
            "s_relay9",
            "p_relay",
            "e_sync_engine",
            "Relay · Sprint 9".into(),
            -1,
            1,
        ),
        (
            "s_relay10",
            "p_relay",
            "e_onboarding",
            "Relay · Sprint 10".into(),
            1,
            3,
        ),
        ("s_helix_q2", "p_helix", "e_search", "Helix · Q2".into(), 0, 8),
    ];
    for (i, (slug, project, track, title, from, to)) in sprints.iter().enumerate() {
        f.at(
            w(-12),
            primary_user_id(),
            sprint_create(slug, project, Some(track), title, *from, *to, i),
        );
    }
}

fn track_create(slug: &str, project: &str, title: &str, color: &str, i: usize) -> Op {
    Op::TrackCreate {
        track: TrackInput {
            id: id(slug),
            project_id: id(project),
            title: title.to_string(),
            color: color.to_string(),
            sort_key: format!("M{i:03}"),
        },
    }
}

/// `from`/`to` are weeks relative to the anchor; `to` is exclusive.
fn sprint_create(
    slug: &str,
    project: &str,
    track: Option<&str>,
    title: &str,
    from: i64,
    to: i64,
    i: usize,
) -> Op {
    Op::SprintCreate {
        sprint: SprintInput {
            id: id(slug),
            project_id: id(project),
            track_id: track.map(id),
            title: title.to_string(),
            starts_on: Some(w(from).date_naive()),
            ends_on: Some(w(to).date_naive()),
            sort_key: format!("M{i:03}"),
        },
    }
}

fn set_dates(slug: &str, from: i64, to: i64) -> Op {
    Op::SprintSetDates {
        sprint_id: id(slug),
        starts_on: w(from).date_naive(),
        ends_on: w(to).date_naive(),
    }
}

fn set_sprint(task: &str, sprint: Option<&str>) -> Op {
    Op::TaskSetSprint {
        task_id: id(task),
        sprint_id: sprint.map(id),
    }
}

/// Twelve weeks of plan history for Atlas. Hand-written because it *is*
/// a narrative — the point of the version scrubber is that specific
/// things slipped on specific weeks, and random churn demonstrates
/// nothing. Every state the drift overlay can render appears here once.
fn fixture_plan_history(f: &mut Fixture) {
    let me = primary_user_id();
    let d = |days: i64| Duration::days(days);

    // ---- W-12: the baseline board ----
    f.at(w(-12), me, sprint_create("sp_a1", "p_atlas", Some("e_auth_v2"), "Atlas · Groundwork", -12, -10, 10));
    f.at(w(-12), me, sprint_create("sp_a2", "p_atlas", Some("e_auth_v2"), "Atlas · Token rotation", -10, -8, 11));
    f.at(w(-12), me, sprint_create("sp_a3", "p_atlas", Some("e_billing"), "Atlas · Billing hardening", -8, -6, 12));
    f.at(w(-12) + d(1), me, set_sprint("t_atlas_done_older", Some("sp_a1")));
    f.at(w(-12) + d(1), me, set_sprint("t_atlas_done_july_two", Some("sp_a1")));

    // ---- W-10: a healthy climbing done-count ----
    f.at(w(-10), me, set_sprint("t_atlas_done_july_one", Some("sp_a2")));
    f.at(w(-10), me, set_sprint("t_atlas_done_last_week", Some("sp_a2")));

    // ---- W-8: the headline slip ----
    f.at(w(-8), me, set_dates("sp_a2", -8, -6));
    f.at(w(-8) + d(1), me, set_sprint("t_atlas_done_yesterday", Some("sp_a3")));
    f.at(w(-8) + d(1), me, set_sprint("t_atlas_done_today", Some("sp_a3")));
    f.at(w(-8) + d(1), me, set_sprint("t_atlas_someday1", Some("sp_a3")));

    // ---- W-7: a sprint that won't survive ----
    f.at(w(-7), me, sprint_create("sp_a5", "p_atlas", Some("e_perf"), "Atlas · Scratch", -6, -4, 13));

    // ---- W-6: the retrack, and scope creep mid-sprint ----
    f.at(w(-6), me, Op::SprintSetTrack { sprint_id: id("sp_a3"), track_id: Some(id("e_perf")) });
    f.at(w(-6) + d(1), me, set_sprint("t_atlas_done_recent", Some("sp_a2")));

    // ---- W-5: a task that is later deleted outright. Not in TASKS: its
    // end state is "gone", and it exists to give the scrubber's
    // resurrection path something real to rebuild.
    f.at(w(-5), me, Op::TaskCreate {
        task: TaskInput {
            id: id("t_atlas_dropped"),
            project_id: id("p_atlas"),
            track_id: Some(id("e_perf")),
            sprint_id: None,
            assignee_id: Some(me),
            title: "Retire the v1 metrics pipeline".to_string(),
            description_md: String::new(),
            section: "later".to_string(),
            status: "todo".to_string(),
            priority: None,
            source: "local".to_string(),
            external_id: None,
            external_url: None,
            estimate_min: Some(90),
            spent_min: 0,
            tag_ids: vec![],
            sort_key: "M".into(),
        },
    });
    f.at(w(-5) + d(1), me, set_sprint("t_atlas_dropped", Some("sp_a2")));
    f.at(w(-4) + d(3), me, Op::TaskTick { task_id: id("t_atlas_dropped"), done: true });

    // ---- W-4: "added since T", and a membership drop ----
    f.at(w(-4), me, sprint_create("sp_a4", "p_atlas", Some("e_perf"), "Atlas · Observability", -4, -2, 14));
    f.at(w(-4) + d(1), me, set_sprint("t_atlas_later1", Some("sp_a4")));
    f.at(w(-4) + d(1), me, set_sprint("t_atlas_later2", Some("sp_a4")));
    f.at(w(-4) + d(2), me, set_sprint("t_atlas_someday1", None));

    // ---- W-3 ----
    f.at(w(-3), me, set_sprint("t_atlas_later3", Some("sp_a5")));

    // ---- W-2: the resurrection case, and tasks returning to the inbox ----
    f.at(w(-2), me, Op::TaskDelete { task_id: id("t_atlas_dropped") });
    f.at(w(-2) + d(1), me, Op::SprintDelete { sprint_id: id("sp_a5") });

    // ---- W-1: cumulative drift, not a one-off ----
    f.at(w(-1), me, set_dates("sp_a2", -8, -5));
}

/// Palette for the derived tag rows. Cursor advances per distinct
/// (project, title) pair, in TASKS order.
const TAG_PALETTE: [&str; 7] = [
    "#0F766E", "#B45309", "#6D28D9", "#1D4ED8", "#BE123C", "#4D7C0F", "#9333EA",
];

fn tag_slug(project: &str, title: &str) -> String {
    format!("tag_{project}_{title}")
}

/// Distinct (project, tag-title) pairs across TASKS become tag rows.
/// The same name in two projects gets two distinct tags.
fn fixture_tags(f: &mut Fixture) {
    let mut seen: std::collections::HashSet<(&str, &str)> = Default::default();
    let mut cursor = 0usize;
    for t in TASKS {
        for title in t.tags.iter().copied() {
            if !seen.insert((t.project, title)) {
                continue;
            }
            let color = TAG_PALETTE[cursor % TAG_PALETTE.len()];
            cursor += 1;
            // Before every task, so `task.create`'s tag_ids resolve.
            f.at(
                w(-13),
                id(t.assignee),
                Op::TagCreate {
                    tag: TagInput {
                        id: id(&tag_slug(t.project, title)),
                        project_id: id(t.project),
                        title: title.to_string(),
                        color: color.to_string(),
                    },
                },
            );
        }
    }
}

fn fixture_tasks(f: &mut Fixture) {
    for t in TASKS {
        let actor = id(t.assignee);
        let created = w(t.created_w);
        f.at(
            created,
            actor,
            Op::TaskCreate {
                task: TaskInput {
                    id: id(t.slug),
                    project_id: id(t.project),
                    track_id: t.track.map(id),
                    sprint_id: t.sprint.map(id),
                    assignee_id: Some(actor),
                    title: t.title.to_string(),
                    description_md: t.description.to_string(),
                    section: t.section.to_string(),
                    status: t.status.to_string(),
                    priority: t.priority.map(str::to_string),
                    source: t.source.to_string(),
                    external_id: t.external_id.map(str::to_string),
                    external_url: None,
                    estimate_min: t.estimate_min,
                    spent_min: t.spent_min,
                    tag_ids: t
                        .tags
                        .iter()
                        .map(|title| id(&tag_slug(t.project, title)))
                        .collect(),
                    sort_key: "M".into(),
                },
            },
        );

        for (i, (title, done)) in t.subtasks.iter().enumerate() {
            f.at(
                created,
                actor,
                Op::SubtaskCreate {
                    subtask: SubtaskInput {
                        id: id(&format!("{}_s{}", t.slug, i)),
                        task_id: id(t.slug),
                        title: title.to_string(),
                        done: false,
                        sort_key: format!("M{i:03}"),
                    },
                },
            );
            if *done {
                f.at(
                    created + Duration::days(1),
                    actor,
                    Op::SubtaskTick {
                        subtask_id: id(&format!("{}_s{}", t.slug, i)),
                        done: true,
                    },
                );
            }
        }

        // `task.create` doesn't stamp `finished_at` — only a transition
        // into done does. Ticking is also the truer history: the task
        // existed before it was finished.
        if t.status == "done" {
            f.at(
                created + Duration::days(2),
                actor,
                Op::TaskTick {
                    task_id: id(t.slug),
                    done: true,
                },
            );
        }
    }
}

/// Timestamps no op writes. Has to be a post-pass: `created_at` and
/// `finished_at` are both server-managed (`DEFAULT now()`, and the tick
/// handler hardcodes `now()`), and teaching production SQL about
/// seeding would be backwards.
async fn backdate_fixups(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    // Match the row to the op log that created it, or the retro band's
    // created_at fallback disagrees with the history it replays.
    for t in TASKS {
        sqlx::query("UPDATE tasks SET created_at = $2 WHERE id = $1")
            .bind(id(t.slug))
            .bind(w(t.created_w))
            .execute(&mut **tx)
            .await?;
    }
    // No op writes `active` — the plan board reads the span and its
    // "now" marker instead. Set here so the list's sprint filter keeps
    // the same three current sprints it had before the op conversion.
    sqlx::query("UPDATE sprints SET active = true WHERE id = ANY($1)")
        .bind(
            ["s_apr27", "s_relay9", "s_helix_q2"]
                .iter()
                .map(|s| id(s))
                .collect::<Vec<_>>(),
        )
        .execute(&mut **tx)
        .await?;

    // Spread the completed Atlas fixtures across archive periods so the
    // Done grouping is useful immediately.
    for (slug, days_ago) in [
        ("t_atlas_done_today", 0_i64),
        ("t_atlas_done_yesterday", 1),
        ("t_atlas_done_recent", 3),
        ("t_atlas_done_last_week", 8),
        ("t_atlas_done_july_one", 14),
        ("t_atlas_done_july_two", 35),
        ("t_atlas_done_older", 75),
        // Unplanned finishes, newest first. Three fortnights' worth, so
        // the retro band renders as a band rather than one lone bucket.
        ("t_atlas_loose5", 6),
        ("t_atlas_loose4", 11),
        ("t_atlas_loose3", 18),
        ("t_atlas_loose2", 25),
        ("t_atlas_loose1", 31),
    ] {
        sqlx::query("UPDATE tasks SET finished_at = now() - ($2 * INTERVAL '1 day') WHERE id = $1")
            .bind(id(slug))
            .bind(days_ago)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

fn fixture_blocks(f: &mut Fixture) {
    // (day, start_min, dur_min, state, task_slug). State is hardcoded per
    // block — explicitly NOT derived from the wallclock at seed time. The
    // dump-bootstrap snapshot freezes "now", so a wallclock-driven state
    // would mean a snapshot taken Sunday night shows every block of the
    // week as "completed" and the demo loses its done/planned mix. Instead
    // the seed declares "Mon–Wed morning are done, the rest is planned" as
    // the canonical fixture, and the demo reads the same regardless of
    // when the dump ran.
    let blocks: &[(i64, i64, i64, &str, &str)] = &[
        // MON — fully completed
        (0, 9 * 60, 90, "completed", "t_atlas_oauth"),
        (0, 10 * 60 + 30, 60, "completed", "t_atlas_review"),
        (0, 13 * 60, 120, "completed", "t_atlas_billing"),
        (0, 15 * 60 + 30, 90, "completed", "t_relay_jira"),
        // TUE — fully completed
        (1, 9 * 60, 120, "completed", "t_atlas_oauth"),
        (1, 11 * 60 + 30, 90, "completed", "t_helix_emb"),
        (1, 14 * 60, 90, "completed", "t_relay_jira"),
        (1, 16 * 60, 60, "completed", "t_atlas_review"),
        // WED — morning completed, afternoon still planned
        (2, 9 * 60, 90, "completed", "t_atlas_oauth"),
        (2, 11 * 60, 60, "completed", "t_atlas_billing"),
        (2, 13 * 60, 90, "planned", "t_relay_jira"),
        (2, 15 * 60, 60, "planned", "t_atlas_review"),
        (2, 16 * 60 + 30, 90, "planned", "t_helix_emb"),
        // THU — all planned
        (3, 9 * 60, 120, "planned", "t_atlas_oauth"),
        (3, 11 * 60 + 30, 60, "planned", "t_atlas_billing"),
        (3, 13 * 60, 90, "planned", "t_relay_jira"),
        (3, 15 * 60, 120, "planned", "t_relay_diff"),
        // FRI — all planned
        (4, 9 * 60, 90, "planned", "t_atlas_billing"),
        (4, 10 * 60 + 30, 60, "planned", "t_atlas_oauth"),
        (4, 13 * 60, 120, "planned", "t_helix_emb"),
        (4, 15 * 60 + 30, 90, "planned", "t_relay_jira"),
        // SAT — planned
        (5, 10 * 60, 90, "planned", "t_helix_emb"),
        // ---- Recurring instances ----
        // Daily standup at 08:00 UTC (right before the 09:00 OAuth block)
        // — completed Mon/Tue, planned Thu/Fri.
        (0, 8 * 60, 30, "completed", "t_atlas_standup"),
        (1, 8 * 60, 30, "completed", "t_atlas_standup"),
        (3, 8 * 60, 30, "planned", "t_atlas_standup"),
        (4, 8 * 60, 30, "planned", "t_atlas_standup"),
        // Weekly code review — single Tue slot, this week's already done.
        // 17:00–18:00 avoids the 13:00 GCal standup and the 16:00 review.
        (1, 17 * 60, 60, "completed", "t_atlas_codereview"),
    ];
    for (i, (day, start_min, dur, state, slug)) in blocks.iter().enumerate() {
        let start_at = ts(*day, *start_min);
        // Logged at the moment the block starts: the fixture's history
        // then reads as "planned the week it happened", and `seq`
        // follows the calendar.
        f.at(
            start_at,
            primary_user_id(),
            Op::BlockCreate {
                block: BlockInput {
                    id: id(&format!("b_{i}")),
                    task_id: id(slug),
                    user_id: primary_user_id(),
                    start_at,
                    end_at: ts(*day, *start_min + *dur),
                    state: state.to_string(),
                },
            },
        );
    }

    fixture_block_history(f, blocks.len());
}

/// Five prior weeks of history, so the month dashboard has something to
/// aggregate. Without this the heatmap is one week of cells in a
/// six-week grid and the day-of-week chart is noise.
///
/// Every block here is `completed`, declared rather than derived — same
/// rule as the current week above. These are past weeks in a fixture, so
/// "completed" is a statement about the fixture, not about the wallclock
/// at seed time.
///
/// The shape is deliberately uneven: heavier Atlas than Helix, light
/// Fridays, two genuinely empty weekdays, one Saturday, and a week where
/// the standup lapses. A perfectly regular fixture makes the heatmap and
/// the day-of-week bars look synthetic and hides bugs in the "active
/// days" / "avg per active day" maths.
fn fixture_block_history(f: &mut Fixture, id_offset: usize) {
    // (week, day, start_min, dur_min, task_slug). `week` counts back from
    // the current week: -1 is last week. `day` is 0=Mon .. 6=Sun.
    let h: &[(i64, i64, i64, i64, &str)] = &[
        // ---- last week: a heavy, well-rounded week ----
        (-1, 0, 8 * 60, 30, "t_atlas_standup"),
        (-1, 0, 9 * 60, 120, "t_atlas_oauth"),
        (-1, 0, 11 * 60 + 30, 60, "t_atlas_review"),
        (-1, 0, 14 * 60, 120, "t_atlas_billing"),
        (-1, 1, 8 * 60, 30, "t_atlas_standup"),
        (-1, 1, 9 * 60, 150, "t_atlas_oauth"),
        (-1, 1, 13 * 60, 120, "t_relay_jira"),
        (-1, 1, 15 * 60 + 30, 90, "t_helix_emb"),
        (-1, 2, 8 * 60, 30, "t_atlas_standup"),
        (-1, 2, 9 * 60, 120, "t_atlas_billing"),
        (-1, 2, 13 * 60, 180, "t_helix_emb"),
        (-1, 3, 8 * 60, 30, "t_atlas_standup"),
        (-1, 3, 9 * 60, 90, "t_atlas_perf"),
        (-1, 3, 11 * 60, 60, "t_atlas_review"),
        (-1, 3, 14 * 60, 120, "t_relay_diff"),
        (-1, 4, 9 * 60 + 30, 90, "t_atlas_logs"),
        // ---- two weeks back: a Wednesday off, catching up Thursday ----
        (-2, 0, 8 * 60, 30, "t_atlas_standup"),
        (-2, 0, 9 * 60, 120, "t_atlas_sso"),
        (-2, 0, 13 * 60, 90, "t_relay_jira"),
        (-2, 1, 8 * 60, 30, "t_atlas_standup"),
        (-2, 1, 9 * 60, 180, "t_atlas_sso"),
        (-2, 1, 14 * 60, 60, "t_atlas_review"),
        // (-2, 2) deliberately empty — a day off mid-week.
        (-2, 3, 8 * 60, 30, "t_atlas_standup"),
        (-2, 3, 9 * 60, 210, "t_atlas_sso"),
        (-2, 3, 13 * 60, 120, "t_atlas_billing"),
        (-2, 3, 15 * 60 + 30, 90, "t_relay_diff"),
        (-2, 4, 9 * 60, 120, "t_helix_emb"),
        (-2, 4, 13 * 60, 60, "t_atlas_review"),
        (-2, 5, 10 * 60, 120, "t_helix_idea"),
        // ---- three weeks back: research-heavy, standup lapses ----
        (-3, 0, 9 * 60, 180, "t_helix_emb"),
        (-3, 0, 14 * 60, 90, "t_helix_idea"),
        (-3, 1, 9 * 60, 120, "t_helix_emb"),
        (-3, 1, 13 * 60, 120, "t_atlas_perf"),
        (-3, 2, 8 * 60, 30, "t_atlas_standup"),
        (-3, 2, 9 * 60, 150, "t_atlas_perf"),
        (-3, 2, 14 * 60, 90, "t_relay_notion"),
        (-3, 3, 9 * 60, 120, "t_atlas_oauth"),
        (-3, 3, 13 * 60, 150, "t_helix_idea"),
        (-3, 4, 10 * 60, 90, "t_relay_notion"),
        // ---- four weeks back: a light week ----
        (-4, 0, 8 * 60, 30, "t_atlas_standup"),
        (-4, 0, 9 * 60, 120, "t_atlas_logs"),
        (-4, 1, 8 * 60, 30, "t_atlas_standup"),
        (-4, 1, 9 * 60, 90, "t_atlas_logs"),
        (-4, 1, 13 * 60, 60, "t_relay_jira"),
        (-4, 2, 8 * 60, 30, "t_atlas_standup"),
        (-4, 2, 9 * 60 + 30, 120, "t_atlas_review"),
        // (-4, 3) deliberately empty.
        (-4, 4, 9 * 60, 60, "t_atlas_logs"),
        // ---- five weeks back: a full, front-loaded week ----
        (-5, 0, 8 * 60, 30, "t_atlas_standup"),
        (-5, 0, 9 * 60, 180, "t_atlas_oauth"),
        (-5, 0, 13 * 60, 120, "t_atlas_billing"),
        (-5, 0, 15 * 60 + 30, 90, "t_relay_jira"),
        (-5, 1, 8 * 60, 30, "t_atlas_standup"),
        (-5, 1, 9 * 60, 150, "t_atlas_oauth"),
        (-5, 1, 13 * 60, 180, "t_atlas_billing"),
        (-5, 2, 8 * 60, 30, "t_atlas_standup"),
        (-5, 2, 9 * 60, 120, "t_helix_emb"),
        (-5, 2, 13 * 60, 120, "t_relay_diff"),
        (-5, 3, 8 * 60, 30, "t_atlas_standup"),
        (-5, 3, 9 * 60, 120, "t_atlas_perf"),
        (-5, 3, 14 * 60, 90, "t_atlas_review"),
        (-5, 4, 9 * 60, 120, "t_relay_notion"),
    ];

    // Block ids continue the `b_{i}` sequence so the two tables can't
    // collide on a deterministic id.
    for (i, (week, day, start_min, dur, slug)) in h.iter().enumerate() {
        let day_index = week * 7 + day;
        let start_at = ts(day_index, *start_min);
        f.at(
            start_at,
            primary_user_id(),
            Op::BlockCreate {
                block: BlockInput {
                    id: id(&format!("b_{}", id_offset + i)),
                    task_id: id(slug),
                    user_id: primary_user_id(),
                    start_at,
                    end_at: ts(day_index, *start_min + *dur),
                    state: "completed".into(),
                },
            },
        );
    }
}

/// Maya's goals in the team workspace. Deliberately one of each shape,
/// so the dashboard's goal card has to handle all of them on first run:
/// a task-scoped daily floor, a project-scoped daily floor, a
/// tag-scoped weekly floor, and a cap.
fn fixture_goals(f: &mut Fixture) {
    struct GoalSpec {
        slug: &'static str,
        name: &'static str,
        cadence: &'static str,
        direction: &'static str,
        target_min: Option<i32>,
        project: Option<&'static str>,
        tag: Option<&'static str>,
        task: Option<&'static str>,
    }

    let goals = &[
        GoalSpec {
            slug: "g_standup", name: "Daily standup",
            cadence: "daily", direction: "at_least", target_min: Some(30),
            project: None, tag: None, task: Some("t_atlas_standup"),
        },
        GoalSpec {
            slug: "g_deep_atlas", name: "Deep work on Atlas",
            cadence: "daily", direction: "at_least", target_min: Some(120),
            project: Some("p_atlas"), tag: None, task: None,
        },
        GoalSpec {
            slug: "g_research", name: "Research time",
            cadence: "weekly", direction: "at_least", target_min: Some(180),
            project: None, tag: Some("tag_p_helix_research"), task: None,
        },
        // The cap. Exercises the inverted fill rule and proves an empty
        // day reads as a pass rather than a miss.
        GoalSpec {
            slug: "g_meetings", name: "Keep meetings down",
            cadence: "daily", direction: "at_most", target_min: Some(60),
            project: None, tag: Some("tag_p_atlas_review"), task: None,
        },
    ];

    for (i, g) in goals.iter().enumerate() {
        // workspace_id / user_id come from the actor, not the payload.
        f.at(
            w(-6),
            primary_user_id(),
            Op::GoalCreate {
                goal: GoalInput {
                    id: id(g.slug),
                    name: g.name.to_string(),
                    cadence: g.cadence.to_string(),
                    direction: g.direction.to_string(),
                    target_min: g.target_min,
                    project_id: g.project.map(id),
                    tag_id: g.tag.map(id),
                    task_id: g.task.map(id),
                    sort_key: format!("M{i:03}"),
                },
            },
        );
    }
}
