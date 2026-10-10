// Tier B: the plan ops against a real database.
//
// `#[sqlx::test]` gives each test its own migrated database, so there is
// no fixture teardown to write and no ordering between tests. It covers
// what the pure `project_at` tests can't: that each op persists what it
// claims, that the SET NULL cascades behave, and that a cross-project id
// is rejected with a readable error rather than silently filtered.
//
// Run with: cargo test --manifest-path api/Cargo.toml

use chrono::NaiveDate;
use fira_api::ops::{apply_payload, Op, SprintInput, TaskInput, TrackInput};
use fira_api::storage::{LocalStorage, StorageBackend};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const U: Uuid = Uuid::from_u128(0x11);
const WS: Uuid = Uuid::from_u128(0x22);
const P1: Uuid = Uuid::from_u128(0x33);
const P2: Uuid = Uuid::from_u128(0x34);

fn storage() -> StorageBackend {
    StorageBackend::Local(LocalStorage::new("/tmp/fira-test-storage".into()))
}

fn d(s: &str) -> NaiveDate {
    s.parse().unwrap()
}

/// One user, one workspace, two projects they own. Tenancy is always
/// direct INSERT — there is no `user.create` op.
async fn tenancy(pool: &PgPool) {
    sqlx::query("INSERT INTO users (id, email, name, initials) VALUES ($1,'m@e.dev','Maya','MA')")
        .bind(U).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO workspaces (id, title, is_personal, created_by) VALUES ($1,'WS',false,$2)")
        .bind(WS).bind(U).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1,$2,'owner')")
        .bind(WS).bind(U).execute(pool).await.unwrap();
    for (id, title) in [(P1, "Atlas"), (P2, "Relay")] {
        sqlx::query(
            "INSERT INTO projects (id, workspace_id, title, icon, color, source, owner_id)
             VALUES ($1,$2,$3,'Compass','#0F766E','local',$4)",
        ).bind(id).bind(WS).bind(title).bind(U).execute(pool).await.unwrap();
    }
}

async fn apply(tx: &mut Transaction<'_, Postgres>, op: Op) -> anyhow::Result<Option<Uuid>> {
    let mut project_id = None;
    apply_payload(tx, U, WS, op, &mut project_id, &storage()).await?;
    Ok(project_id)
}

async fn sort_key(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> String {
    sqlx::query_scalar("SELECT sort_key FROM tracks WHERE id = $1")
        .bind(id).fetch_one(&mut **tx).await.unwrap()
}

async fn sprint_of(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT sprint_id FROM tasks WHERE id = $1")
        .bind(id).fetch_one(&mut **tx).await.unwrap()
}

fn track(id: Uuid, project_id: Uuid, title: &str) -> Op {
    Op::TrackCreate {
        track: TrackInput {
            id, project_id, title: title.into(),
            color: "#334155".into(), sort_key: "M".into(),
        },
    }
}

fn sprint(id: Uuid, project_id: Uuid, track_id: Option<Uuid>, from: &str, to: &str) -> Op {
    Op::SprintCreate {
        sprint: SprintInput {
            id, project_id, track_id, title: "A1".into(),
            starts_on: Some(d(from)), ends_on: Some(d(to)), sort_key: "M".into(),
        },
    }
}

fn task(id: Uuid, project_id: Uuid, sprint_id: Option<Uuid>) -> Op {
    Op::TaskCreate {
        task: TaskInput {
            id, project_id, track_id: None, sprint_id, assignee_id: Some(U),
            title: "Pick a queue".into(), description_md: String::new(),
            section: "later".into(), status: "todo".into(), priority: None,
            source: "local".into(), external_id: None, external_url: None,
            estimate_min: None, spent_min: 0, tag_ids: vec![], sort_key: "M".into(),
        },
    }
}

#[sqlx::test]
async fn ops_persist_what_they_claim(pool: PgPool) {
    tenancy(&pool).await;
    let tr = Uuid::from_u128(0x41);
    let sp = Uuid::from_u128(0x51);
    let mut tx = pool.begin().await.unwrap();

    assert_eq!(apply(&mut tx, track(tr, P1, "Arch")).await.unwrap(), Some(P1));
    apply(&mut tx, sprint(sp, P1, Some(tr), "2026-10-05", "2026-10-19")).await.unwrap();

    apply(&mut tx, Op::TrackSetTitle { track_id: tr, title: "Architecture".into() }).await.unwrap();
    apply(&mut tx, Op::TrackSetColor { track_id: tr, color: "#B45309".into() }).await.unwrap();
    apply(&mut tx, Op::SprintSetTitle { sprint_id: sp, title: "Groundwork".into() }).await.unwrap();
    apply(&mut tx, Op::SprintSetDates {
        sprint_id: sp, starts_on: d("2026-10-12"), ends_on: d("2026-11-02"),
    }).await.unwrap();

    let (title, color): (String, String) =
        sqlx::query_as("SELECT title, color FROM tracks WHERE id = $1")
            .bind(tr).fetch_one(&mut *tx).await.unwrap();
    assert_eq!((title.as_str(), color.as_str()), ("Architecture", "#B45309"));

    let (st, from, to): (String, NaiveDate, NaiveDate) =
        sqlx::query_as("SELECT title, starts_on, ends_on FROM sprints WHERE id = $1")
            .bind(sp).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(st, "Groundwork");
    assert_eq!((from, to), (d("2026-10-12"), d("2026-11-02")), "the card actually moved");
}

#[sqlx::test]
async fn track_reorder_only_touches_its_own_project(pool: PgPool) {
    tenancy(&pool).await;
    let a = Uuid::from_u128(0x41);
    let b = Uuid::from_u128(0x42);
    let foreign = Uuid::from_u128(0x43);
    let mut tx = pool.begin().await.unwrap();
    apply(&mut tx, track(a, P1, "A")).await.unwrap();
    apply(&mut tx, track(b, P1, "B")).await.unwrap();
    apply(&mut tx, track(foreign, P2, "Foreign")).await.unwrap();

    // The `project_id` predicate *is* the authorization: ids inside
    // `ordered` are never trusted, so smuggling another project's id in
    // must be a no-op rather than a write.
    apply(&mut tx, Op::TrackReorder {
        project_id: P1,
        ordered: vec![b, a, foreign],
    }).await.unwrap();

    assert_eq!(sort_key(&mut tx, b).await, "M000");
    assert_eq!(sort_key(&mut tx, a).await, "M001");
    assert_eq!(sort_key(&mut tx, foreign).await, "M", "the forged id was not written");
}

#[sqlx::test]
async fn deleting_a_track_orphans_rather_than_destroys(pool: PgPool) {
    tenancy(&pool).await;
    let tr = Uuid::from_u128(0x41);
    let sp = Uuid::from_u128(0x51);
    let t = Uuid::from_u128(0x61);
    let mut tx = pool.begin().await.unwrap();
    apply(&mut tx, track(tr, P1, "Arch")).await.unwrap();
    apply(&mut tx, sprint(sp, P1, Some(tr), "2026-10-05", "2026-10-19")).await.unwrap();
    apply(&mut tx, task(t, P1, Some(sp))).await.unwrap();

    apply(&mut tx, Op::TrackDelete { track_id: tr }).await.unwrap();

    let (sprints, orphaned): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE track_id IS NULL) FROM sprints WHERE id = $1",
    ).bind(sp).fetch_one(&mut *tx).await.unwrap();
    assert_eq!((sprints, orphaned), (1, 1), "the sprint survives, without a track");

    let tasks: i64 = sqlx::query_scalar("SELECT count(*) FROM tasks WHERE id = $1")
        .bind(t).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(tasks, 1, "no task is destroyed by a plan-view gesture");
}

#[sqlx::test]
async fn deleting_a_sprint_returns_its_tasks_to_the_inbox(pool: PgPool) {
    tenancy(&pool).await;
    let sp = Uuid::from_u128(0x51);
    let t = Uuid::from_u128(0x61);
    let mut tx = pool.begin().await.unwrap();
    apply(&mut tx, sprint(sp, P1, None, "2026-10-05", "2026-10-19")).await.unwrap();
    apply(&mut tx, task(t, P1, Some(sp))).await.unwrap();

    apply(&mut tx, Op::SprintDelete { sprint_id: sp }).await.unwrap();

    let (count, unplaced): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE sprint_id IS NULL) FROM tasks WHERE id = $1",
    ).bind(t).fetch_one(&mut *tx).await.unwrap();
    assert_eq!((count, unplaced), (1, 1));
}

#[sqlx::test]
async fn cross_project_ids_are_rejected_with_a_readable_error(pool: PgPool) {
    tenancy(&pool).await;
    let foreign_track = Uuid::from_u128(0x43);
    let sp1 = Uuid::from_u128(0x51);
    let foreign_sprint = Uuid::from_u128(0x52);
    let t = Uuid::from_u128(0x61);
    let mut tx = pool.begin().await.unwrap();
    apply(&mut tx, track(foreign_track, P2, "Foreign")).await.unwrap();
    apply(&mut tx, sprint(sp1, P1, None, "2026-10-05", "2026-10-19")).await.unwrap();
    apply(&mut tx, sprint(foreign_sprint, P2, None, "2026-10-05", "2026-10-19")).await.unwrap();
    apply(&mut tx, task(t, P1, None)).await.unwrap();

    // Rejected, not silently filtered — silently filtering would lose
    // the user's intent without telling them.
    let e = apply(&mut tx, Op::SprintSetTrack {
        sprint_id: sp1, track_id: Some(foreign_track),
    }).await.unwrap_err().to_string();
    assert!(e.contains("different project"), "got: {e}");

    let e = apply(&mut tx, Op::TaskSetSprint {
        task_id: t, sprint_id: Some(foreign_sprint),
    }).await.unwrap_err().to_string();
    assert!(e.contains("different project"), "got: {e}");

    let e = apply(&mut tx, Op::SprintCreate {
        sprint: SprintInput {
            id: Uuid::from_u128(0x53), project_id: P1, track_id: Some(foreign_track),
            title: "X".into(), starts_on: Some(d("2026-10-05")),
            ends_on: Some(d("2026-10-19")), sort_key: "M".into(),
        },
    }).await.unwrap_err().to_string();
    assert!(e.contains("different project"), "got: {e}");
}

#[sqlx::test]
async fn an_out_of_scope_id_is_not_a_probe_oracle(pool: PgPool) {
    tenancy(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    // An id the caller cannot see at all resolves through the same
    // helper, so the error says "not in scope" rather than confirming
    // or denying that the row exists.
    let e = apply(&mut tx, Op::SprintSetTrack {
        sprint_id: Uuid::from_u128(0xDEAD), track_id: None,
    }).await.unwrap_err().to_string();
    assert!(e.contains("sprint not in scope"), "got: {e}");

    let e = apply(&mut tx, Op::TrackSetTitle {
        track_id: Uuid::from_u128(0xDEAD), title: "X".into(),
    }).await.unwrap_err().to_string();
    assert!(e.contains("track not in scope"), "got: {e}");
}

#[sqlx::test]
async fn an_invalid_span_is_rejected_before_the_database_sees_it(pool: PgPool) {
    tenancy(&pool).await;
    let sp = Uuid::from_u128(0x51);
    let mut tx = pool.begin().await.unwrap();
    apply(&mut tx, sprint(sp, P1, None, "2026-10-05", "2026-10-19")).await.unwrap();

    // A readable message, not a raw CHECK violation — these mirror
    // sprints_span_forward and sprints_*_monday from migration 0034.
    let e = apply(&mut tx, Op::SprintSetDates {
        sprint_id: sp, starts_on: d("2026-10-19"), ends_on: d("2026-10-05"),
    }).await.unwrap_err().to_string();
    assert!(e.contains("after its starts_on"), "got: {e}");

    let e = apply(&mut tx, Op::SprintSetDates {
        sprint_id: sp, starts_on: d("2026-10-05"), ends_on: d("2026-10-05"),
    }).await.unwrap_err().to_string();
    assert!(e.contains("after its starts_on"), "got: {e}");

    // 2026-10-06 is a Tuesday.
    let e = apply(&mut tx, Op::SprintSetDates {
        sprint_id: sp, starts_on: d("2026-10-06"), ends_on: d("2026-10-19"),
    }).await.unwrap_err().to_string();
    assert!(e.contains("Mondays"), "got: {e}");

    // The span is unchanged by any of the three.
    let (from, to): (NaiveDate, NaiveDate) =
        sqlx::query_as("SELECT starts_on, ends_on FROM sprints WHERE id = $1")
            .bind(sp).fetch_one(&mut *tx).await.unwrap();
    assert_eq!((from, to), (d("2026-10-05"), d("2026-10-19")));
}

#[sqlx::test]
async fn a_half_specified_span_is_rejected(pool: PgPool) {
    tenancy(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let e = apply(&mut tx, Op::SprintCreate {
        sprint: SprintInput {
            id: Uuid::from_u128(0x51), project_id: P1, track_id: None,
            title: "X".into(), starts_on: Some(d("2026-10-05")),
            ends_on: None, sort_key: "M".into(),
        },
    }).await.unwrap_err().to_string();
    assert!(e.contains("both starts_on and ends_on, or neither"), "got: {e}");
}

#[sqlx::test]
async fn task_set_sprint_round_trips_through_null(pool: PgPool) {
    tenancy(&pool).await;
    let sp = Uuid::from_u128(0x51);
    let t = Uuid::from_u128(0x61);
    let mut tx = pool.begin().await.unwrap();
    apply(&mut tx, sprint(sp, P1, None, "2026-10-05", "2026-10-19")).await.unwrap();
    apply(&mut tx, task(t, P1, None)).await.unwrap();

    assert_eq!(sprint_of(&mut tx, t).await, None);
    apply(&mut tx, Op::TaskSetSprint { task_id: t, sprint_id: Some(sp) }).await.unwrap();
    assert_eq!(sprint_of(&mut tx, t).await, Some(sp));
    apply(&mut tx, Op::TaskSetSprint { task_id: t, sprint_id: None }).await.unwrap();
    assert_eq!(sprint_of(&mut tx, t).await, None, "dragging out of a card is reversible");
}

#[sqlx::test]
async fn sprint_defaults_persist_validate_and_cascade(pool: PgPool) {
    tenancy(&pool).await;
    let sp = Uuid::from_u128(0x91);
    let tag = Uuid::from_u128(0x92);
    let foreign_tag = Uuid::from_u128(0x93);
    let t = Uuid::from_u128(0x94);
    let mut tx = pool.begin().await.unwrap();
    apply(&mut tx, sprint(sp, P1, None, "2026-10-05", "2026-10-19")).await.unwrap();
    apply(&mut tx, task(t, P1, Some(sp))).await.unwrap();
    for (id, project_id) in [(tag, P1), (foreign_tag, P2)] {
        sqlx::query("INSERT INTO tags (id, project_id, title, color) VALUES ($1,$2,'Default','#334155')")
            .bind(id).bind(project_id).execute(&mut *tx).await.unwrap();
    }
    assert_eq!(apply(&mut tx, Op::SprintSetDefaults {
        sprint_id: sp, default_assignee_id: Some(U), default_tag_ids: vec![tag, tag],
    }).await.unwrap(), Some(P1));
    let assignee: Option<Uuid> = sqlx::query_scalar("SELECT default_assignee_id FROM sprints WHERE id=$1")
        .bind(sp).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(assignee, Some(U));
    let tags: Vec<Uuid> = sqlx::query_scalar("SELECT tag_id FROM sprint_default_tags WHERE sprint_id=$1")
        .bind(sp).fetch_all(&mut *tx).await.unwrap();
    assert_eq!(tags, vec![tag]);
    // Editing defaults doesn't retroactively attach tags to member tasks.
    let existing_tags: i64 = sqlx::query_scalar("SELECT count(*) FROM task_tags WHERE task_id=$1")
        .bind(t).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(existing_tags, 0);
    tx.commit().await.unwrap();
    let fetched = fira_api::db::list_sprints_in_scope(&pool, &[P1]).await.unwrap();
    let fetched = fetched.iter().find(|s| s.id == sp).unwrap();
    assert_eq!(fetched.default_assignee_id, Some(U));
    assert_eq!(fetched.default_tag_ids, vec![tag]);
    let mut tx = pool.begin().await.unwrap();
    assert!(apply(&mut tx, Op::SprintSetDefaults {
        sprint_id: sp, default_assignee_id: None, default_tag_ids: vec![foreign_tag],
    }).await.unwrap_err().to_string().contains("cross-project"));
    assert!(apply(&mut tx, Op::SprintSetDefaults {
        sprint_id: sp, default_assignee_id: Some(Uuid::from_u128(0x95)), default_tag_ids: vec![],
    }).await.unwrap_err().to_string().contains("active project member"));
    apply(&mut tx, Op::TagDelete { tag_id: tag }).await.unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM sprint_default_tags WHERE sprint_id=$1")
        .bind(sp).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(remaining, 0);
    apply(&mut tx, Op::SprintSetDefaults {
        sprint_id: sp, default_assignee_id: None, default_tag_ids: vec![],
    }).await.unwrap();
    tx.commit().await.unwrap();
    let fetched = fira_api::db::list_sprints_in_scope(&pool, &[P1]).await.unwrap();
    let fetched = fetched.iter().find(|s| s.id == sp).unwrap();
    assert_eq!(fetched.default_assignee_id, None);
    assert!(fetched.default_tag_ids.is_empty());
}
