// task-cli server support (sprint 34): revisions, the all-or-nothing
// apply, the existence check, and automation-token auth.
//
// Run with: cargo test --manifest-path api/Cargo.toml --test task_cli_api

use fira_api::cli_api::{
    apply_batch, fetch_state, load_token_ctx, ApplyError, ApplyRequest, CliCtx, FetchRequest,
    Precondition,
};
use fira_api::ops::OpEnvelope;
use fira_api::storage::{LocalStorage, StorageBackend};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const U: Uuid = Uuid::from_u128(0x11);
const OTHER: Uuid = Uuid::from_u128(0x12);
const WS: Uuid = Uuid::from_u128(0x22);
const P1: Uuid = Uuid::from_u128(0x33);
const P2: Uuid = Uuid::from_u128(0x34);

fn storage() -> StorageBackend {
    StorageBackend::Local(LocalStorage::new("/tmp/fira-test-storage".into()))
}

fn ctx(can_write: bool) -> CliCtx {
    CliCtx {
        token_id: Uuid::nil(),
        user_id: U,
        workspace_id: WS,
        can_write,
    }
}

async fn tenancy(pool: &PgPool) {
    for (id, email) in [(U, "m@e.dev"), (OTHER, "o@e.dev")] {
        sqlx::query("INSERT INTO users (id, email, name, initials) VALUES ($1,$2,'N','NN')")
            .bind(id).bind(email).execute(pool).await.unwrap();
    }
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

fn env(payload: serde_json::Value) -> OpEnvelope {
    OpEnvelope { op_id: Uuid::new_v4().to_string(), payload }
}

fn task_create(id: Uuid, project: Uuid) -> serde_json::Value {
    json!({"kind": "task.create", "task": {
        "id": id, "project_id": project, "title": "T", "section": "later",
        "status": "todo", "source": "local"
    }})
}

async fn apply(pool: &PgPool, pres: Vec<Precondition>, ops: Vec<OpEnvelope>) -> Result<(), ApplyError> {
    apply_batch(pool, &ctx(true), ApplyRequest { project_id: P1, preconditions: pres, ops }, &storage())
        .await
        .map(|_| ())
}

async fn rev(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT revision FROM tasks WHERE id = $1").bind(id).fetch_one(pool).await.unwrap()
}

fn pre(id: Uuid, revision: Option<i64>) -> Precondition {
    Precondition { kind: "task".into(), id, revision, order: None }
}

#[sqlx::test]
async fn revision_tracks_managed_fields_and_children(pool: PgPool) {
    tenancy(&pool).await;
    let t = Uuid::new_v4();
    apply(&pool, vec![pre(t, None)], vec![env(task_create(t, P1))]).await.unwrap();

    let r0 = rev(&pool, t).await;
    sqlx::query("UPDATE tasks SET sort_key = 'Z', updated_at = now() WHERE id = $1")
        .bind(t).execute(&pool).await.unwrap();
    assert_eq!(rev(&pool, t).await, r0, "reorder must not bump");

    sqlx::query("UPDATE tasks SET title = 'U' WHERE id = $1").bind(t).execute(&pool).await.unwrap();
    let r1 = rev(&pool, t).await;
    assert!(r1 > r0);

    sqlx::query("INSERT INTO subtasks (id, task_id, title) VALUES ($1,$2,'s')")
        .bind(Uuid::new_v4()).bind(t).execute(&pool).await.unwrap();
    let r2 = rev(&pool, t).await;
    assert!(r2 > r1, "subtask insert bumps parent");

    let tag = Uuid::new_v4();
    sqlx::query("INSERT INTO tags (id, project_id, title, color) VALUES ($1,$2,'x','#000000')")
        .bind(tag).bind(P1).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO task_tags (task_id, tag_id) VALUES ($1,$2)")
        .bind(t).bind(tag).execute(&pool).await.unwrap();
    assert!(rev(&pool, t).await > r2, "tag link bumps parent");
}

#[sqlx::test]
async fn stale_precondition_rejects_whole_batch(pool: PgPool) {
    tenancy(&pool).await;
    let t = Uuid::new_v4();
    apply(&pool, vec![], vec![env(task_create(t, P1))]).await.unwrap();
    let seen = rev(&pool, t).await;
    // Someone edits in the UI between preview and write.
    sqlx::query("UPDATE tasks SET title = 'web edit' WHERE id = $1").bind(t).execute(&pool).await.unwrap();

    let new_task = Uuid::new_v4();
    let err = apply(
        &pool,
        vec![pre(t, Some(seen)), pre(new_task, None)],
        vec![
            env(json!({"kind": "task.set_title", "task_id": t, "title": "cli edit"})),
            env(task_create(new_task, P1)),
        ],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ApplyError::Conflicts(ref c) if c.len() == 1 && c[0].id == t));
    let title: String = sqlx::query_scalar("SELECT title FROM tasks WHERE id = $1")
        .bind(t).fetch_one(&pool).await.unwrap();
    assert_eq!(title, "web edit");
    let created: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks WHERE id = $1)")
        .bind(new_task).fetch_one(&pool).await.unwrap();
    assert!(!created, "nothing in the batch may apply");
}

#[sqlx::test]
async fn failing_op_rolls_back_earlier_ops(pool: PgPool) {
    tenancy(&pool).await;
    let a = Uuid::new_v4();
    let err = apply(
        &pool,
        vec![],
        vec![
            env(task_create(a, P1)),
            env(json!({"kind": "task.set_title", "task_id": Uuid::new_v4(), "title": "x"})),
        ],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ApplyError::Rejected { index: 1, .. }), "{err:?}");
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks WHERE id = $1)")
        .bind(a).fetch_one(&pool).await.unwrap();
    assert!(!exists);
}

#[sqlx::test]
async fn retry_with_same_op_ids_is_a_noop(pool: PgPool) {
    tenancy(&pool).await;
    let t = Uuid::new_v4();
    let ops = || vec![
        OpEnvelope { op_id: "op-create".into(), payload: task_create(t, P1) },
        OpEnvelope { op_id: "op-sub".into(), payload: json!({"kind": "subtask.create", "subtask": {
            "id": Uuid::from_u128(0x99), "task_id": t, "title": "s"}}) },
    ];
    let r1 = apply_batch(&pool, &ctx(true), ApplyRequest { project_id: P1, preconditions: vec![], ops: ops() }, &storage()).await.unwrap();
    assert_eq!(r1.applied, 2);
    let r2 = apply_batch(&pool, &ctx(true), ApplyRequest { project_id: P1, preconditions: vec![], ops: ops() }, &storage()).await.unwrap();
    assert_eq!((r2.applied, r2.already_applied), (0, 2));
}

#[sqlx::test]
async fn deletes_and_cross_project_ops_are_rejected(pool: PgPool) {
    tenancy(&pool).await;
    let t = Uuid::new_v4();
    apply(&pool, vec![], vec![env(task_create(t, P1))]).await.unwrap();
    let err = apply(&pool, vec![], vec![env(json!({"kind": "task.delete", "task_id": t}))]).await.unwrap_err();
    assert!(matches!(err, ApplyError::Rejected { ref message, .. } if message.contains("not allowed")));

    let other = Uuid::new_v4();
    let err = apply(&pool, vec![], vec![env(task_create(other, P2))]).await.unwrap_err();
    assert!(matches!(err, ApplyError::Rejected { ref message, .. } if message.contains("different project")));
}

#[sqlx::test]
async fn read_only_token_cannot_apply(pool: PgPool) {
    tenancy(&pool).await;
    let err = apply_batch(
        &pool,
        &ctx(false),
        ApplyRequest { project_id: P1, preconditions: vec![], ops: vec![env(task_create(Uuid::new_v4(), P1))] },
        &storage(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ApplyError::Forbidden(_)));
}

#[sqlx::test]
async fn existence_tells_deleted_from_never_and_other_project(pool: PgPool) {
    tenancy(&pool).await;
    let deleted = Uuid::new_v4();
    let elsewhere = Uuid::new_v4();
    let never = Uuid::new_v4();
    apply(&pool, vec![], vec![env(task_create(deleted, P1))]).await.unwrap();
    // The web client deletes through /ops; replicate its log row.
    {
        let mut tx = pool.begin().await.unwrap();
        let mut pid = None;
        fira_api::ops::apply_payload(&mut tx, U, WS,
            serde_json::from_value(json!({"kind": "task.delete", "task_id": deleted})).unwrap(),
            &mut pid, &storage()).await.unwrap();
        sqlx::query("INSERT INTO processed_ops (op_id, user_id, kind, payload, project_id, workspace_id)
                     VALUES ('del', $1, 'task.delete', $2, $3, $4)")
            .bind(U).bind(json!({"kind": "task.delete", "task_id": deleted})).bind(P1).bind(WS)
            .execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
    }
    apply_batch(&pool, &ctx(true), ApplyRequest { project_id: P2, preconditions: vec![], ops: vec![env(task_create(elsewhere, P2))] }, &storage()).await.unwrap();

    let res = fetch_state(&pool, &storage(), &ctx(false), &FetchRequest {
        project_id: P1, sprint_ids: vec![], task_ids: vec![deleted, elsewhere, never], all_sprints: false,
    }).await.unwrap();
    let state = |id| res.missing.iter().find(|m| m.id == id).unwrap().state;
    assert_eq!(state(deleted), "deleted");
    assert_eq!(state(elsewhere), "other_project");
    assert_eq!(state(never), "never");
}

#[sqlx::test]
async fn tokens_are_hashed_and_follow_membership(pool: PgPool) {
    tenancy(&pool).await;
    let token = "fira_testtoken";
    sqlx::query("INSERT INTO automation_tokens (id, user_id, workspace_id, name, token_hash, token_prefix, can_write)
                 VALUES ($1,$2,$3,'laptop',$4,'fira_t',true)")
        .bind(Uuid::new_v4()).bind(U).bind(WS).bind(fira_api::cli_api::hash_token(token))
        .execute(&pool).await.unwrap();
    let stored: String = sqlx::query_scalar("SELECT token_hash FROM automation_tokens").fetch_one(&pool).await.unwrap();
    assert_ne!(stored, token);

    let c = load_token_ctx(&pool, token).await.unwrap().expect("valid token");
    assert_eq!((c.user_id, c.workspace_id, c.can_write), (U, WS, true));
    assert!(load_token_ctx(&pool, "fira_wrong").await.unwrap().is_none());

    sqlx::query("UPDATE workspace_members SET removed_at = now() WHERE user_id = $1")
        .bind(U).execute(&pool).await.unwrap();
    assert!(load_token_ctx(&pool, token).await.unwrap().is_none(), "removed member loses access");

    sqlx::query("UPDATE workspace_members SET removed_at = NULL WHERE user_id = $1")
        .bind(U).execute(&pool).await.unwrap();
    sqlx::query("UPDATE automation_tokens SET revoked_at = now()").execute(&pool).await.unwrap();
    assert!(load_token_ctx(&pool, token).await.unwrap().is_none(), "revoked token rejected");
}

#[sqlx::test]
async fn sprint_description_round_trips_and_bumps_revision(pool: PgPool) {
    tenancy(&pool).await;
    let s = Uuid::new_v4();
    apply(&pool, vec![], vec![env(json!({"kind": "sprint.create", "sprint": {
        "id": s, "project_id": P1, "title": "S", "sort_key": "M"}}))]).await.unwrap();
    let r0: i64 = sqlx::query_scalar("SELECT revision FROM sprints WHERE id = $1").bind(s).fetch_one(&pool).await.unwrap();
    apply(
        &pool,
        vec![Precondition { kind: "sprint".into(), id: s, revision: Some(r0), order: None }],
        vec![env(json!({"kind": "sprint.set_description", "sprint_id": s, "description_md": "Goal.\n\nMore."}))],
    )
    .await
    .unwrap();
    let snap = fetch_state(&pool, &storage(), &ctx(false), &FetchRequest {
        project_id: P1, sprint_ids: vec![s], task_ids: vec![], all_sprints: false,
    }).await.unwrap();
    assert_eq!(snap.sprints[0].description_md, "Goal.\n\nMore.");
    assert!(snap.sprints[0].revision > r0, "the CLI manages the description");
}

#[sqlx::test]
async fn task_reorder_is_allowed_and_task_order_follows_it(pool: PgPool) {
    tenancy(&pool).await;
    let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    apply(&pool, vec![], vec![env(task_create(a, P1)), env(task_create(b, P1)), env(task_create(c, P1))]).await.unwrap();
    let ra = rev(&pool, a).await;
    apply(&pool, vec![], vec![env(json!({"kind": "task.reorder", "project_id": P1, "ordered": [c, a, b]}))]).await.unwrap();
    let snap = fetch_state(&pool, &storage(), &ctx(false), &FetchRequest {
        project_id: P1, sprint_ids: vec![], task_ids: vec![], all_sprints: false,
    }).await.unwrap();
    assert_eq!(snap.task_order, vec![c, a, b]);
    assert_eq!(rev(&pool, a).await, ra, "order is not a revisioned field");
    // Byte order, as the web compares: '0…' sorts before 'M'.
    let d = Uuid::new_v4();
    apply(&pool, vec![], vec![env(task_create(d, P1))]).await.unwrap();
    sqlx::query("UPDATE tasks SET sort_key = 'M' WHERE id = $1").bind(d).execute(&pool).await.unwrap();
    let snap = fetch_state(&pool, &storage(), &ctx(false), &FetchRequest {
        project_id: P1, sprint_ids: vec![], task_ids: vec![], all_sprints: false,
    }).await.unwrap();
    assert_eq!(snap.task_order, vec![c, a, b, d]);
}

#[sqlx::test]
async fn task_order_precondition_rejects_a_concurrent_reorder(pool: PgPool) {
    tenancy(&pool).await;
    let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    apply(&pool, vec![], vec![env(task_create(a, P1)), env(task_create(b, P1)), env(task_create(c, P1))]).await.unwrap();
    let order = |o: Vec<Uuid>| Precondition { kind: "task_order".into(), id: P1, revision: None, order: Some(o) };
    let fetched = |pool: PgPool| async move {
        fetch_state(&pool, &storage(), &ctx(false), &FetchRequest {
            project_id: P1, sprint_ids: vec![], task_ids: vec![], all_sprints: false,
        }).await.unwrap().task_order
    };
    let seen = fetched(pool.clone()).await;
    // Someone drags in the web UI after the CLI's fetch.
    apply(&pool, vec![], vec![env(json!({"kind": "task.reorder", "project_id": P1, "ordered": [b, a, c]}))]).await.unwrap();
    let res = apply(&pool, vec![order(seen)], vec![env(json!({"kind": "task.reorder", "project_id": P1, "ordered": [c, b, a]}))]).await;
    assert!(matches!(res, Err(ApplyError::Conflicts(ref c)) if c.len() == 1 && c[0].kind == "task_order"), "{res:?}");
    assert_eq!(fetched(pool.clone()).await, vec![b, a, c], "nothing applied");
    // Against the current order it goes through.
    let seen = fetched(pool.clone()).await;
    apply(&pool, vec![order(seen)], vec![env(json!({"kind": "task.reorder", "project_id": P1, "ordered": [c, b, a]}))]).await.unwrap();
    assert_eq!(fetched(pool.clone()).await, vec![c, b, a]);
    // A task created since the fetch changes the order too.
    let seen = fetched(pool.clone()).await;
    apply(&pool, vec![], vec![env(task_create(Uuid::new_v4(), P1))]).await.unwrap();
    let res = apply(&pool, vec![order(seen)], vec![]).await;
    assert!(matches!(res, Err(ApplyError::Conflicts(_))), "{res:?}");
}
