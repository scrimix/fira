// Tags and tracks are project structure: only project leads/owners and
// workspace owners may create, rename, recolour, reorder or delete them.
// Members can still *use* them (tag a task, put a sprint on a track).
//
// Run with: cargo test --manifest-path api/Cargo.toml --test tag_track_authority

use fira_api::ops::{apply_payload, Op};
use fira_api::storage::{LocalStorage, StorageBackend};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const OWNER: Uuid = Uuid::from_u128(0x11);
const LEAD: Uuid = Uuid::from_u128(0x12);
const MEMBER: Uuid = Uuid::from_u128(0x13);
const WS: Uuid = Uuid::from_u128(0x22);
const P: Uuid = Uuid::from_u128(0x33);
const TAG: Uuid = Uuid::from_u128(0x44);
const TRACK: Uuid = Uuid::from_u128(0x55);

fn storage() -> StorageBackend {
    StorageBackend::Local(LocalStorage::new("/tmp/fira-test-storage".into()))
}

async fn setup(pool: &PgPool) {
    for (id, email) in [(OWNER, "o@e.dev"), (LEAD, "l@e.dev"), (MEMBER, "m@e.dev")] {
        sqlx::query("INSERT INTO users (id, email, name, initials) VALUES ($1,$2,'N','NN')")
            .bind(id).bind(email).execute(pool).await.unwrap();
    }
    sqlx::query("INSERT INTO workspaces (id, title, is_personal, created_by) VALUES ($1,'WS',false,$2)")
        .bind(WS).bind(OWNER).execute(pool).await.unwrap();
    for (id, role) in [(OWNER, "owner"), (LEAD, "member"), (MEMBER, "member")] {
        sqlx::query("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1,$2,$3)")
            .bind(WS).bind(id).bind(role).execute(pool).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO projects (id, workspace_id, title, icon, color, source, owner_id)
         VALUES ($1,$2,'Atlas','Compass','#0F766E','local',$3)",
    ).bind(P).bind(WS).bind(OWNER).execute(pool).await.unwrap();
    for (id, role) in [(LEAD, "lead"), (MEMBER, "member")] {
        sqlx::query("INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,$3)")
            .bind(P).bind(id).bind(role).execute(pool).await.unwrap();
    }
    sqlx::query("INSERT INTO tags (id, project_id, title, color) VALUES ($1,$2,'bug','#000000')")
        .bind(TAG).bind(P).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO tracks (id, project_id, title) VALUES ($1,$2,'Platform')")
        .bind(TRACK).bind(P).execute(pool).await.unwrap();
}

async fn run(pool: &PgPool, user: Uuid, op: serde_json::Value) -> anyhow::Result<()> {
    let op: Op = serde_json::from_value(op).unwrap();
    let mut tx = pool.begin().await.unwrap();
    let mut pid = None;
    apply_payload(&mut tx, user, WS, op, &mut pid, &storage()).await?;
    tx.commit().await.unwrap();
    Ok(())
}

fn structure_ops(who: &str) -> Vec<serde_json::Value> {
    vec![
        json!({"kind": "tag.create", "tag": {"id": Uuid::new_v4(), "project_id": P, "title": format!("new-{who}"), "color": "#111111"}}),
        json!({"kind": "tag.set_title", "tag_id": TAG, "title": "defect"}),
        json!({"kind": "tag.set_color", "tag_id": TAG, "color": "#222222"}),
        json!({"kind": "track.create", "track": {"id": Uuid::new_v4(), "project_id": P, "title": format!("New {who}")}}),
        json!({"kind": "track.set_title", "track_id": TRACK, "title": "Core"}),
        json!({"kind": "track.set_color", "track_id": TRACK, "color": "#333333"}),
        json!({"kind": "track.reorder", "project_id": P, "ordered": [TRACK]}),
        json!({"kind": "tag.delete", "tag_id": TAG}),
        json!({"kind": "track.delete", "track_id": TRACK}),
    ]
}

#[sqlx::test]
async fn members_cannot_change_tags_or_tracks(pool: PgPool) {
    setup(&pool).await;
    for op in structure_ops("member") {
        let kind = op["kind"].clone();
        let err = run(&pool, MEMBER, op).await.expect_err(&format!("{kind} must be refused for a member"));
        assert!(err.to_string().contains("managed by project leads"), "{kind}: {err}");
    }
    let title: String = sqlx::query_scalar("SELECT title FROM tags WHERE id = $1").bind(TAG).fetch_one(&pool).await.unwrap();
    assert_eq!(title, "bug");
}

#[sqlx::test]
async fn leads_and_workspace_owners_can(pool: PgPool) {
    setup(&pool).await;
    for op in structure_ops("lead") {
        let kind = op["kind"].clone();
        run(&pool, LEAD, op).await.unwrap_or_else(|e| panic!("{kind} as lead: {e}"));
    }
    setup_again(&pool).await;
    for op in structure_ops("owner") {
        let kind = op["kind"].clone();
        run(&pool, OWNER, op).await.unwrap_or_else(|e| panic!("{kind} as workspace owner: {e}"));
    }
}

async fn setup_again(pool: &PgPool) {
    sqlx::query("INSERT INTO tags (id, project_id, title, color) VALUES ($1,$2,'bug','#000000')")
        .bind(TAG).bind(P).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO tracks (id, project_id, title) VALUES ($1,$2,'Platform')")
        .bind(TRACK).bind(P).execute(pool).await.unwrap();
}

#[sqlx::test]
async fn members_can_still_use_them(pool: PgPool) {
    setup(&pool).await;
    let task = Uuid::new_v4();
    let sprint = Uuid::new_v4();
    run(&pool, MEMBER, json!({"kind": "task.create", "task": {"id": task, "project_id": P, "title": "T",
        "section": "later", "status": "todo", "source": "local", "tag_ids": [TAG]}})).await.unwrap();
    run(&pool, MEMBER, json!({"kind": "task.set_tags", "task_id": task, "tag_ids": [TAG]})).await.unwrap();
    run(&pool, MEMBER, json!({"kind": "sprint.create", "sprint": {"id": sprint, "project_id": P, "title": "S", "track_id": TRACK}})).await.unwrap();
    run(&pool, MEMBER, json!({"kind": "sprint.set_defaults", "sprint_id": sprint, "default_assignee_id": null, "default_tag_ids": [TAG]})).await.unwrap();
}
