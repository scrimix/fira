// task-cli attachments (sprint 35): set semantics by filename + hash,
// id preconditions, replace/delete ops, lazy hashing, download headers.
//
// Run with: cargo test --manifest-path api/Cargo.toml --test task_cli_attachments

use fira_api::cli_api::{apply_batch, fetch_state, sha256_hex, ApplyRequest, CliCtx, FetchRequest};
use fira_api::cli_attachments::{
    delete_attachment, download_headers, put_attachment, read_attachment, AttachmentError, AttachmentPre,
};
use fira_api::ops::OpEnvelope;
use fira_api::storage::{LocalStorage, StorageBackend};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const U: Uuid = Uuid::from_u128(0x11);
const WS: Uuid = Uuid::from_u128(0x22);
const P1: Uuid = Uuid::from_u128(0x33);

fn storage_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("fira-test-storage-attachments")
}

fn storage() -> StorageBackend {
    StorageBackend::Local(LocalStorage::new(storage_dir().to_string_lossy().into_owned()))
}

fn ctx(can_write: bool) -> CliCtx {
    CliCtx { token_id: Uuid::nil(), user_id: U, workspace_id: WS, can_write }
}

async fn setup(pool: &PgPool) -> Uuid {
    sqlx::query("INSERT INTO users (id, email, name, initials) VALUES ($1,'m@e.dev','N','NN')")
        .bind(U).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO workspaces (id, title, is_personal, created_by) VALUES ($1,'WS',false,$2)")
        .bind(WS).bind(U).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1,$2,'owner')")
        .bind(WS).bind(U).execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO projects (id, workspace_id, title, icon, color, source, owner_id)
         VALUES ($1,$2,'Atlas','Compass','#0F766E','local',$3)",
    ).bind(P1).bind(WS).bind(U).execute(pool).await.unwrap();
    let t = Uuid::new_v4();
    let op = json!({"kind": "task.create", "task": {
        "id": t, "project_id": P1, "title": "T", "section": "later", "status": "todo", "source": "local"
    }});
    apply_batch(pool, &ctx(true), ApplyRequest {
        project_id: P1, preconditions: vec![],
        ops: vec![OpEnvelope { op_id: Uuid::new_v4().to_string(), payload: op }],
    }, &storage()).await.unwrap();
    t
}

async fn put(pool: &PgPool, t: Uuid, name: &str, pre: AttachmentPre, data: &[u8]) -> Result<(Uuid, bool), AttachmentError> {
    put_attachment(pool, &storage(), &ctx(true), t, name, pre, "image/png", data)
        .await
        .map(|r| (r.attachment.id, r.changed))
}

async fn ops_of(pool: &PgPool, kind: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM processed_ops WHERE kind = $1").bind(kind).fetch_one(pool).await.unwrap()
}

async fn fetch_atts(pool: &PgPool, t: Uuid) -> Vec<fira_api::cli_attachments::CliAttachment> {
    let res = fetch_state(pool, &storage(), &ctx(false), &FetchRequest {
        project_id: P1, sprint_ids: vec![], task_ids: vec![t], all_sprints: false,
    }).await.unwrap();
    res.tasks.into_iter().find(|x| x.id == t).unwrap().attachments
}

#[sqlx::test]
async fn create_same_replace_delete(pool: PgPool) {
    let t = setup(&pool).await;

    let (a1, changed) = put(&pool, t, "shot.png", AttachmentPre::Absent, b"one").await.unwrap();
    assert!(changed);
    let atts = fetch_atts(&pool, t).await;
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0].sha256.as_deref(), Some(sha256_hex(b"one").as_str()));

    // Same content: nothing written, even with a stale precondition (a
    // retry after a lost response).
    let (same, changed) = put(&pool, t, "shot.png", AttachmentPre::Absent, b"one").await.unwrap();
    assert_eq!((same, changed), (a1, false));
    assert_eq!(ops_of(&pool, "task.add_attachment").await, 1);

    // A second create of the same name with different content is stale.
    assert!(matches!(put(&pool, t, "shot.png", AttachmentPre::Absent, b"two").await, Err(AttachmentError::Stale { current: Some(c) }) if c == a1));

    // Replace: new row, old row and file gone, both ops recorded.
    let old_path: String = sqlx::query_scalar("SELECT storage_path FROM attachments WHERE id = $1").bind(a1).fetch_one(&pool).await.unwrap();
    let (a2, changed) = put(&pool, t, "shot.png", AttachmentPre::Is(a1), b"two").await.unwrap();
    assert!(changed && a2 != a1);
    assert!(!storage_dir().join(&old_path).exists());
    assert_eq!(ops_of(&pool, "task.remove_attachment").await, 1);
    let (_, data) = read_attachment(&pool, &storage(), &ctx(false), a2).await.unwrap();
    assert_eq!(data, b"two");

    // Replacing against the old id is stale now.
    assert!(matches!(put(&pool, t, "shot.png", AttachmentPre::Is(a1), b"three").await, Err(AttachmentError::Stale { .. })));

    // Delete needs the current id.
    assert!(matches!(delete_attachment(&pool, &storage(), &ctx(true), t, "shot.png", a1).await, Err(AttachmentError::Stale { .. })));
    delete_attachment(&pool, &storage(), &ctx(true), t, "shot.png", a2).await.unwrap();
    assert!(fetch_atts(&pool, t).await.is_empty());
    assert_eq!(ops_of(&pool, "task.remove_attachment").await, 2);
}

#[sqlx::test]
async fn read_only_tokens_and_bad_names_are_refused(pool: PgPool) {
    let t = setup(&pool).await;
    let r = put_attachment(&pool, &storage(), &ctx(false), t, "a.png", AttachmentPre::Absent, "", b"x").await;
    assert!(matches!(r, Err(AttachmentError::Forbidden(_))));
    let r = put(&pool, t, "a b.png", AttachmentPre::Absent, b"x").await;
    assert!(matches!(r, Err(AttachmentError::BadRequest(_))));
    let r = put(&pool, Uuid::new_v4(), "a.png", AttachmentPre::Absent, b"x").await;
    assert!(matches!(r, Err(AttachmentError::NotFound(_))));
}

#[sqlx::test]
async fn duplicate_names_are_ambiguous(pool: PgPool) {
    let t = setup(&pool).await;
    for _ in 0..2 {
        sqlx::query("INSERT INTO attachments (id, task_id, filename, storage_path, content_type, size) VALUES ($1,$2,'dup.png','x/y','image/png',1)")
            .bind(Uuid::new_v4()).bind(t).execute(&pool).await.unwrap();
    }
    let r = put(&pool, t, "dup.png", AttachmentPre::Absent, b"x").await;
    assert!(matches!(r, Err(AttachmentError::Ambiguous)));
}

#[sqlx::test]
async fn missing_hashes_are_filled_on_fetch(pool: PgPool) {
    let t = setup(&pool).await;
    let id = Uuid::new_v4();
    let path = format!("{P1}/{t}/{id}.png");
    storage().write_file(&path, b"legacy").await.unwrap();
    sqlx::query("INSERT INTO attachments (id, task_id, filename, storage_path, content_type, size) VALUES ($1,$2,'old.png',$3,'image/png',6)")
        .bind(id).bind(t).bind(&path).execute(&pool).await.unwrap();
    let atts = fetch_atts(&pool, t).await;
    assert_eq!(atts[0].sha256.as_deref(), Some(sha256_hex(b"legacy").as_str()));
    let stored: Option<String> = sqlx::query_scalar("SELECT sha256 FROM attachments WHERE id = $1").bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(stored, atts[0].sha256);
    // The legacy row (no hash at upload) still works as a precondition.
    let (_, changed) = put(&pool, t, "old.png", AttachmentPre::Is(id), b"new").await.unwrap();
    assert!(changed);
}

#[sqlx::test]
async fn html_is_served_as_a_download(pool: PgPool) {
    let t = setup(&pool).await;
    let r = put_attachment(&pool, &storage(), &ctx(true), t, "report.html", AttachmentPre::Absent, "text/html", b"<script>").await.unwrap();
    let a = fira_api::db::get_attachment(&pool, r.attachment.id).await.unwrap();
    let h = download_headers(&a);
    assert_eq!(h["content-type"], "text/html");
    assert!(h["content-security-policy"].to_str().unwrap().contains("sandbox"));
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(h["content-disposition"].to_str().unwrap().starts_with("attachment"));
    let png = put_attachment(&pool, &storage(), &ctx(true), t, "a.png", AttachmentPre::Absent, "image/png", b"p").await.unwrap();
    let a = fira_api::db::get_attachment(&pool, png.attachment.id).await.unwrap();
    let h = download_headers(&a);
    assert_eq!(h["content-type"], "image/png");
    assert!(h.get("content-disposition").is_none());
}
