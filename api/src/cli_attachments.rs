// task-cli attachments (sprint 35): upload, replace, delete and download a
// task's attachments with an automation token.
//
// The CLI treats a task's attachments as a set of filename + content hash.
// Writes are keyed by filename and guarded by the attachment *id* the CLI
// saw in its preview (`If-Match`), or by "no attachment with this name yet"
// (`If-None-Match: *`). The id, not the hash, is the precondition, so rows
// uploaded before hashes existed still work.
//
// A replace is insert-new + delete-old in one transaction, recorded as the
// same `task.add_attachment` / `task.remove_attachment` ops the browser
// routes produce, so open tabs update through the change feed. Storage
// files are written before the transaction (and removed again if it
// fails) and old ones are deleted only after commit, so a failure never
// leaves a row pointing at a missing file.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::cli_api::{sha256_hex, CliCtx};
use crate::ensure_scope::{ensure_attachment_in_scope, ensure_task_in_scope};
use crate::models::Attachment;
use crate::storage::StorageBackend;
use crate::{db, ops, AppState};

/// Same limit as the browser upload route.
pub const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

/// What the CLI sees of an attachment.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CliAttachment {
    pub id: Uuid,
    pub filename: String,
    /// `None` only if the stored file could not be read to hash it.
    pub sha256: Option<String>,
    pub size: i64,
    pub content_type: String,
}

impl From<&Attachment> for CliAttachment {
    fn from(a: &Attachment) -> Self {
        CliAttachment {
            id: a.id,
            filename: a.filename.clone(),
            sha256: a.sha256.clone(),
            size: a.size,
            content_type: a.content_type.clone(),
        }
    }
}

/// CLI filenames need no escaping in Markdown and pass the browser
/// route's `sanitize_filename` unchanged.
pub fn valid_cli_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 120
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Image types that may render inline. Everything else is served as a
/// download, so uploaded HTML or SVG can never run same-origin.
pub fn is_inline_image(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    matches!(ct.as_str(), "image/png" | "image/jpeg" | "image/gif" | "image/webp")
}

/// Response headers for serving an attachment's bytes.
pub fn download_headers(a: &Attachment) -> HeaderMap {
    let mut h = HeaderMap::new();
    let inline = is_inline_image(&a.content_type);
    // The real type stays: the UI fetches into a blob and previews PDFs
    // and videos by it. Navigation to the URL is what the headers guard.
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&a.content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // Even if something does render it, it gets no origin and no scripts.
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox; default-src 'none'"));
    if !inline {
        // ASCII-only fallback name; the UI downloads by blob with its own name.
        let safe: String = a
            .filename
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
            .collect();
        if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{safe}\"")) {
            h.insert(header::CONTENT_DISPOSITION, v);
        }
    }
    h
}

/// Attachment rows of these tasks, with missing hashes filled in: the file
/// is read once, hashed, and the hash stored.
pub async fn attachments_for_tasks(
    pool: &PgPool,
    storage: &StorageBackend,
    task_ids: &[Uuid],
) -> sqlx::Result<Vec<Attachment>> {
    let mut rows: Vec<Attachment> = sqlx::query_as(
        "SELECT id, task_id, filename, storage_path, content_type, size, sha256, created_at
         FROM attachments WHERE task_id = ANY($1) ORDER BY filename, created_at, id",
    )
    .bind(task_ids)
    .fetch_all(pool)
    .await?;
    for a in rows.iter_mut().filter(|a| a.sha256.is_none()) {
        match storage.read_file(&a.storage_path).await {
            Ok(data) => {
                let h = sha256_hex(&data);
                sqlx::query("UPDATE attachments SET sha256 = $1 WHERE id = $2 AND sha256 IS NULL")
                    .bind(&h)
                    .bind(a.id)
                    .execute(pool)
                    .await?;
                a.sha256 = Some(h);
            }
            Err(e) => tracing::warn!("cannot hash attachment {} ({}): {e:?}", a.id, a.storage_path),
        }
    }
    Ok(rows)
}

/// Guard for a write to one filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentPre {
    /// `If-Match: <id>`: the attachment with this name must be this one.
    Is(Uuid),
    /// `If-None-Match: *`: no attachment with this name may exist.
    Absent,
}

#[derive(Debug)]
pub enum AttachmentError {
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    /// The precondition failed: someone changed it since the preview.
    Stale { current: Option<Uuid> },
    /// Two attachments share the filename; resolve it in the UI.
    Ambiguous,
    TooLarge,
    Internal(String),
}

impl From<sqlx::Error> for AttachmentError {
    fn from(e: sqlx::Error) -> Self {
        AttachmentError::Internal(format!("database: {e}"))
    }
}

fn json_error(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

impl IntoResponse for AttachmentError {
    fn into_response(self) -> Response {
        use serde_json::json;
        match self {
            AttachmentError::Forbidden(m) => json_error(StatusCode::FORBIDDEN, json!({"error": m})),
            AttachmentError::NotFound(m) => json_error(StatusCode::NOT_FOUND, json!({"error": m})),
            AttachmentError::BadRequest(m) => json_error(StatusCode::BAD_REQUEST, json!({"error": m})),
            AttachmentError::Stale { current } => json_error(
                StatusCode::CONFLICT,
                json!({"error": "the attachment changed in Fira since the preview; nothing was written", "stale": true, "current": current}),
            ),
            AttachmentError::Ambiguous => json_error(
                StatusCode::CONFLICT,
                json!({"error": "the task has two attachments with this filename; delete or rename one in Fira first", "ambiguous": true}),
            ),
            AttachmentError::TooLarge => json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": format!("attachments are limited to {} MB", MAX_ATTACHMENT_BYTES / 1024 / 1024)}),
            ),
            AttachmentError::Internal(m) => {
                tracing::warn!("cli attachment error: {m}");
                json_error(StatusCode::SERVICE_UNAVAILABLE, json!({"error": "attachment write failed; nothing was changed, retry the command"}))
            }
        }
    }
}

#[derive(Serialize, Debug)]
pub struct PutResponse {
    pub attachment: CliAttachment,
    /// False when the stored file already had this content.
    pub changed: bool,
}

fn parse_pre(headers: &HeaderMap) -> Result<AttachmentPre, AttachmentError> {
    let get = |h: header::HeaderName| headers.get(h).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string());
    match (get(header::IF_MATCH), get(header::IF_NONE_MATCH)) {
        (Some(m), None) => m
            .trim_matches('"')
            .parse()
            .map(AttachmentPre::Is)
            .map_err(|_| AttachmentError::BadRequest(format!("If-Match must be an attachment id, got {m:?}"))),
        (None, Some(n)) if n == "*" => Ok(AttachmentPre::Absent),
        _ => Err(AttachmentError::BadRequest(
            "send exactly one of If-Match: <attachment id> or If-None-Match: *".into(),
        )),
    }
}

/// Lock the task (serialises concurrent writes to its attachments) and
/// return its project and the rows with this filename.
async fn lock_named(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &CliCtx,
    task_id: Uuid,
    filename: &str,
) -> Result<(Uuid, Vec<Attachment>), AttachmentError> {
    let project_id = ensure_task_in_scope(tx, ctx.user_id, ctx.workspace_id, task_id)
        .await
        .map_err(|_| AttachmentError::NotFound("task not found".into()))?;
    sqlx::query("SELECT 1 FROM tasks WHERE id = $1 FOR UPDATE")
        .bind(task_id)
        .execute(&mut **tx)
        .await?;
    let rows: Vec<Attachment> = sqlx::query_as(
        "SELECT id, task_id, filename, storage_path, content_type, size, sha256, created_at
         FROM attachments WHERE task_id = $1 AND filename = $2 ORDER BY created_at, id",
    )
    .bind(task_id)
    .bind(filename)
    .fetch_all(&mut **tx)
    .await?;
    Ok((project_id, rows))
}

fn check_write(ctx: &CliCtx, filename: &str) -> Result<(), AttachmentError> {
    if !ctx.can_write {
        return Err(AttachmentError::Forbidden(
            "this token is read-only; create a write token in Fira account settings".into(),
        ));
    }
    if !valid_cli_filename(filename) {
        return Err(AttachmentError::BadRequest(format!(
            "invalid attachment filename {filename:?}: use letters, digits, '.', '_' and '-' only"
        )));
    }
    Ok(())
}

async fn stored_hash(storage: &StorageBackend, a: &Attachment) -> Option<String> {
    match &a.sha256 {
        Some(h) => Some(h.clone()),
        None => storage.read_file(&a.storage_path).await.ok().map(|d| sha256_hex(&d)),
    }
}

/// Create or replace the attachment `filename` of `task_id`.
#[allow(clippy::too_many_arguments)]
pub async fn put_attachment(
    pool: &PgPool,
    storage: &StorageBackend,
    ctx: &CliCtx,
    task_id: Uuid,
    filename: &str,
    pre: AttachmentPre,
    content_type: &str,
    data: &[u8],
) -> Result<PutResponse, AttachmentError> {
    check_write(ctx, filename)?;
    if data.len() > MAX_ATTACHMENT_BYTES {
        return Err(AttachmentError::TooLarge);
    }
    let hash = sha256_hex(data);
    let mut tx = pool.begin().await?;
    let (project_id, rows) = lock_named(&mut tx, ctx, task_id, filename).await?;
    if rows.len() > 1 {
        return Err(AttachmentError::Ambiguous);
    }
    let old = rows.into_iter().next();

    // Already this content: a retry after a lost response, or someone
    // uploaded the same file. Nothing to write either way.
    if let Some(o) = &old {
        if stored_hash(storage, o).await.as_deref() == Some(hash.as_str()) {
            return Ok(PutResponse { attachment: CliAttachment::from(o), changed: false });
        }
    }
    match (pre, &old) {
        (AttachmentPre::Absent, None) => {}
        (AttachmentPre::Is(id), Some(o)) if o.id == id => {}
        (_, o) => return Err(AttachmentError::Stale { current: o.as_ref().map(|o| o.id) }),
    }

    let id = Uuid::new_v4();
    let ext = filename.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).filter(|e| !e.is_empty() && e.len() <= 16).unwrap_or_else(|| "bin".into());
    let storage_path = format!("{project_id}/{task_id}/{id}.{ext}");
    let content_type = if content_type.trim().is_empty() { "application/octet-stream" } else { content_type.trim() };
    let new = Attachment {
        id,
        task_id,
        filename: filename.to_string(),
        storage_path: storage_path.clone(),
        content_type: content_type.to_string(),
        size: data.len() as i64,
        sha256: Some(hash),
        created_at: Utc::now(),
    };
    storage
        .write_file(&storage_path, data)
        .await
        .map_err(|e| AttachmentError::Internal(format!("storage write {storage_path}: {e:?}")))?;

    let result: Result<(), AttachmentError> = async {
        db::insert_attachment(&mut tx, new.clone()).await?;
        let kind = "task.add_attachment";
        let payload = serde_json::json!({ "kind": kind, "task_id": task_id, "attachment": &new });
        ops::record_synthesized_op(&mut tx, ctx.user_id, ctx.workspace_id, kind, payload, Some(project_id)).await?;
        if let Some(o) = &old {
            db::delete_attachment(&mut tx, o.id).await?;
            let kind = "task.remove_attachment";
            let payload = serde_json::json!({ "kind": kind, "task_id": task_id, "attachment": o });
            ops::record_synthesized_op(&mut tx, ctx.user_id, ctx.workspace_id, kind, payload, Some(project_id)).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = storage.delete_file(&storage_path).await;
        return Err(e);
    }
    if let Some(o) = &old {
        if let Err(e) = storage.delete_file(&o.storage_path).await {
            tracing::warn!("replaced attachment {}: old file {} not deleted: {e:?}", o.id, o.storage_path);
        }
    }
    Ok(PutResponse { attachment: CliAttachment::from(&new), changed: true })
}

/// Delete the attachment `filename` of `task_id`, which must be `expected`.
pub async fn delete_attachment(
    pool: &PgPool,
    storage: &StorageBackend,
    ctx: &CliCtx,
    task_id: Uuid,
    filename: &str,
    expected: Uuid,
) -> Result<(), AttachmentError> {
    check_write(ctx, filename)?;
    let mut tx = pool.begin().await?;
    let (project_id, rows) = lock_named(&mut tx, ctx, task_id, filename).await?;
    if rows.len() > 1 {
        return Err(AttachmentError::Ambiguous);
    }
    let Some(o) = rows.into_iter().next().filter(|o| o.id == expected) else {
        return Err(AttachmentError::Stale { current: None });
    };
    db::delete_attachment(&mut tx, o.id).await?;
    let kind = "task.remove_attachment";
    let payload = serde_json::json!({ "kind": kind, "task_id": task_id, "attachment": &o });
    ops::record_synthesized_op(&mut tx, ctx.user_id, ctx.workspace_id, kind, payload, Some(project_id)).await?;
    tx.commit().await?;
    if let Err(e) = storage.delete_file(&o.storage_path).await {
        tracing::warn!("deleted attachment {}: file {} not deleted: {e:?}", o.id, o.storage_path);
    }
    Ok(())
}

pub async fn read_attachment(
    pool: &PgPool,
    storage: &StorageBackend,
    ctx: &CliCtx,
    id: Uuid,
) -> Result<(Attachment, Vec<u8>), AttachmentError> {
    ensure_attachment_in_scope(pool, ctx.user_id, ctx.workspace_id, id)
        .await
        .map_err(|_| AttachmentError::NotFound("attachment not found".into()))?;
    let a = db::get_attachment(pool, id).await?;
    let data = storage
        .read_file(&a.storage_path)
        .await
        .map_err(|e| AttachmentError::Internal(format!("storage read {}: {e:?}", a.storage_path)))?;
    Ok((a, data))
}

// ---- handlers ----

pub async fn put_handler(
    State(s): State<AppState>,
    ctx: CliCtx,
    Path((task_id, filename)): Path<(Uuid, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PutResponse>, AttachmentError> {
    let pre = parse_pre(&headers)?;
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    Ok(Json(put_attachment(&s.pool, &s.storage, &ctx, task_id, &filename, pre, ct, &body).await?))
}

pub async fn delete_handler(
    State(s): State<AppState>,
    ctx: CliCtx,
    Path((task_id, filename)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AttachmentError> {
    let AttachmentPre::Is(expected) = parse_pre(&headers)? else {
        return Err(AttachmentError::BadRequest("a delete needs If-Match: <attachment id>".into()));
    };
    delete_attachment(&s.pool, &s.storage, &ctx, task_id, &filename, expected).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_handler(
    State(s): State<AppState>,
    ctx: CliCtx,
    Path(id): Path<Uuid>,
) -> Result<(HeaderMap, Vec<u8>), AttachmentError> {
    let (a, data) = read_attachment(&s.pool, &s.storage, &ctx, id).await?;
    Ok((download_headers(&a), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames() {
        for ok in ["layout.png", "spec-v2.pdf", "a_b.tar.gz", "README"] {
            assert!(valid_cli_filename(ok), "{ok}");
        }
        for bad in ["", ".env", "a b.png", "ü.png", "../x", "a/b", "x\"y"] {
            assert!(!valid_cli_filename(bad), "{bad}");
        }
    }

    #[test]
    fn only_raster_images_render_inline() {
        assert!(is_inline_image("image/png"));
        assert!(is_inline_image("image/JPEG; charset=binary"));
        assert!(!is_inline_image("image/svg+xml"));
        assert!(!is_inline_image("text/html"));
    }
}
