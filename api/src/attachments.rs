use axum::{
    Json, extract::{Multipart, Path, State}, http::HeaderValue,
};
use chrono::Utc;
use serde::{Serialize, Deserialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use crate::{auth::AuthCtx, db, ensure_scope::ensure_attachment_in_scope, ops, storage::StorageBackend};
use crate::error::{ApiError, ApiResult};
use crate::AppState;
use crate::models::Attachment;
use std::str::FromStr;
use crate::ensure_scope::ensure_task_in_scope;

#[derive(Deserialize, Serialize)]
pub struct UploadFileResponse {
    pub attachment_id: Uuid,
    pub storage_path: String,
}

pub async fn upload_attachment(State(state): State<AppState>, ctx: AuthCtx, Path(task_id): Path<Uuid>, mut multipart: Multipart)
    -> ApiResult<Json<UploadFileResponse>>
{
    let mut err_ctx = format!("upload_attachment[task_id={}]", task_id).to_string();
    
    let result: Result<Json<UploadFileResponse>, String> = async {
        let task = db::get_task(&state.pool, task_id)
            .await.map_err(|e| format!("Failed to get task: {}", e))?.ok_or_else(|| "Task not found")?;

        while let Some(field) = multipart.next_field()
            .await.map_err(|e| format!("Failed to read field: {}", e))?
        {
            // Extract fields
            let name = field.name()
                .ok_or_else(|| "Missing field name")?.to_string();
            err_ctx = format!("{}, field_name={}", err_ctx, name);
            
            let file_name = field.file_name()
                .ok_or_else(|| "Missing file name")?.to_string();
            let content_type = field.content_type()
                .ok_or_else(|| "Content type not found")?.to_string();
            let data = field.bytes()
                .await.map_err(|e| format!("Failed to read field bytes: {}", e))?;
            let file_size = data.len() as i64;

            if name == "file" {
                let id = Uuid::new_v4();
                let file_extension = file_name.split('.').last().unwrap_or("bin");
                let storage_name = format!("{}.{}", id, file_extension);
                let storage_path = format!("{}/{}/{}", task.project_id, task.id, storage_name);

                // Write to storage
                state.storage.write_file(&storage_path, &data)
                    .await.map_err(|e| format!("Failed to write file: {storage_path} to storage: {}", e))?;

                // Insert into DB
                let attachment = Attachment {
                    id,
                    task_id,
                    filename: file_name,
                    storage_path: storage_path.clone(),
                    content_type,
                    size: file_size,
                    created_at: Utc::now()
                };
                let mut tx = state.pool.begin()
                    .await.map_err(|e| format!("failed to get db tx {e}"))?;
                
                let _proj_id = ensure_task_in_scope(&mut tx, ctx.user.id, ctx.workspace_id, attachment.task_id)
                    .await.map_err(|e| format!("check failed for task in scope access: {e}"))?;

                db::insert_attachment(&mut tx, attachment.clone())
                    .await.map_err(|e| format!("failed to insert attachment: {e}"))?;

                let kind = "task.add_attachment";
                let payload = serde_json::json!({ "kind": kind, "task_id": task_id, "attachment": &attachment });
                ops::record_synthesized_op(&mut tx, ctx.user.id, ctx.workspace_id, kind, payload, Some(task.project_id))
                    .await.map_err(|e| format!("failed to record op: {e}"))?;

                tx.commit().await.map_err(|e| format!("failed to commit tx: {e}"))?;

                return Ok(Json(UploadFileResponse { attachment_id: id, storage_path }));
            }
        }
        return Err("No file field found".into());
    }.await;

    result.map_err(|e| ApiError::InternalServerError(format!("{}, error: {}", err_ctx, e)))
}

pub async fn get_attachment(State(state): State<AppState>, ctx: AuthCtx, Path(file_id): Path<String>)
    -> ApiResult<(axum::http::HeaderMap, Vec<u8>)>
{
    let err_ctx = format!("get_attachment[path: {file_id}]");
    let result: Result<(axum::http::HeaderMap, Vec<u8>), String> = async {
        // Get info about attachment, check in scope
        let file_id = Uuid::from_str(&file_id)
            .map_err(|e| format!("failed to get uuid: {e}"))?;
        let _proj_id = ensure_attachment_in_scope(&state.pool, ctx.user.id, ctx.workspace_id, file_id)
            .await.map_err(|e| format!("check failed for attachment in scope access: {e}"))?;
        let attachment = db::get_attachment(&state.pool, file_id)
            .await.map_err(|e| format!("failed to get attachment info: {e}"))?;

        // Read from storage
        let data = state.storage.read_file(&attachment.storage_path)
            .await.map_err(|e| format!("failed to read file: {} from storage: {e}", attachment.storage_path))?;
        
        // Prepare headers
        let mut headers = axum::http::HeaderMap::new();
        let content_type = HeaderValue::from_str(&attachment.content_type).map_err(|e| format!("content_type: {e}"))?;
        let content_length = HeaderValue::from_str(&attachment.size.to_string()).map_err(|e| format!("content_length: {e}"))?;
        headers.insert(axum::http::header::CONTENT_TYPE, content_type);
        headers.insert(axum::http::header::CONTENT_LENGTH, content_length);
        Ok((headers, data))
    }.await;

    result.map_err(|e| ApiError::InternalServerError(format!("{err_ctx} error: {e}")))
}

pub async fn delete_attachment(State(state): State<AppState>, ctx: AuthCtx, Path(file_id): Path<String>)
    -> ApiResult<()>
{
    let err_ctx = format!("delete_attachment [file_id: {file_id}]");

    let result: Result<(), String> = async {
        // Get info about attachment, check in scope
        let file_id = Uuid::from_str(&file_id)
            .map_err(|e| format!("failed to get uuid: {e}"))?;
        let project_id = ensure_attachment_in_scope(&state.pool, ctx.user.id, ctx.workspace_id, file_id)
            .await.map_err(|e| format!("check failed for attachment in scope access: {e}"))?;
        let attachment = db::get_attachment(&state.pool, file_id)
            .await.map_err(|e| format!("failed to get attachment info: {e}"))?;

        // Remove from storage
        state.storage.delete_file(&attachment.storage_path)
            .await.map_err(|e| format!("failed to delete file: {} from storage: {e}", attachment.storage_path))?;

        // Remove from db
        let mut tx = state.pool.begin()
                    .await.map_err(|e| format!("failed to get db tx {e}"))?;
        let rows_deleted = db::delete_attachment(&mut tx, file_id)
            .await.map_err(|e| format!("failed to remove attachment: {e}"))?;
        if !rows_deleted {
            return Err("attachment doesn't exist in db".to_string());
        }
        
        // Notify UI fro changes
        let kind = "task.remove_attachment";
        let payload = serde_json::json!({ "kind": kind, "task_id": attachment.task_id, "attachment": &attachment });
        ops::record_synthesized_op(&mut tx, ctx.user.id, ctx.workspace_id, kind, payload, Some(project_id))
            .await.map_err(|e| format!("failed to record op: {e}"))?;

        tx.commit().await.map_err(|e| format!("failed to commit tx: {e}"))?;

        Ok(())
    }.await;

    result.map_err(|e| ApiError::InternalServerError(format!("{err_ctx} error: {e}")))
}

pub async fn delete_task_attachments(tx: &mut Transaction<'_, Postgres>, storage: &StorageBackend, task_id: Uuid)
    -> anyhow::Result<()>
{
    let err_ctx = format!("delete_all_attachments_for_task [task_id: {task_id}]");

    let result: Result<(), String> = async {
        // Get info about attachments
        let attachments = db::list_attachments_for_task(&mut *tx, task_id)
            .await.map_err(|e| format!("failed to get attachments info: {e}"))?;

        // Remove from storage
        for attachment in &attachments {
            storage.delete_file(&attachment.storage_path)
                .await.map_err(|e| format!("failed to delete file: {} from storage: {e}", attachment.storage_path))?;
        }

        // Remove from db
        db::delete_attachments_for_task(&mut *tx, task_id)
            .await.map_err(|e| format!("failed to remove attachments: {e}"))?;

        Ok(())
    }.await;

    result.map_err(|e| anyhow::anyhow!("{err_ctx} error: {e}"))
}