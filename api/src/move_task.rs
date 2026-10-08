// Move a task to another project.
//
// `tasks.project_id` isn't a label — it's the scope key for
// authorization (`ensure_scope.rs`), for calendar visibility
// (`db::list_blocks_in_scope` joins blocks through the task's project),
// for the change feed (`processed_ops.project_id`), and for the four
// things a task points at: tags, track, sprint, Jira project. Moving a
// task moves all of that out from under it, so this is a REST endpoint
// with a confirm gate rather than an outbox op:
//
//   - it needs the user to see the consequences *before* the write, and
//     the outbox is fire-and-forget by construction;
//   - it spans two project scopes, and `ops::apply_payload` returns a
//     single `out_project_id` with nowhere to put the second.
//
// Same posture as attachments and project-member edits (see the README's
// note on how attachments bent the local-first shape).

use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::db;
use crate::gcal::urlencoding_encode;
use crate::ensure_scope::{ensure_task_in_scope, require_project_access};
use crate::error::{ApiError, ApiResult};
use crate::models::Task;
use crate::ops;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct MoveTaskBody {
    pub to_project_id: Uuid,
    /// Set by the client once the user has confirmed the impact dialog.
    /// Without it, a move that strands anyone is refused with 409 — a
    /// client running stale code can't skip the warning.
    #[serde(default)]
    pub acknowledge_access_loss: bool,
}

/// One person who can't see the target project. Returned in the 409 body
/// so the caller can render the warning even if its local state is stale;
/// the happy path computes the same set client-side and never reads this.
#[derive(Debug, Serialize)]
pub struct StrandedUser {
    pub user_id: Uuid,
    pub name: String,
    /// How many of their time blocks are on this task. Blocks aren't
    /// deleted — they stop being *visible*, because
    /// `list_blocks_in_scope` reaches them through the task's project.
    pub block_count: i64,
    pub is_assignee: bool,
}

#[derive(Debug, Serialize)]
pub struct MoveTaskResponse {
    pub task: Task,
}

pub async fn move_task(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(task_id): Path<Uuid>,
    Json(body): Json<MoveTaskBody>,
) -> ApiResult<Json<MoveTaskResponse>> {
    let mut tx = s.pool.begin().await?;

    // Both scope checks are workspace-pinned against the X-Workspace-Id
    // header, so a cross-workspace move can't be expressed here: the
    // source project must be in the header's workspace and so must the
    // target. That's deliberate — tags, members and invites are all
    // per-workspace, and moving across one is a much larger feature.
    let from_project_id = ensure_task_in_scope(&mut tx, ctx.user.id, ctx.workspace_id, task_id)
        .await
        .map_err(|_| ApiError::Forbidden)?;
    require_project_access(&mut tx, ctx.user.id, ctx.workspace_id, body.to_project_id)
        .await
        .map_err(|_| ApiError::Forbidden)?;

    if from_project_id == body.to_project_id {
        return Err(ApiError::BadRequest(
            "task is already in that project".into(),
        ));
    }

    // The client computes this same set locally to render its dialog and
    // sets the ack flag to what it actually showed the user. So this arm
    // fires exactly when the two disagree — someone's membership changed
    // between the dialog rendering and the POST, or the client's
    // directory was missing a user. Naming them lets the caller say
    // something useful instead of "move failed".
    let stranded = stranded_users(&mut tx, task_id, body.to_project_id, ctx.workspace_id).await?;
    if !stranded.is_empty() && !body.acknowledge_access_loss {
        let names = stranded
            .iter()
            .map(|u| u.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ApiError::Conflict(format!(
            "{names} cannot see the target project; re-confirm the move"
        )));
    }

    // Preserve a resolved issue link before the project's template goes
    // away. Per-task `external_url` already wins over the project
    // template on the client, so materializing the *currently* resolved
    // URL keeps the link pointing at the same issue instead of being
    // silently re-resolved against the target project's template.
    let carried_url = carry_external_url(&mut tx, task_id, from_project_id, body.to_project_id)
        .await?;

    // Tail of the target project's same section, matching the client's
    // `${maxSort}~` convention in `addTask`.
    let sort_key: String = sqlx::query_scalar(
        "SELECT COALESCE(MAX(t2.sort_key), '0') || '~'
         FROM tasks t2
         WHERE t2.project_id = $1
           AND t2.section = (SELECT section FROM tasks WHERE id = $2)",
    )
    .bind(body.to_project_id)
    .bind(task_id)
    .fetch_one(&mut *tx)
    .await?;

    // track_id / sprint_id both FK into project-scoped tables and have no
    // sane counterpart in the target, so they clear. Together with the
    // tag drop below this is the irreversible part of the move — moving
    // the task back does not restore any of it.
    sqlx::query(
        "UPDATE tasks
         SET project_id = $2,
             track_id = NULL,
             sprint_id = NULL,
             sort_key = $3,
             external_url = COALESCE(external_url, $4::text),
             updated_at = now()
         WHERE id = $1",
    )
    .bind(task_id)
    .bind(body.to_project_id)
    .bind(&sort_key)
    .bind(carried_url.as_deref())
    .execute(&mut *tx)
    .await?;

    // Tags are identity-bearing rows scoped to a project (migration
    // 0015), not strings — they don't travel. Drop the links; the source
    // project's `tags` rows stay put for its other tasks.
    sqlx::query("DELETE FROM task_tags WHERE task_id = $1")
        .bind(task_id)
        .execute(&mut *tx)
        .await?;

    let moved = db::get_task_tx(&mut tx, task_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Two log rows, one per audience. `processed_ops.project_id` is a
    // single column and `get_changes` filters on it, but a move has two
    // audiences with opposite needs: source-project members must drop
    // the task and its blocks, target-project members must gain them.
    // One row can only reach one of them.
    //
    // Both rows carry the same payload; the client branches on whether
    // it can see `to_project_id`, so a client in *both* projects
    // receives both rows and applies the same idempotent upsert twice.
    //
    // The payload carries the task's blocks as well as the task. Blocks
    // are reached through `task → project` (`list_blocks_in_scope`), so
    // a target-project member who wasn't in the source project has
    // never seen them: without this they'd gain the task and none of its
    // history until their next hydrate. Receivers upsert by block id, so
    // a client that already had them is unaffected.
    let blocks: Vec<crate::models::TimeBlock> = sqlx::query_as(
        "SELECT id, task_id, user_id, start_at, end_at, state, jira_worklog_id, jira_sync_error
         FROM time_blocks WHERE task_id = $1 ORDER BY start_at",
    )
    .bind(task_id)
    .fetch_all(&mut *tx)
    .await?;

    let payload = serde_json::json!({
        "kind": "task.move_project",
        "from_project_id": from_project_id,
        "to_project_id": body.to_project_id,
        "task": &moved,
        "blocks": &blocks,
    });
    for scope in [from_project_id, body.to_project_id] {
        ops::record_synthesized_op(
            &mut tx,
            ctx.user.id,
            ctx.workspace_id,
            "task.move_project",
            payload.clone(),
            Some(scope),
        )
        .await?;
    }

    tx.commit().await?;
    Ok(Json(MoveTaskResponse { task: moved }))
}

/// Everyone with a stake in the task — the assignee and every block
/// owner — who can't see the target project.
///
/// The access predicate has to match `require_project_access` exactly or
/// the dialog and the server disagree. Note `project_members.role =
/// 'inactive'` still counts as access: it's a display state that hides
/// someone from inbox assignee groups, not an authorization state.
async fn stranded_users(
    tx: &mut Transaction<'_, Postgres>,
    task_id: Uuid,
    to_project_id: Uuid,
    workspace_id: Uuid,
) -> sqlx::Result<Vec<StrandedUser>> {
    sqlx::query_as::<_, (Uuid, String, i64, bool)>(
        "WITH involved AS (
             SELECT assignee_id AS user_id FROM tasks
             WHERE id = $1 AND assignee_id IS NOT NULL
             UNION
             SELECT DISTINCT user_id FROM time_blocks WHERE task_id = $1
         )
         SELECT i.user_id,
                u.name,
                (SELECT COUNT(*) FROM time_blocks b
                  WHERE b.task_id = $1 AND b.user_id = i.user_id),
                EXISTS (SELECT 1 FROM tasks t
                         WHERE t.id = $1 AND t.assignee_id = i.user_id)
         FROM involved i
         JOIN users u ON u.id = i.user_id
         WHERE NOT (
             EXISTS (SELECT 1 FROM projects p
                      WHERE p.id = $2 AND p.owner_id = i.user_id)
             OR EXISTS (SELECT 1 FROM project_members pm
                         WHERE pm.project_id = $2 AND pm.user_id = i.user_id
                           AND pm.removed_at IS NULL)
             OR EXISTS (SELECT 1 FROM workspace_members wm
                         WHERE wm.workspace_id = $3 AND wm.user_id = i.user_id
                           AND wm.removed_at IS NULL AND wm.role = 'owner')
         )
         ORDER BY u.name",
    )
    .bind(task_id)
    .bind(to_project_id)
    .bind(workspace_id)
    .fetch_all(&mut **tx)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(user_id, name, block_count, is_assignee)| StrandedUser {
                user_id,
                name,
                block_count,
                is_assignee,
            })
            .collect()
    })
}

/// The issue URL the task resolves to *today*, when that resolution is
/// about to change. Returns `None` when the task has no issue link, when
/// it already carries an explicit `external_url` (which survives the move
/// untouched), or when both projects resolve it the same way.
async fn carry_external_url(
    tx: &mut Transaction<'_, Postgres>,
    task_id: Uuid,
    from_project_id: Uuid,
    to_project_id: Uuid,
) -> sqlx::Result<Option<String>> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT external_id, external_url FROM tasks WHERE id = $1",
    )
    .bind(task_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((Some(external_id), None)) = row else {
        return Ok(None);
    };

    let from_tpl: Option<String> =
        sqlx::query_scalar("SELECT external_url_template FROM projects WHERE id = $1")
            .bind(from_project_id)
            .fetch_one(&mut **tx)
            .await?;
    let to_tpl: Option<String> =
        sqlx::query_scalar("SELECT external_url_template FROM projects WHERE id = $1")
            .bind(to_project_id)
            .fetch_one(&mut **tx)
            .await?;
    if from_tpl == to_tpl {
        return Ok(None);
    }

    // Mirrors the client's resolution in TaskModal: `{key}` substitution
    // when the template has a placeholder, plain append otherwise.
    Ok(from_tpl.map(|tpl| {
        let key = urlencoding_encode(&external_id);
        if tpl.contains("{key}") {
            tpl.replace("{key}", &key)
        } else {
            format!("{tpl}{key}")
        }
    }))
}
