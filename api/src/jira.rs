// Jira integration: per-(user, workspace) API token auth. Unlike gcal,
// there's no OAuth grant here — Jira Cloud's REST API takes Basic Auth
// (account email + a personal API token the user creates at
// id.atlassian.com/manage-profile/security/api-tokens), so "connecting" is
// just validating and storing that pair.
//
// The Jira site itself (`workspaces.jira_site_url`) is a workspace
// setting, not a global one — different workspaces (different teams /
// companies) can run different Jira Cloud instances. The token stays
// per-user *within* that workspace: Jira attributes a worklog's `author`
// to whichever credential made the call, with no override, so a shared
// token would misattribute every teammate's logged time to one account.
// A user who belongs to two workspaces with two different Jira sites
// connects separately in each. See
// docs/sprints/28-jira-integration-base.md for the full history.
//
// Beyond connect/disconnect, this module covers: resolving a Jira project by
// key (for the project-settings picker), listing a project's epics (for the
// "create in Jira" epic picker), pushing a Fira task to Jira as a new issue,
// and pushing/resyncing a time block as a Jira worklog.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::db;
use crate::ensure_scope;
use crate::error::{ApiError, ApiResult};
use crate::ops;
use crate::AppState;

#[derive(Deserialize)]
pub struct ConnectRequest {
    pub email: String,
    pub api_token: String,
}

#[derive(Serialize)]
pub struct JiraStatusResponse {
    pub connected: bool,
    pub email: Option<String>,
    pub auto_sync_new_blocks: bool,
}

/// `POST /api/jira/connect` — validates the pasted credentials against
/// the *caller's active workspace's* Jira site before saving anything.
/// This is the only signal we get that the token is real: unlike gcal
/// there's no prior OAuth consent screen that could have already failed,
/// so skipping this check would let a typo'd token sit silently broken
/// until the first real push fails.
pub async fn connect(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Json(body): Json<ConnectRequest>,
) -> ApiResult<Json<JiraStatusResponse>> {
    let email = body.email.trim().to_string();
    let api_token = body.api_token.trim().to_string();
    if email.is_empty() || api_token.is_empty() {
        return Err(ApiError::BadRequest(
            "email and api_token are required".into(),
        ));
    }
    let Some(site_url) = db::workspace_jira_site_url(&s.pool, ctx.workspace_id).await? else {
        return Err(ApiError::BadRequest(
            "this workspace has no Jira site configured — set one in workspace settings first"
                .into(),
        ));
    };

    verify_credentials(&site_url, &email, &api_token)
        .await
        .map_err(|e| ApiError::BadRequest(format!("Jira auth failed: {e}")))?;

    let auto_sync_new_blocks =
        upsert_credentials(&s.pool, ctx.user.id, ctx.workspace_id, &email, &api_token).await?;
    Ok(Json(JiraStatusResponse {
        connected: true,
        email: Some(email),
        auto_sync_new_blocks,
    }))
}

/// `POST /api/jira/disconnect` — deletes the stored credentials for the
/// caller's active workspace. No revoke call to Jira; API tokens are
/// managed (and revoked) from the user's own Atlassian account settings,
/// not through our API.
pub async fn disconnect(
    State(s): State<AppState>,
    ctx: AuthCtx,
) -> Result<StatusCode, ApiError> {
    sqlx::query("DELETE FROM jira_credentials WHERE user_id = $1 AND workspace_id = $2")
        .bind(ctx.user.id)
        .bind(ctx.workspace_id)
        .execute(&s.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct SetAutoSyncRequest {
    pub enabled: bool,
}

/// `POST /api/jira/auto_sync` — toggles whether a newly created time block
/// on a Jira-linked task gets its worklog pushed automatically (see
/// `ops::apply_one`'s `block.create` handling), instead of waiting for the
/// manual "Log to Jira" click. Requires an existing connection — there's
/// no row to flip the flag on otherwise.
pub async fn set_auto_sync(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Json(body): Json<SetAutoSyncRequest>,
) -> ApiResult<Json<JiraStatusResponse>> {
    let updated: Option<(String,)> = sqlx::query_as(
        "UPDATE jira_credentials SET auto_sync_new_blocks = $3
         WHERE user_id = $1 AND workspace_id = $2
         RETURNING email",
    )
    .bind(ctx.user.id)
    .bind(ctx.workspace_id)
    .bind(body.enabled)
    .fetch_optional(&s.pool)
    .await?;
    let Some((email,)) = updated else {
        return Err(ApiError::BadRequest(
            "connect your Jira account first".into(),
        ));
    };
    Ok(Json(JiraStatusResponse {
        connected: true,
        email: Some(email),
        auto_sync_new_blocks: body.enabled,
    }))
}

async fn verify_credentials(site_url: &str, email: &str, api_token: &str) -> Result<(), String> {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{site_url}/rest/api/3/myself"))
        .basic_auth(email, Some(api_token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Jira returned {}", res.status()));
    }
    Ok(())
}

/// A connected user's stored credentials for one workspace — read by
/// issue-create / worklog-push handlers in later sprints so every
/// outbound call authenticates as the acting user, not a shared account.
pub struct StoredCredentials {
    pub email: String,
    pub api_token: String,
}

pub async fn load_credentials(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
) -> sqlx::Result<Option<StoredCredentials>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT email, api_token FROM jira_credentials
         WHERE user_id = $1 AND workspace_id = $2",
    )
    .bind(user_id)
    .bind(workspace_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(email, api_token)| StoredCredentials { email, api_token }))
}

/// Returns the row's `auto_sync_new_blocks` — untouched by this upsert, so
/// this just reports back whatever a prior connection had it set to (or
/// the column default, `false`, on a brand-new connection).
async fn upsert_credentials(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
    email: &str,
    api_token: &str,
) -> sqlx::Result<bool> {
    let (auto_sync_new_blocks,): (bool,) = sqlx::query_as(
        "INSERT INTO jira_credentials (user_id, workspace_id, email, api_token, last_sync_error)
         VALUES ($1, $2, $3, $4, NULL)
         ON CONFLICT (user_id, workspace_id) DO UPDATE
             SET email = EXCLUDED.email,
                 api_token = EXCLUDED.api_token,
                 last_sync_error = NULL
         RETURNING auto_sync_new_blocks",
    )
    .bind(user_id)
    .bind(workspace_id)
    .bind(email)
    .bind(api_token)
    .fetch_one(pool)
    .await?;
    Ok(auto_sync_new_blocks)
}

// ---- project mapping / issue create ----

struct WorkspaceJiraContext {
    site_url: String,
    email: String,
    api_token: String,
}

/// Loads both halves needed for any authenticated Jira call: the
/// workspace's configured site and the caller's own credentials for it.
/// Errors with an actionable message when either is missing — these are
/// the two setup steps (workspace owner sets the site, each member
/// connects their token) that have to happen before any push works.
async fn require_workspace_jira(
    pool: &PgPool,
    user_id: Uuid,
    workspace_id: Uuid,
) -> ApiResult<WorkspaceJiraContext> {
    let Some(site_url) = db::workspace_jira_site_url(pool, workspace_id).await? else {
        return Err(ApiError::BadRequest(
            "this workspace has no Jira site configured — set one in workspace settings first"
                .into(),
        ));
    };
    let Some(cred) = load_credentials(pool, user_id, workspace_id).await? else {
        return Err(ApiError::BadRequest(
            "connect your Jira account in Account Settings first".into(),
        ));
    };
    Ok(WorkspaceJiraContext {
        site_url,
        email: cred.email,
        api_token: cred.api_token,
    })
}

#[derive(Serialize)]
pub struct JiraProjectResponse {
    pub key: String,
    pub name: String,
}

/// `GET /api/jira/projects/:key` — resolves a Jira project by key so the
/// project-settings picker can confirm it exists and show its name before
/// saving. Project keys are plain uppercase-alnum by Jira's own convention;
/// rejecting anything else here avoids needing a URL-encoder for what
/// should never contain special characters.
pub async fn resolve_project(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(key): Path<String>,
) -> ApiResult<Json<JiraProjectResponse>> {
    let key = key.trim().to_string();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ApiError::BadRequest(
            "project key must be alphanumeric".into(),
        ));
    }
    let jc = require_workspace_jira(&s.pool, ctx.user.id, ctx.workspace_id).await?;

    #[derive(Deserialize)]
    struct RawProject {
        key: String,
        name: String,
    }
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/rest/api/3/project/{}", jc.site_url, key))
        .basic_auth(&jc.email, Some(&jc.api_token))
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Jira request failed: {e}")))?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ApiError::BadRequest(format!(
            "no Jira project found for key '{key}'"
        )));
    }
    if !res.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "Jira returned {}",
            res.status()
        )));
    }
    let p: RawProject = res
        .json()
        .await
        .map_err(|e| ApiError::BadRequest(format!("bad Jira response: {e}")))?;
    Ok(Json(JiraProjectResponse {
        key: p.key,
        name: p.name,
    }))
}

#[derive(Deserialize)]
pub struct ListEpicsQuery {
    pub project_key: String,
}

#[derive(Serialize)]
pub struct JiraEpicResponse {
    pub key: String,
    pub summary: String,
}

/// `GET /api/jira/epics?project_key=` — epics in one Jira project, newest
/// first, for the "create in Jira" epic picker.
pub async fn list_epics(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Query(q): Query<ListEpicsQuery>,
) -> ApiResult<Json<Vec<JiraEpicResponse>>> {
    let project_key = q.project_key.trim().to_string();
    if project_key.is_empty() || !project_key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ApiError::BadRequest(
            "project_key must be alphanumeric".into(),
        ));
    }
    let jc = require_workspace_jira(&s.pool, ctx.user.id, ctx.workspace_id).await?;

    #[derive(Deserialize)]
    struct RawFields {
        summary: Option<String>,
    }
    #[derive(Deserialize)]
    struct RawIssue {
        key: String,
        fields: RawFields,
    }
    #[derive(Deserialize)]
    struct SearchResponse {
        #[serde(default)]
        issues: Vec<RawIssue>,
    }
    let jql = format!("project = \"{project_key}\" AND issuetype = Epic ORDER BY created DESC");
    let client = reqwest::Client::new();
    // `/rest/api/3/search` (the old GET search) is deprecated and now
    // returns 410 Gone on migrated sites — Atlassian's replacement is the
    // enhanced JQL search endpoint below. Same query params, same
    // `issues[].{key,fields}` response shape; only pagination (token-based
    // instead of startAt/total) differs, and we don't paginate here.
    let res = client
        .get(format!("{}/rest/api/3/search/jql", jc.site_url))
        .basic_auth(&jc.email, Some(&jc.api_token))
        .query(&[
            ("jql", jql.as_str()),
            ("maxResults", "50"),
            ("fields", "summary"),
        ])
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Jira request failed: {e}")))?;
    if !res.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "Jira returned {}",
            res.status()
        )));
    }
    let parsed: SearchResponse = res
        .json()
        .await
        .map_err(|e| ApiError::BadRequest(format!("bad Jira response: {e}")))?;
    Ok(Json(
        parsed
            .issues
            .into_iter()
            .map(|i| JiraEpicResponse {
                key: i.key,
                summary: i.fields.summary.unwrap_or_default(),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct PushTaskRequest {
    #[serde(default)]
    pub epic_key: Option<String>,
}

#[derive(Serialize)]
pub struct PushTaskResponse {
    pub external_id: String,
    pub external_url: String,
}

/// `POST /api/jira/tasks/:task_id` — creates a Jira issue for an existing
/// Fira task and writes the result back into the task's existing manual
/// issue-link fields (`external_id` / `external_url`). Reuses those fields
/// rather than inventing a new "linked" concept — `TaskModal`'s issue-link
/// display already renders whatever's in them, whether it got there by
/// paste or by this push.
pub async fn push_task(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(task_id): Path<Uuid>,
    Json(body): Json<PushTaskRequest>,
) -> ApiResult<Json<PushTaskResponse>> {
    let jc = require_workspace_jira(&s.pool, ctx.user.id, ctx.workspace_id).await?;

    let mut tx = s.pool.begin().await?;
    let project_id =
        ensure_scope::ensure_task_in_scope(&mut tx, ctx.user.id, ctx.workspace_id, task_id)
            .await
            .map_err(|_| ApiError::NotFound)?;

    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT t.title, p.jira_project_key FROM tasks t
         JOIN projects p ON p.id = t.project_id
         WHERE t.id = $1",
    )
    .bind(task_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((title, jira_project_key)) = row else {
        return Err(ApiError::NotFound);
    };
    let Some(project_key) = jira_project_key else {
        return Err(ApiError::BadRequest(
            "this project has no Jira project key configured".into(),
        ));
    };

    let task_link = format!(
        "{}/#/w/{}/t/{}",
        s.auth.app_base_url, ctx.workspace_id, task_id
    );
    let created = create_issue(
        &jc,
        &project_key,
        &title,
        body.epic_key.as_deref(),
        &task_link,
    )
    .await
    .map_err(|e| ApiError::BadRequest(format!("Jira issue create failed: {e}")))?;
    let external_url = format!("{}/browse/{}", jc.site_url, created.key);

    sqlx::query(
        "UPDATE tasks SET external_id = $2, external_url = $3, updated_at = now() WHERE id = $1",
    )
    .bind(task_id)
    .bind(&created.key)
    .bind(&external_url)
    .execute(&mut *tx)
    .await?;

    // Two synthesized ops (not one custom kind) so every other connected
    // session picks this up through the existing `task.set_external_id` /
    // `task.set_external_url` client handlers — same as if the user had
    // pasted the link manually. No new client-side op case needed.
    let id_payload = serde_json::json!({
        "kind": "task.set_external_id",
        "task_id": task_id,
        "external_id": &created.key,
    });
    ops::record_synthesized_op(
        &mut tx,
        ctx.user.id,
        ctx.workspace_id,
        "task.set_external_id",
        id_payload,
        Some(project_id),
    )
    .await?;
    let url_payload = serde_json::json!({
        "kind": "task.set_external_url",
        "task_id": task_id,
        "external_url": &external_url,
    });
    ops::record_synthesized_op(
        &mut tx,
        ctx.user.id,
        ctx.workspace_id,
        "task.set_external_url",
        url_payload,
        Some(project_id),
    )
    .await?;

    tx.commit().await?;
    Ok(Json(PushTaskResponse {
        external_id: created.key,
        external_url,
    }))
}

struct CreatedIssue {
    key: String,
}

async fn create_issue(
    jc: &WorkspaceJiraContext,
    project_key: &str,
    summary: &str,
    epic_key: Option<&str>,
    task_link: &str,
) -> Result<CreatedIssue, String> {
    // Some Jira projects require a non-empty description, so every issue we
    // create gets at least a link back to the Fira task it came from.
    let description = serde_json::json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": "View this task in Fira \u{2192}",
                "marks": [{ "type": "link", "attrs": { "href": task_link } }],
            }],
        }],
    });
    let mut fields = serde_json::json!({
        "project": { "key": project_key },
        "summary": summary,
        "issuetype": { "name": "Task" },
        "description": description,
    });
    // `parent` is Jira Cloud's unified-hierarchy epic link field (works for
    // both team-managed and company-managed projects since the 2022
    // hierarchy rollout). Older company-managed projects that never
    // migrated use a custom field instead — best-effort here, not handled.
    if let Some(epic) = epic_key.filter(|e| !e.is_empty()) {
        fields["parent"] = serde_json::json!({ "key": epic });
    }
    let body = serde_json::json!({ "fields": fields });

    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/rest/api/3/issue", jc.site_url))
        .basic_auth(&jc.email, Some(&jc.api_token))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    let text = res.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("{status}: {text}"));
    }
    #[derive(Deserialize)]
    struct RawCreated {
        key: String,
    }
    let parsed: RawCreated = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(CreatedIssue { key: parsed.key })
}

// ---- time-block worklog push ----

#[derive(Serialize)]
pub struct WorklogPushResponse {
    pub jira_worklog_id: String,
}

/// `POST /api/jira/blocks/:block_id` — manual "Log to Jira" action. Scope
/// check only; the actual push (network call + DB write) happens outside
/// the scope-check transaction in `push_block_worklog`, shared with the
/// background resync below.
pub async fn push_block(
    State(s): State<AppState>,
    ctx: AuthCtx,
    Path(block_id): Path<Uuid>,
) -> ApiResult<Json<WorklogPushResponse>> {
    let mut tx = s.pool.begin().await?;
    ensure_scope::ensure_block_in_scope(&mut tx, ctx.user.id, ctx.workspace_id, block_id)
        .await
        .map_err(|_| ApiError::NotFound)?;
    tx.commit().await?;

    let jira_worklog_id = push_block_worklog(&s.pool, ctx.workspace_id, block_id)
        .await
        .map_err(ApiError::BadRequest)?;
    Ok(Json(WorklogPushResponse { jira_worklog_id }))
}

/// Creates (first push) or updates (every push after) a Jira worklog for
/// one time block. Shared by the manual endpoint above and the
/// fire-and-forget resync `ops.rs` triggers after `block.update` commits.
///
/// Authenticates using the *block owner's* stored credentials, not
/// whoever triggered the call — a worklog's `author` is fixed to whichever
/// token made the request, and the entire point of per-user tokens (see
/// module doc) is that logged time is attributed to whoever the time
/// belongs to, regardless of who clicked the button or whose edit
/// triggered the resync.
///
/// On both success and failure, updates `time_blocks` directly and emits a
/// synthesized `block.update` op (not client-submitted — no `Op` variant
/// needed) carrying just the two Jira fields as a patch. The client's
/// existing `block.update` handler already does a generic partial merge,
/// so no new frontend dispatch code is needed for other sessions to see
/// the sync result.
async fn push_block_worklog(
    pool: &PgPool,
    workspace_id: Uuid,
    block_id: Uuid,
) -> Result<String, String> {
    let row: Option<(Uuid, Uuid, DateTime<Utc>, DateTime<Utc>, Option<String>, String)> =
        sqlx::query_as(
            "SELECT t.project_id, b.user_id, b.start_at, b.end_at, b.jira_worklog_id, u.name
             FROM time_blocks b
             JOIN tasks t ON t.id = b.task_id
             JOIN users u ON u.id = b.user_id
             WHERE b.id = $1",
        )
        .bind(block_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;
    let Some((project_id, owner_id, start_at, end_at, existing_worklog_id, owner_name)) = row
    else {
        return Err("time block not found".into());
    };

    let issue_key: Option<String> = sqlx::query_scalar(
        "SELECT t.external_id FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         JOIN projects p ON p.id = t.project_id
         WHERE b.id = $1 AND p.jira_project_key IS NOT NULL",
    )
    .bind(block_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
    .flatten();
    let Some(issue_key) = issue_key else {
        return Err("this task isn't linked to a Jira issue".into());
    };

    let Some(site_url) = db::workspace_jira_site_url(pool, workspace_id)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err("this workspace has no Jira site configured".into());
    };
    let Some(cred) = load_credentials(pool, owner_id, workspace_id)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err(format!(
            "{owner_name} hasn't connected Jira in this workspace"
        ));
    };

    // Jira rejects worklogs under 60s; a block shorter than that (shouldn't
    // happen given the 15-min grid, but defends against clock skew) gets
    // floored rather than rejected outright.
    let seconds = (end_at - start_at).num_seconds().max(60);
    // Jira's worklog `started` wants "yyyy-MM-ddTHH:mm:ss.SSSZ" with a
    // bare +/-HHMM offset (no colon) — chrono's %z gives exactly that.
    let started = start_at.format("%Y-%m-%dT%H:%M:%S%.3f%z").to_string();
    let comment_text = format!("Logged via Fira by {owner_name}");
    let body = serde_json::json!({
        "started": started,
        "timeSpentSeconds": seconds,
        "comment": {
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{ "type": "text", "text": comment_text }]
            }]
        }
    });

    let jc = WorkspaceJiraContext {
        site_url,
        email: cred.email,
        api_token: cred.api_token,
    };
    let client = reqwest::Client::new();
    let req = if let Some(worklog_id) = &existing_worklog_id {
        client.put(format!(
            "{}/rest/api/3/issue/{issue_key}/worklog/{worklog_id}",
            jc.site_url
        ))
    } else {
        client.post(format!(
            "{}/rest/api/3/issue/{issue_key}/worklog",
            jc.site_url
        ))
    };
    let result = req
        .basic_auth(&jc.email, Some(&jc.api_token))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string());

    let outcome: Result<String, String> = async {
        let res = result?;
        let status = res.status();
        let text = res.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("Jira returned {status}: {text}"));
        }
        #[derive(Deserialize)]
        struct RawWorklog {
            id: String,
        }
        let parsed: RawWorklog = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        Ok(parsed.id)
    }
    .await;

    // Persist + propagate regardless of outcome — a failed resync needs to
    // surface `jira_sync_error` just as much as a success needs to surface
    // the new `jira_worklog_id`, especially for the background path where
    // nobody's waiting on an HTTP response to tell them it failed.
    let (worklog_id_to_store, sync_error) = match &outcome {
        Ok(id) => (Some(id.clone()), None),
        Err(e) => (existing_worklog_id.clone(), Some(e.clone())),
    };
    let _ = sqlx::query(
        "UPDATE time_blocks SET jira_worklog_id = $2, jira_sync_error = $3 WHERE id = $1",
    )
    .bind(block_id)
    .bind(&worklog_id_to_store)
    .bind(&sync_error)
    .execute(pool)
    .await;

    if let Ok(mut tx) = pool.begin().await {
        let payload = serde_json::json!({
            "kind": "block.update",
            "block_id": block_id,
            "patch": {
                "jira_worklog_id": worklog_id_to_store,
                "jira_sync_error": sync_error,
            },
        });
        let _ = ops::record_synthesized_op(
            &mut tx,
            owner_id,
            workspace_id,
            "block.update",
            payload,
            Some(project_id),
        )
        .await;
        let _ = tx.commit().await;
    }

    outcome
}

/// Fire-and-forget hook called from `ops.rs` after a `block.update` op
/// commits. Only resyncs blocks that were already pushed — first push
/// always goes through the manual endpoint above so a Jira worklog never
/// gets created on the user's behalf without them opting in via the
/// button; once it exists, keeping it in sync with further edits is
/// implicit (same posture as gcal's background sync: never block the
/// request path on Jira's latency/availability, just log a warning).
pub async fn resync_block_if_linked(pool: &PgPool, workspace_id: Uuid, block_id: Uuid) {
    let already_linked: bool = sqlx::query_scalar(
        "SELECT jira_worklog_id IS NOT NULL FROM time_blocks WHERE id = $1",
    )
    .bind(block_id)
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    if !already_linked {
        return;
    }
    if let Err(e) = push_block_worklog(pool, workspace_id, block_id).await {
        tracing::warn!("jira worklog resync failed for block {block_id}: {e}");
    }
}

/// Fire-and-forget hook called from `ops::apply_one` after a `block.create`
/// op commits. Unlike `resync_block_if_linked` (which only ever touches a
/// worklog that already exists), this can make the *first* push — but only
/// when the block's owner opted into `jira_credentials.auto_sync_new_blocks`
/// (see `jira::set_auto_sync`); everyone else still pushes manually via the
/// "Log to Jira" button.
pub async fn auto_sync_new_block_if_enabled(pool: &PgPool, workspace_id: Uuid, block_id: Uuid) {
    let row: Option<(bool, bool)> = sqlx::query_as(
        "SELECT t.external_id IS NOT NULL, COALESCE(jc.auto_sync_new_blocks, false)
         FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         LEFT JOIN jira_credentials jc ON jc.user_id = b.user_id AND jc.workspace_id = $2
         WHERE b.id = $1",
    )
    .bind(block_id)
    .bind(workspace_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let Some((task_linked, auto_sync_enabled)) = row else {
        return;
    };
    if !task_linked || !auto_sync_enabled {
        return;
    }
    if let Err(e) = push_block_worklog(pool, workspace_id, block_id).await {
        tracing::warn!("jira worklog auto-sync failed for block {block_id}: {e}");
    }
}

// ---- time-block worklog delete ----

/// What's needed to delete a worklog after the time block it came from is
/// already gone from our DB — looked up by `pending_worklog_delete` while
/// the row still exists, then carried across the delete for the caller to
/// act on afterwards.
pub struct PendingWorklogDelete {
    pub issue_key: String,
    pub worklog_id: String,
    pub owner_id: Uuid,
}

/// Looks up the Jira worklog (if any) tied to a time block. Called from
/// `ops::apply_one` *before* the `block.delete` op runs — reads straight
/// from `pool` rather than the op's own transaction since this is a
/// best-effort snapshot for a fire-and-forget follow-up call, same posture
/// as `resync_block_if_linked`.
pub async fn pending_worklog_delete(
    pool: &PgPool,
    block_id: Uuid,
) -> sqlx::Result<Option<PendingWorklogDelete>> {
    let row: Option<(String, String, Uuid)> = sqlx::query_as(
        "SELECT t.external_id, b.jira_worklog_id, b.user_id
         FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         WHERE b.id = $1 AND b.jira_worklog_id IS NOT NULL AND t.external_id IS NOT NULL",
    )
    .bind(block_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(issue_key, worklog_id, owner_id)| PendingWorklogDelete {
        issue_key,
        worklog_id,
        owner_id,
    }))
}

/// Same lookup as `pending_worklog_delete`, but for every block under a
/// task at once — called from `ops::apply_one` before the `task.delete`
/// op's FK cascade removes them along with the task.
pub async fn pending_worklog_deletes_for_task(
    pool: &PgPool,
    task_id: Uuid,
) -> sqlx::Result<Vec<PendingWorklogDelete>> {
    let rows: Vec<(String, String, Uuid)> = sqlx::query_as(
        "SELECT t.external_id, b.jira_worklog_id, b.user_id
         FROM time_blocks b
         JOIN tasks t ON t.id = b.task_id
         WHERE b.task_id = $1 AND b.jira_worklog_id IS NOT NULL AND t.external_id IS NOT NULL",
    )
    .bind(task_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(issue_key, worklog_id, owner_id)| PendingWorklogDelete {
            issue_key,
            worklog_id,
            owner_id,
        })
        .collect())
}

/// Fire-and-forget hook called after a `block.delete` op commits, for a
/// block that had a Jira worklog. Same posture as `resync_block_if_linked`:
/// never block the request path on Jira's latency/availability, just log a
/// warning on failure — the local delete has already committed either way,
/// so there's no `jira_sync_error` field left to report against.
pub async fn delete_worklog_if_linked(pool: &PgPool, workspace_id: Uuid, job: PendingWorklogDelete) {
    if let Err(e) = delete_worklog(pool, workspace_id, &job).await {
        tracing::warn!(
            "jira worklog delete failed for issue {} worklog {}: {e}",
            job.issue_key,
            job.worklog_id
        );
    }
}

async fn delete_worklog(pool: &PgPool, workspace_id: Uuid, job: &PendingWorklogDelete) -> Result<(), String> {
    let jc = require_workspace_jira(pool, job.owner_id, workspace_id)
        .await
        .map_err(|e| e.to_string())?;
    let client = reqwest::Client::new();
    let res = client
        .delete(format!(
            "{}/rest/api/3/issue/{}/worklog/{}",
            jc.site_url, job.issue_key, job.worklog_id
        ))
        .basic_auth(&jc.email, Some(&jc.api_token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    // A worklog that's already gone (manually deleted in Jira, or a retry
    // of this same cleanup) still counts as a successful delete.
    if !res.status().is_success() && res.status() != reqwest::StatusCode::NOT_FOUND {
        return Err(format!("Jira returned {}", res.status()));
    }
    Ok(())
}
