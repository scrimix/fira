// Google Calendar integration.
//
// Two surfaces:
//   1. OAuth (incremental authorization). The signup flow only asks for
//      `openid email profile` so first-time users aren't forced to
//      grant calendar to log in. A signed-in user opts into calendar by
//      hitting `/api/gcal/connect`, which redirects to Google's consent
//      screen with `scope=calendar.readonly`, `access_type=offline` and
//      `prompt=consent` (both required to receive a refresh_token —
//      without `prompt=consent`, repeat consents return no token).
//
//   2. Sync. `sync_user_calendar` reads `gcal_credentials`, refreshes
//      the access token if needed, calls Google's events.list with a
//      window centered on now, and upserts into `gcal_events`. The
//      bootstrap handler kicks this off as a fire-and-forget task so
//      Google's latency / availability never blocks the SPA.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{auth::AuthUser, AppState};

const GCAL_STATE_COOKIE: &str = "gcal_oauth_state";
const STATE_TTL_SECONDS: i64 = 300;
const CALENDAR_SCOPE: &str = "https://www.googleapis.com/auth/calendar.readonly";
// Sync window: events from 2 weeks back to 8 weeks ahead. Wider than
// the visible week so calendar nav doesn't show empty future days
// while a fresh sync is in flight.
const SYNC_WINDOW_PAST_DAYS: i64 = 14;
const SYNC_WINDOW_FUTURE_DAYS: i64 = 56;
// Skew so we refresh the access token before Google considers it
// expired — protects against clock drift and request latency.
const TOKEN_REFRESH_SKEW_SECS: i64 = 60;

// ---- /api/gcal/connect ----

pub async fn connect(State(s): State<AppState>, _user: AuthUser, jar: CookieJar) -> Response {
    if s.auth.google_client_id.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Google OAuth not configured (GOOGLE_CLIENT_ID missing)",
        )
            .into_response();
    }
    let state = random_token(24);
    let redirect_uri = gcal_redirect_url(&s.auth);
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?{}",
        querystring(&[
            ("client_id", &s.auth.google_client_id),
            ("redirect_uri", &redirect_uri),
            ("response_type", "code"),
            ("scope", CALENDAR_SCOPE),
            ("state", &state),
            // offline + consent are both required to receive a
            // refresh_token: offline turns it on, consent forces
            // re-prompt (without it, the second consent returns no
            // refresh_token at all).
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "true"),
        ]),
    );
    let state_cookie = build_cookie(GCAL_STATE_COOKIE, state, STATE_TTL_SECONDS, &s.auth);
    (jar.add(state_cookie), Redirect::to(&url)).into_response()
}

// ---- /api/gcal/callback ----

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: i64,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    email: String,
}

pub async fn callback(
    State(s): State<AppState>,
    user: AuthUser,
    jar: CookieJar,
    Query(p): Query<CallbackParams>,
) -> Response {
    if let Some(err) = p.error {
        return (StatusCode::BAD_REQUEST, format!("oauth error: {err}")).into_response();
    }
    let Some(code) = p.code else {
        return (StatusCode::BAD_REQUEST, "missing code").into_response();
    };
    let Some(state_param) = p.state else {
        return (StatusCode::BAD_REQUEST, "missing state").into_response();
    };
    let cookie_state = jar.get(GCAL_STATE_COOKIE).map(|c| c.value().to_string());
    if cookie_state.as_deref() != Some(state_param.as_str()) {
        return (StatusCode::BAD_REQUEST, "state mismatch").into_response();
    }

    let token: GoogleTokenResponse = match exchange_code(&s.auth, &code).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("gcal token exchange failed: {e:?}");
            return (StatusCode::BAD_GATEWAY, "token exchange failed").into_response();
        }
    };
    // Without a refresh_token we can't sync past the first hour of
    // access. Reject the connection and ask the user to retry — usually
    // this means Google didn't see prompt=consent and returned only an
    // access_token because consent was already cached.
    let Some(refresh_token) = token.refresh_token else {
        tracing::warn!("gcal callback returned no refresh_token");
        return (
            StatusCode::BAD_REQUEST,
            "no refresh token returned — please try again",
        )
            .into_response();
    };

    let email = match fetch_userinfo(&token.access_token).await {
        Ok(u) => u.email,
        Err(e) => {
            // Non-fatal: we still have tokens, just no email label.
            tracing::warn!("gcal userinfo fetch failed: {e:?}");
            String::new()
        }
    };

    let expires_at = Utc::now() + Duration::seconds(token.expires_in);
    if let Err(e) = upsert_credentials(
        &s.pool,
        user.id,
        &refresh_token,
        Some(&token.access_token),
        Some(expires_at),
        if email.is_empty() { None } else { Some(&email) },
    )
    .await
    {
        tracing::error!("gcal credentials upsert failed: {e:?}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "credential save failed").into_response();
    }

    // Best-effort initial sync so the user sees events on the very next
    // bootstrap. Errors logged, never bubbled — the user's calendar
    // session is the right place to surface a degraded sync state.
    if let Err(e) = sync_user_calendar(&s.pool, user.id).await {
        tracing::warn!("initial gcal sync failed: {}", e.message);
    }

    let cleared = clear_cookie(GCAL_STATE_COOKIE, &s.auth);
    let jar = jar.add(cleared);
    (jar, Redirect::to(&s.auth.app_base_url)).into_response()
}

// ---- /api/gcal/disconnect ----

pub async fn disconnect(State(s): State<AppState>, user: AuthUser) -> Result<StatusCode, Response> {
    // Best-effort revoke at Google's side so the user's connected-apps
    // list reflects reality. We don't fail the disconnect if Google's
    // side errors — the local state is the source of truth here.
    let token: Option<(Option<String>, String)> = sqlx::query_as(
        "SELECT access_token, refresh_token FROM gcal_credentials WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_optional(&s.pool)
    .await
    .map_err(map_db_err)?;
    if let Some((access, refresh)) = token {
        let to_revoke = access.unwrap_or(refresh);
        let client = reqwest::Client::new();
        let _ = client
            .post("https://oauth2.googleapis.com/revoke")
            .form(&[("token", to_revoke.as_str())])
            .send()
            .await;
    }
    let mut tx = s.pool.begin().await.map_err(map_db_err)?;
    sqlx::query("DELETE FROM gcal_events WHERE user_id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
    sqlx::query("DELETE FROM gcal_credentials WHERE user_id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
    tx.commit().await.map_err(map_db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_db_err(e: sqlx::Error) -> Response {
    tracing::error!("gcal db error: {e:?}");
    (StatusCode::INTERNAL_SERVER_ERROR, "database error").into_response()
}

// ---- sync ----

#[derive(Debug)]
pub struct SyncError {
    pub message: String,
    /// True when Google's token endpoint returned `invalid_grant` —
    /// the refresh token was revoked, expired (Testing-mode 7-day cap),
    /// or invalidated by the user. The credentials row stays so the
    /// UI can keep rendering "Reconnect needed", but no further sync
    /// attempts will succeed until the user reconnects.
    pub invalid_grant: bool,
}

impl<E: std::fmt::Display> From<E> for SyncError {
    fn from(e: E) -> Self {
        SyncError { message: e.to_string(), invalid_grant: false }
    }
}

/// Pull events from Google for a user with stored credentials. No-op
/// (Ok) if the user isn't connected. Refreshes the access token first
/// if it's expired or near-expired. Upserts on (user_id,
/// google_event_id) so re-running is cheap and idempotent. Deletes
/// rows in the sync window that Google no longer returns so cancelled
/// events disappear.
pub async fn sync_user_calendar(pool: &PgPool, user_id: Uuid) -> Result<(), SyncError> {
    let cred = load_credentials(pool, user_id).await?;
    let Some(mut cred) = cred else {
        // Not connected — nothing to do.
        return Ok(());
    };
    let cfg = crate::auth::AuthConfig::from_env();
    if cfg.google_client_id.is_empty() {
        return Err(SyncError { message: "GOOGLE_CLIENT_ID missing".into(), invalid_grant: false });
    }

    let now = Utc::now();
    let needs_refresh = match cred.access_expires_at {
        Some(e) => e <= now + Duration::seconds(TOKEN_REFRESH_SKEW_SECS),
        None => true,
    };
    if needs_refresh {
        match refresh_access_token(&cfg, &cred.refresh_token).await {
            Ok(refreshed) => {
                cred.access_token = Some(refreshed.access_token.clone());
                cred.access_expires_at = Some(refreshed.expires_at);
                // COALESCE so we keep the existing refresh_token when
                // Google didn't rotate (production-mode apps), and
                // overwrite when it did (Testing-mode rotation). The
                // old token is invalidated by Google shortly after a
                // rotation, so failing to persist the new one would
                // strand the user on a dead credential.
                if let Some(rotated) = &refreshed.rotated_refresh_token {
                    cred.refresh_token = rotated.clone();
                }
                let _ = sqlx::query(
                    "UPDATE gcal_credentials
                     SET access_token = $2,
                         access_expires_at = $3,
                         refresh_token = COALESCE($4, refresh_token),
                         last_sync_error = NULL
                     WHERE user_id = $1",
                )
                .bind(user_id)
                .bind(&refreshed.access_token)
                .bind(refreshed.expires_at)
                .bind(refreshed.rotated_refresh_token.as_deref())
                .execute(pool)
                .await;
            }
            Err(e) => {
                // Persist a kind-prefixed error so the UI can branch
                // on "Reconnect" vs generic failure without parsing
                // the message.
                let stored = if e.invalid_grant {
                    "invalid_grant: please reconnect Google Calendar".to_string()
                } else {
                    format!("refresh_failed: {}", e.message)
                };
                let mut tx = pool.begin().await?;
                sqlx::query(
                    "UPDATE gcal_credentials SET last_sync_error = $2 WHERE user_id = $1",
                )
                .bind(user_id)
                .bind(&stored)
                .execute(&mut *tx)
                .await?;
                if e.invalid_grant {
                    // Drop cached events so the user doesn't keep
                    // seeing stale rows behind the "reconnect needed"
                    // banner. Reconnect upserts fresh creds + runs an
                    // initial sync, so the events come back as soon as
                    // they consent again.
                    sqlx::query("DELETE FROM gcal_events WHERE user_id = $1")
                        .bind(user_id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                return Err(e);
            }
        }
    }
    let access = cred
        .access_token
        .as_deref()
        .ok_or_else(|| SyncError { message: "no access token after refresh".into(), invalid_grant: false })?;

    let time_min = now - Duration::days(SYNC_WINDOW_PAST_DAYS);
    let time_max = now + Duration::days(SYNC_WINDOW_FUTURE_DAYS);
    // Wrap the network + db section so a Google outage / 5xx /
    // network blip surfaces as a stored `sync_failed:` instead of
    // silently leaving the previous error message stale.
    match do_sync(pool, user_id, access, time_min, time_max).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = sqlx::query(
                "UPDATE gcal_credentials SET last_sync_error = $2 WHERE user_id = $1",
            )
            .bind(user_id)
            .bind(format!("sync_failed: {}", e.message))
            .execute(pool)
            .await;
            Err(e)
        }
    }
}

async fn do_sync(
    pool: &PgPool,
    user_id: Uuid,
    access: &str,
    time_min: DateTime<Utc>,
    time_max: DateTime<Utc>,
) -> Result<(), SyncError> {
    // Sync every calendar the user has selected in Google Calendar's
    // UI — primary + secondaries + shared subscriptions. Holiday /
    // birthday calendars stay selected by default in Google so they
    // come in too; that's fine, they look like normal events on the
    // grid and the user can untick them on Google's side if unwanted.
    let calendars = fetch_calendar_list(access).await?;

    // (calendar_id, google_event_id) pairs we just upserted — anything
    // in the window not on this list is stale and gets deleted below.
    let mut keep_cal: Vec<String> = Vec::new();
    let mut keep_evt: Vec<String> = Vec::new();

    let mut tx = pool.begin().await?;
    for cal in &calendars {
        let events = fetch_events(access, &cal.id, time_min, time_max).await?;
        for evt in &events {
            // Skip all-day and events without timed start/end. The
            // grid has no row for all-day items today.
            let (Some(start), Some(end)) = (evt.start_dt, evt.end_dt) else { continue };
            keep_cal.push(cal.id.clone());
            keep_evt.push(evt.id.clone());
            let summary = evt.summary.clone().unwrap_or_default();
            sqlx::query(
                "INSERT INTO gcal_events
                     (id, user_id, title, start_at, end_at, description, html_link,
                      google_event_id, updated_at_remote, calendar_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (user_id, calendar_id, google_event_id)
                     WHERE google_event_id IS NOT NULL
                 DO UPDATE SET
                     title             = EXCLUDED.title,
                     start_at          = EXCLUDED.start_at,
                     end_at            = EXCLUDED.end_at,
                     description       = EXCLUDED.description,
                     html_link         = EXCLUDED.html_link,
                     updated_at_remote = EXCLUDED.updated_at_remote",
            )
            .bind(Uuid::new_v4())
            .bind(user_id)
            .bind(&summary)
            .bind(start)
            .bind(end)
            .bind(evt.description.as_deref())
            .bind(evt.html_link.as_deref())
            .bind(&evt.id)
            .bind(evt.updated)
            .bind(&cal.id)
            .execute(&mut *tx)
            .await?;
        }
    }
    // Drop events for calendars the user unsubscribed/unselected since
    // last sync — without this they'd linger forever even though Google
    // no longer treats them as part of the user's calendar set.
    let current_cal_ids: Vec<String> = calendars.iter().map(|c| c.id.clone()).collect();
    sqlx::query(
        "DELETE FROM gcal_events
         WHERE user_id = $1
           AND NOT (calendar_id = ANY($2))",
    )
    .bind(user_id)
    .bind(&current_cal_ids)
    .execute(&mut *tx)
    .await?;
    // Delete any in-window rows Google didn't return on this pass —
    // covers cancellations and events moved out of the window. Match
    // by (calendar_id, google_event_id) since the same id can appear
    // in multiple calendars (e.g. shared meeting).
    sqlx::query(
        "DELETE FROM gcal_events
         WHERE user_id = $1
           AND google_event_id IS NOT NULL
           AND start_at >= $2 AND start_at < $3
           AND NOT EXISTS (
               SELECT 1 FROM unnest($4::text[], $5::text[]) AS k(cid, evtid)
               WHERE k.cid = gcal_events.calendar_id
                 AND k.evtid = gcal_events.google_event_id
           )",
    )
    .bind(user_id)
    .bind(time_min)
    .bind(time_max)
    .bind(&keep_cal)
    .bind(&keep_evt)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE gcal_credentials
         SET last_sync_at = now(), last_sync_error = NULL
         WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

struct StoredCredentials {
    refresh_token: String,
    access_token: Option<String>,
    access_expires_at: Option<DateTime<Utc>>,
}

async fn load_credentials(
    pool: &PgPool,
    user_id: Uuid,
) -> sqlx::Result<Option<StoredCredentials>> {
    // `gcal_credentials.calendar_id` is left on the table for backward
    // compat with the single-calendar era but is no longer read —
    // multi-calendar sync discovers calendars via calendarList.list.
    let row: Option<(String, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT refresh_token, access_token, access_expires_at
         FROM gcal_credentials WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(r, a, e)| StoredCredentials {
        refresh_token: r,
        access_token: a,
        access_expires_at: e,
    }))
}

async fn upsert_credentials(
    pool: &PgPool,
    user_id: Uuid,
    refresh_token: &str,
    access_token: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
    email: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO gcal_credentials
             (user_id, refresh_token, access_token, access_expires_at,
              calendar_email, last_sync_error)
         VALUES ($1, $2, $3, $4, $5, NULL)
         ON CONFLICT (user_id) DO UPDATE
             SET refresh_token     = EXCLUDED.refresh_token,
                 access_token      = EXCLUDED.access_token,
                 access_expires_at = EXCLUDED.access_expires_at,
                 calendar_email    = COALESCE(EXCLUDED.calendar_email, gcal_credentials.calendar_email),
                 last_sync_error   = NULL",
    )
    .bind(user_id)
    .bind(refresh_token)
    .bind(access_token)
    .bind(expires_at)
    .bind(email)
    .execute(pool)
    .await?;
    Ok(())
}

async fn exchange_code(
    cfg: &crate::auth::AuthConfig,
    code: &str,
) -> Result<GoogleTokenResponse, SyncError> {
    let redirect = gcal_redirect_url(cfg);
    let client = reqwest::Client::new();
    let res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", cfg.google_client_id.as_str()),
            ("client_secret", cfg.google_client_secret.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<GoogleTokenResponse>()
        .await?;
    Ok(res)
}

struct RefreshedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
    // Apps in Testing mode rotate refresh tokens — Google returns a
    // new one in the refresh response and invalidates the old one
    // after a short grace window. If we don't capture and persist
    // the rotated value, the next refresh hits `invalid_grant` and
    // the user has to reconnect.
    rotated_refresh_token: Option<String>,
}

async fn refresh_access_token(
    cfg: &crate::auth::AuthConfig,
    refresh_token: &str,
) -> Result<RefreshedToken, SyncError> {
    #[derive(Deserialize)]
    struct RefreshResponse {
        access_token: String,
        expires_in: i64,
        #[serde(default)]
        refresh_token: Option<String>,
    }
    #[derive(Deserialize)]
    struct ErrorResponse {
        error: String,
    }
    let client = reqwest::Client::new();
    // Inspect the body manually so we can distinguish `invalid_grant`
    // (refresh token dead — user must reconnect) from generic 4xx/5xx
    // (transient — keep the row, bubble up). `error_for_status()`
    // would fold both into the same opaque reqwest error.
    let res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", cfg.google_client_id.as_str()),
            ("client_secret", cfg.google_client_secret.as_str()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await?;
    let status = res.status();
    let body = res.text().await?;
    if !status.is_success() {
        let invalid_grant = serde_json::from_str::<ErrorResponse>(&body)
            .map(|e| e.error == "invalid_grant")
            .unwrap_or(false);
        return Err(SyncError {
            message: format!("refresh failed ({}): {}", status, body),
            invalid_grant,
        });
    }
    let parsed: RefreshResponse = serde_json::from_str(&body)
        .map_err(|e| SyncError { message: e.to_string(), invalid_grant: false })?;
    Ok(RefreshedToken {
        access_token: parsed.access_token,
        expires_at: Utc::now() + Duration::seconds(parsed.expires_in),
        rotated_refresh_token: parsed.refresh_token.filter(|t| !t.is_empty()),
    })
}

async fn fetch_userinfo(access_token: &str) -> Result<GoogleUserInfo, SyncError> {
    let client = reqwest::Client::new();
    let res = client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?
        .json::<GoogleUserInfo>()
        .await?;
    Ok(res)
}

#[derive(Debug)]
struct ParsedEvent {
    id: String,
    summary: Option<String>,
    description: Option<String>,
    html_link: Option<String>,
    start_dt: Option<DateTime<Utc>>,
    end_dt: Option<DateTime<Utc>>,
    updated: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct EventsListResponse {
    #[serde(default)]
    items: Vec<RawEvent>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct RawEvent {
    id: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "htmlLink", default)]
    html_link: Option<String>,
    #[serde(default)]
    updated: Option<DateTime<Utc>>,
    #[serde(default)]
    start: Option<RawTime>,
    #[serde(default)]
    end: Option<RawTime>,
}

#[derive(Deserialize, Default)]
struct RawTime {
    #[serde(rename = "dateTime", default)]
    date_time: Option<DateTime<Utc>>,
    // `date` (all-day) intentionally not parsed — we ignore those rows
    // until the calendar grid grows an all-day strip.
}

#[derive(Debug)]
struct CalendarListEntry {
    id: String,
}

#[derive(Deserialize)]
struct CalendarListResponse {
    #[serde(default)]
    items: Vec<RawCalendarListEntry>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct RawCalendarListEntry {
    id: String,
    // `selected` is the user's "show on the grid" toggle in Google's
    // UI. Absent means selected (per Google's docs). We treat
    // unselected calendars as opt-out so users get a way to silence
    // noisy calendars (e.g. shared team calendars) without us adding
    // a settings page.
    #[serde(default)]
    selected: Option<bool>,
    // Owners get `owner`/`writer`; shared subscriptions get `reader`.
    // `freeBusyReader` means we can only see busy/free blocks, not
    // event details — useless for the grid, so we skip them.
    #[serde(rename = "accessRole", default)]
    access_role: Option<String>,
}

async fn fetch_calendar_list(access_token: &str) -> Result<Vec<CalendarListEntry>, SyncError> {
    // Paginate just like fetch_events — most users have <50 calendars
    // so a single page covers it, but the cap (20 pages × ~250) keeps
    // a misbehaving response from looping.
    let url = "https://www.googleapis.com/calendar/v3/users/me/calendarList";
    let client = reqwest::Client::new();
    let mut out: Vec<CalendarListEntry> = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..20 {
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(t) = &page_token {
            query.push(("pageToken", t.clone()));
        }
        let res = client
            .get(url)
            .bearer_auth(access_token)
            .query(&query)
            .send()
            .await?
            .error_for_status()?
            .json::<CalendarListResponse>()
            .await?;
        for entry in res.items {
            if entry.selected == Some(false) {
                continue;
            }
            if entry.access_role.as_deref() == Some("freeBusyReader") {
                continue;
            }
            out.push(CalendarListEntry { id: entry.id });
        }
        match res.next_page_token {
            Some(t) if !t.is_empty() => page_token = Some(t),
            _ => return Ok(out),
        }
    }
    Err(SyncError {
        message: "calendarList.list exceeded pagination cap (20 pages)".into(),
        invalid_grant: false,
    })
}

async fn fetch_events(
    access_token: &str,
    calendar_id: &str,
    time_min: DateTime<Utc>,
    time_max: DateTime<Utc>,
) -> Result<Vec<ParsedEvent>, SyncError> {
    // Paginate via nextPageToken. Without this, busy calendars with
    // >250 events in the window get truncated to the earliest 250
    // (orderBy=startTime asc), so current/future events silently
    // disappear while past ones stay visible.
    let url = format!(
        "https://www.googleapis.com/calendar/v3/calendars/{}/events",
        urlencoding_encode(calendar_id),
    );
    let client = reqwest::Client::new();
    let time_min_s = time_min.to_rfc3339();
    let time_max_s = time_max.to_rfc3339();
    let mut out: Vec<ParsedEvent> = Vec::new();
    let mut page_token: Option<String> = None;
    // Safety cap. 20 pages × 250 = 5000 events in a 10-week window;
    // anything beyond that is almost certainly a misconfigured calendar
    // and we'd rather bail than spin forever.
    for _ in 0..20 {
        let mut query: Vec<(&str, String)> = vec![
            ("timeMin", time_min_s.clone()),
            ("timeMax", time_max_s.clone()),
            ("singleEvents", "true".to_string()),
            ("orderBy", "startTime".to_string()),
            ("maxResults", "250".to_string()),
        ];
        if let Some(t) = &page_token {
            query.push(("pageToken", t.clone()));
        }
        let res = client
            .get(&url)
            .bearer_auth(access_token)
            .query(&query)
            .send()
            .await?
            .error_for_status()?
            .json::<EventsListResponse>()
            .await?;
        out.extend(
            res.items
                .into_iter()
                .filter(|e| e.status.as_deref() != Some("cancelled"))
                .map(|e| ParsedEvent {
                    id: e.id,
                    summary: e.summary,
                    description: e.description,
                    html_link: e.html_link,
                    start_dt: e.start.and_then(|t| t.date_time),
                    end_dt: e.end.and_then(|t| t.date_time),
                    updated: e.updated,
                }),
        );
        match res.next_page_token {
            Some(t) if !t.is_empty() => page_token = Some(t),
            _ => return Ok(out),
        }
    }
    Err(SyncError {
        message: "events.list exceeded pagination cap (20 pages)".into(),
        invalid_grant: false,
    })
}

// ---- helpers ----

fn gcal_redirect_url(cfg: &crate::auth::AuthConfig) -> String {
    // The signup redirect ends in `/api/auth/google/callback`; replace
    // the suffix to land at the gcal callback. Falls back to deriving
    // from app_base_url if the signup URL doesn't match the expected
    // shape.
    if let Some(base) = cfg
        .redirect_url
        .strip_suffix("/api/auth/google/callback")
    {
        return format!("{base}/api/gcal/callback");
    }
    std::env::var("OAUTH_GCAL_REDIRECT_URL")
        .unwrap_or_else(|_| format!("{}/api/gcal/callback", cfg.app_base_url))
}

fn build_cookie<'a>(
    name: &'static str,
    value: String,
    max_age_secs: i64,
    cfg: &crate::auth::AuthConfig,
) -> Cookie<'a> {
    let mut c = Cookie::new(name, value);
    c.set_path("/");
    c.set_http_only(true);
    c.set_secure(cfg.cookie_secure);
    c.set_same_site(SameSite::Lax);
    c.set_max_age(time::Duration::seconds(max_age_secs));
    c
}

fn clear_cookie<'a>(name: &'static str, cfg: &crate::auth::AuthConfig) -> Cookie<'a> {
    let mut c = Cookie::new(name, "");
    c.set_path("/");
    c.set_http_only(true);
    c.set_secure(cfg.cookie_secure);
    c.set_same_site(SameSite::Lax);
    c.set_max_age(time::Duration::seconds(0));
    c
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}

fn querystring(pairs: &[(&str, &str)]) -> String {
    let mut s = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            s.push('&');
        }
        s.push_str(&urlencoding_encode(k));
        s.push('=');
        s.push_str(&urlencoding_encode(v));
    }
    s
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub connected: bool,
    pub email: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
}
