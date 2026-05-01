// Google OAuth (authorization code flow) + opaque session cookies.
//
// Flow:
//   1. GET /auth/google/login         → 302 to Google with random state
//                                        (state stored in a short-lived cookie)
//   2. Google redirects back to        /auth/google/callback?code=&state=
//   3. Server exchanges code for tokens, fetches userinfo, upserts the user,
//      creates a row in `sessions`, sets the `sid` cookie, redirects to /.
//   4. Every authenticated request carries `sid`; middleware looks it up.
//
// Cookies:
//   - `sid`           — opaque session id, HttpOnly, SameSite=Lax, ~30 days.
//   - `oauth_state`   — random nonce for CSRF on the callback, 5 min.
//
// In dev (DEV_AUTH=1), an extra `/auth/dev-login?email=...` endpoint creates
// a session for an existing user without going through Google.

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

const SESSION_COOKIE: &str = "sid";
const OAUTH_STATE_COOKIE: &str = "oauth_state";
const SESSION_DAYS: i64 = 30;
const STATE_TTL_SECONDS: i64 = 300;
const WORKSPACE_HEADER: &str = "x-workspace-id";

#[derive(Clone)]
pub struct AuthConfig {
    pub google_client_id: String,
    pub google_client_secret: String,
    pub redirect_url: String,
    pub app_base_url: String,
    pub cookie_secure: bool,
    pub dev_auth: bool,
}

impl AuthConfig {
    pub fn from_env() -> Self {
        Self {
            google_client_id: std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
            google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
            redirect_url: std::env::var("OAUTH_REDIRECT_URL")
                .unwrap_or_else(|_| "http://localhost:5173/api/auth/google/callback".into()),
            // Note: dev callback path is `/api/auth/google/callback` — Vite
            // proxies it to the api unchanged. In prod the api serves both,
            // so the same path works there too.
            app_base_url: std::env::var("APP_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:5173".into()),
            cookie_secure: std::env::var("COOKIE_SECURE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            // DEV_AUTH only consulted when the `dev_auth` feature is on. Prod
            // builds compile this branch out so the env var can't accidentally
            // re-enable the dev endpoints.
            #[cfg(feature = "dev_auth")]
            dev_auth: std::env::var("DEV_AUTH")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            #[cfg(not(feature = "dev_auth"))]
            dev_auth: false,
        }
    }
}

#[derive(Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub initials: String,
    pub avatar_url: Option<String>,
}

// Extractor: any handler that takes `AuthUser` is automatically protected.
// 401 if no valid session cookie.
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let jar = CookieJar::from_headers(&parts.headers);
        let sid = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .ok_or_else(unauthorized)?;
        load_session_user(&app_state.pool, &sid)
            .await
            .map_err(|_| unauthorized())?
            .ok_or_else(unauthorized)
    }
}

/// Authenticated user *and* the workspace they're operating in. The
/// workspace is taken from the `X-Workspace-Id` header — clients send it
/// after `/me` tells them which workspaces exist. If the header is missing,
/// invalid, or doesn't refer to a workspace the user belongs to, the
/// request is rejected with 401.
#[derive(Clone)]
pub struct AuthCtx {
    pub user: AuthUser,
    pub workspace_id: Uuid,
    pub role: String,
}

impl AuthCtx {
    pub fn is_owner(&self) -> bool { self.role == "owner" }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthCtx
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        let app_state = AppState::from_ref(state);
        let header = parts
            .headers
            .get(WORKSPACE_HEADER)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| forbidden("workspace header required"))?;
        let workspace_id: Uuid = header
            .parse()
            .map_err(|_| forbidden("invalid workspace id"))?;
        let role = crate::db::workspace_role(&app_state.pool, workspace_id, user.id)
            .await
            .map_err(|_| forbidden("workspace lookup failed"))?
            .ok_or_else(|| forbidden("not a workspace member"))?;
        Ok(AuthCtx { user, workspace_id, role })
    }
}

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unauthorized" })))
        .into_response()
}

pub async fn load_session_user(pool: &PgPool, sid: &str) -> sqlx::Result<Option<AuthUser>> {
    let row: Option<(Uuid, String, String, String, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT u.id, u.email, u.name, u.initials, u.avatar_url, s.expires_at
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.id = $1",
    )
    .bind(sid)
    .fetch_optional(pool)
    .await?;
    let Some((id, email, name, initials, avatar_url, expires_at)) = row else {
        return Ok(None);
    };
    if expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(sid)
            .execute(pool)
            .await;
        return Ok(None);
    }
    Ok(Some(AuthUser { id, email, name, initials, avatar_url }))
}

// ---- /auth/config ----
//
// Public, unauthenticated config endpoint. Lets the login screen know
// whether to render the "Seed dev data" affordance — we don't want that
// button visible (or its endpoint reachable) in production.

#[derive(Serialize)]
pub struct AuthConfigResponse {
    pub dev_auth: bool,
}

pub async fn config(State(s): State<AppState>) -> Json<AuthConfigResponse> {
    Json(AuthConfigResponse { dev_auth: s.auth.dev_auth })
}

// ---- /me ----

#[derive(Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub initials: String,
    pub avatar_url: Option<String>,
}

pub async fn me(user: AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        initials: user.initials,
        avatar_url: user.avatar_url,
    })
}

// ---- /auth/logout ----

pub async fn logout(
    State(s): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    if let Some(sid) = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()) {
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(sid)
            .execute(&s.pool)
            .await;
    }
    let cleared = clear_cookie(SESSION_COOKIE, &s.auth);
    Ok((jar.add(cleared), StatusCode::NO_CONTENT))
}

// ---- /auth/google/login ----

pub async fn google_login(State(s): State<AppState>, jar: CookieJar) -> Response {
    if s.auth.google_client_id.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Google OAuth not configured (GOOGLE_CLIENT_ID missing)",
        )
            .into_response();
    }
    let state = random_token(24);
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?{}",
        querystring(&[
            ("client_id", &s.auth.google_client_id),
            ("redirect_uri", &s.auth.redirect_url),
            ("response_type", "code"),
            ("scope", "openid email profile"),
            ("state", &state),
            ("prompt", "select_account"),
            ("access_type", "online"),
        ]),
    );
    let state_cookie = build_cookie(OAUTH_STATE_COOKIE, state, STATE_TTL_SECONDS, &s.auth);
    (jar.add(state_cookie), Redirect::to(&url)).into_response()
}

// ---- /auth/google/callback ----

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

pub async fn google_callback(
    State(s): State<AppState>,
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
    let cookie_state = jar.get(OAUTH_STATE_COOKIE).map(|c| c.value().to_string());
    if cookie_state.as_deref() != Some(state_param.as_str()) {
        return (StatusCode::BAD_REQUEST, "state mismatch").into_response();
    }

    let token_res: GoogleTokenResponse = match exchange_code(&s.auth, &code).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("token exchange failed: {e:?}");
            return (StatusCode::BAD_GATEWAY, "token exchange failed").into_response();
        }
    };

    let info: GoogleUserInfo = match fetch_userinfo(&token_res.access_token).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("userinfo fetch failed: {e:?}");
            return (StatusCode::BAD_GATEWAY, "userinfo fetch failed").into_response();
        }
    };

    let user_id = match upsert_user(&s.pool, &info).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("upsert user failed: {e:?}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "user upsert failed").into_response();
        }
    };

    // Personal workspace is the universal landing pad — every user has one.
    // Idempotent so repeat logins don't churn.
    let display_name = info.name.clone().unwrap_or_else(|| info.email.clone());
    if let Err(e) = crate::db::ensure_personal_workspace(&s.pool, user_id, &display_name).await {
        tracing::error!("ensure_personal_workspace failed: {e:?}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "workspace setup failed").into_response();
    }

    let sid = match create_session(&s.pool, user_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("session create failed: {e:?}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "session create failed").into_response();
        }
    };

    let session_cookie = build_cookie(SESSION_COOKIE, sid, SESSION_DAYS * 86400, &s.auth);
    let cleared_state = clear_cookie(OAUTH_STATE_COOKIE, &s.auth);
    let jar = jar.add(session_cookie).add(cleared_state);
    (jar, Redirect::to(&s.auth.app_base_url)).into_response()
}

async fn exchange_code(cfg: &AuthConfig, code: &str) -> anyhow::Result<GoogleTokenResponse> {
    let client = reqwest::Client::new();
    let res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", cfg.google_client_id.as_str()),
            ("client_secret", cfg.google_client_secret.as_str()),
            ("redirect_uri", cfg.redirect_url.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<GoogleTokenResponse>()
        .await?;
    Ok(res)
}

async fn fetch_userinfo(access_token: &str) -> anyhow::Result<GoogleUserInfo> {
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

async fn upsert_user(pool: &PgPool, info: &GoogleUserInfo) -> sqlx::Result<Uuid> {
    let display_name = info.name.clone().unwrap_or_else(|| info.email.clone());
    let initials = compute_initials(&display_name, &info.email);
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (id, email, name, initials, google_sub, avatar_url)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (google_sub) WHERE google_sub IS NOT NULL
         DO UPDATE SET email = EXCLUDED.email,
                       name = EXCLUDED.name,
                       avatar_url = EXCLUDED.avatar_url
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(&info.email)
    .bind(&display_name)
    .bind(&initials)
    .bind(&info.sub)
    .bind(info.picture.as_deref())
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

fn compute_initials(name: &str, email: &str) -> String {
    let parts: Vec<&str> = name
        .split_whitespace()
        .filter(|p| !p.is_empty())
        .collect();
    if !parts.is_empty() {
        let mut s = String::new();
        if let Some(c) = parts[0].chars().next() {
            s.push(c.to_ascii_uppercase());
        }
        if let Some(last) = parts.get(1).and_then(|p| p.chars().next()) {
            s.push(last.to_ascii_uppercase());
        }
        if !s.is_empty() {
            return s;
        }
    }
    email
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string())
}

async fn create_session(pool: &PgPool, user_id: Uuid) -> sqlx::Result<String> {
    let sid = random_token(32);
    let expires = Utc::now() + Duration::days(SESSION_DAYS);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&sid)
    .bind(user_id)
    .bind(expires)
    .execute(pool)
    .await?;
    Ok(sid)
}

// ---- dev login (no Google) ----

#[cfg(feature = "dev_auth")]
#[derive(Deserialize)]
pub struct DevLoginParams {
    email: String,
}

#[cfg(feature = "dev_auth")]
pub async fn dev_login(
    State(s): State<AppState>,
    jar: CookieJar,
    Query(p): Query<DevLoginParams>,
) -> Response {
    if !s.auth.dev_auth {
        return StatusCode::NOT_FOUND.into_response();
    }
    let row: Option<(Uuid,)> = match sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&p.email)
        .fetch_optional(&s.pool)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("dev_login lookup failed: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let Some((user_id,)) = row else {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    };
    let sid = match create_session(&s.pool, user_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("dev_login session failed: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let cookie = build_cookie(SESSION_COOKIE, sid, SESSION_DAYS * 86400, &s.auth);
    (jar.add(cookie), Redirect::to(&s.auth.app_base_url)).into_response()
}

// ---- /auth/dev-seed ----
//
// Dev-only convenience: wipe + reseed the fixture project, then drop a
// session for the primary fixture user (Maya). Equivalent to running the
// `seed` CLI binary and then `dev-login?email=maya@fira.dev`, but in one
// click from the login page.
//
// Refuses to run unless DEV_AUTH=1, both as a guard against shipping it to
// production and so the login UI can hide the button by reading /auth/config.

#[cfg(feature = "dev_auth")]
pub async fn dev_seed(State(s): State<AppState>, jar: CookieJar) -> Response {
    if !s.auth.dev_auth {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut tx = match s.pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("dev_seed begin failed: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if let Err(e) = crate::seed::wipe(&mut tx).await {
        tracing::error!("dev_seed wipe failed: {e:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = crate::seed::seed_all(&mut tx).await {
        tracing::error!("dev_seed seed_all failed: {e:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = tx.commit().await {
        tracing::error!("dev_seed commit failed: {e:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let user_id = crate::seed::primary_user_id();
    let sid = match create_session(&s.pool, user_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("dev_seed session failed: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let cookie = build_cookie(SESSION_COOKIE, sid, SESSION_DAYS * 86400, &s.auth);
    (jar.add(cookie), StatusCode::NO_CONTENT).into_response()
}

// ---- helpers ----

fn build_cookie<'a>(
    name: &'static str,
    value: String,
    max_age_secs: i64,
    cfg: &AuthConfig,
) -> Cookie<'a> {
    let mut c = Cookie::new(name, value);
    c.set_path("/");
    c.set_http_only(true);
    c.set_secure(cfg.cookie_secure);
    c.set_same_site(SameSite::Lax);
    c.set_max_age(time::Duration::seconds(max_age_secs));
    c
}

fn clear_cookie<'a>(name: &'static str, cfg: &AuthConfig) -> Cookie<'a> {
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
        s.push_str(&urlencoding::encode_component(k));
        s.push('=');
        s.push_str(&urlencoding::encode_component(v));
    }
    s
}

mod urlencoding {
    pub fn encode_component(s: &str) -> String {
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
}

