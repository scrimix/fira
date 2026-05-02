// WebSocket nudge channel.
//
// Server-push for the change feed. The wire protocol is intentionally minimal:
// the server sends `{"new_cursor": N}` whenever a new op has committed in a
// workspace this client subscribes to. The client treats it as a hint to call
// the existing GET /api/changes — keeping all scoping/auth logic in one place.
//
// Multi-instance fan-out is handled by `crate::pubsub`, which bridges
// Postgres LISTEN/NOTIFY into per-workspace `tokio::sync::broadcast` channels.
// Each WS connection subscribes to the broadcast channel for its workspace.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use axum_extra::extract::cookie::CookieJar;
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

use crate::{auth::load_session_user, AppState};

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub workspace_id: Uuid,
}

#[derive(Debug, Serialize)]
struct Nudge {
    new_cursor: i64,
}

#[derive(Debug, Serialize)]
struct UserNudge {
    user_changed: bool,
}

/// User-channel socket. One per signed-in user, regardless of which
/// workspace they're viewing — carries opaque "your workspace surface
/// changed" nudges so the client refetches listMyWorkspaces and reconciles.
/// Auth is session-only (no workspace gate); without this, membership
/// changes that *grant* access would have nowhere to be delivered to a
/// not-yet-member.
pub async fn user_ws_handler(
    State(s): State<AppState>,
    jar: CookieJar,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    let sid = match jar.get("sid") {
        Some(c) => c.value().to_string(),
        None => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    let user = match load_session_user(&s.pool, &sid).await {
        Ok(Some(u)) => u,
        _ => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    let rx = s.hub.subscribe_user(user.id);
    upgrade.on_upgrade(move |socket| pump_user(socket, rx))
}

async fn pump_user(socket: WebSocket, mut rx: tokio::sync::broadcast::Receiver<()>) {
    let (mut tx, mut rx_socket) = socket.split();
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            res = rx.recv() => {
                match res {
                    Ok(()) => {
                        let body = serde_json::to_string(&UserNudge { user_changed: true }).unwrap();
                        if tx.send(Message::Text(body)).await.is_err() { break; }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = ping_interval.tick() => {
                if tx.send(Message::Ping(Vec::new())).await.is_err() { break; }
            }
            msg = rx_socket.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}

pub async fn ws_handler(
    State(s): State<AppState>,
    Query(q): Query<WsQuery>,
    jar: CookieJar,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    // Auth via session cookie (browsers can't set arbitrary headers on WS).
    // Workspace scope comes from the query string for the same reason.
    let sid = match jar.get("sid") {
        Some(c) => c.value().to_string(),
        None => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    let user = match load_session_user(&s.pool, &sid).await {
        Ok(Some(u)) => u,
        _ => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    // Same membership check the AuthCtx extractor performs for REST routes.
    let role = match crate::db::workspace_role(&s.pool, q.workspace_id, user.id).await {
        Ok(Some(r)) => r,
        _ => return axum::http::StatusCode::FORBIDDEN.into_response(),
    };
    let _ = role; // membership confirmed; role doesn't affect nudge delivery

    let rx = s.hub.subscribe(q.workspace_id);
    upgrade.on_upgrade(move |socket| pump(socket, rx))
}

async fn pump(socket: WebSocket, mut rx: tokio::sync::broadcast::Receiver<i64>) {
    let (mut tx, mut rx_socket) = socket.split();

    // Heartbeat: server-side ping every 30s. Some intermediaries (Fly's edge,
    // load balancers) silently drop idle WS connections after ~60s, so we
    // keep them warm here. The client also pongs back automatically.
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // New seq from the local hub (fed by the pg listener task).
            res = rx.recv() => {
                match res {
                    Ok(seq) => {
                        let body = serde_json::to_string(&Nudge { new_cursor: seq }).unwrap();
                        if tx.send(Message::Text(body)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Client fell behind. The 60s poll fallback will catch
                        // them up; just keep streaming the next ones.
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = ping_interval.tick() => {
                if tx.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
            // Drain client → server frames so pings/closes are processed.
            // We don't expect any meaningful client messages.
            msg = rx_socket.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}
