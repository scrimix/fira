// Cross-instance change-feed bus.
//
// Each API process holds an in-memory `Hub` that maps workspace_id →
// `tokio::sync::broadcast::Sender<i64>`. WebSocket connections subscribe to
// the sender for their workspace; the value broadcast is the new processed_ops
// `seq` (clients refetch via GET /api/changes after a nudge).
//
// To make this work across multiple API instances (Fly auto-scales >1 machine
// at peak), the write path issues `pg_notify('ops_changes', '<ws>:<seq>')`
// inside the same transaction that inserts into `processed_ops`. NOTIFY is
// transactional in Postgres: it fires only on commit, so a rolled-back op
// never nudges anyone. Each API instance runs `start_listener_task` once at
// boot, which holds a `PgListener` that LISTENs on `ops_changes` and forwards
// every incoming notification into the local Hub. A write on machine A is
// observed by machine B's listener, which fans it out to B's local WS clients.

use sqlx::{postgres::PgListener, PgPool};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use uuid::Uuid;

// Two independent channels:
//   - ops_changes: workspace-scoped change-feed nudges (carries new seq).
//     Subscribers are gated by workspace membership.
//   - user_changes: user-scoped opaque "your workspace surface changed"
//     nudges. Subscribers are gated by session only — used for membership /
//     role / workspace-list events that themselves *decide* membership and
//     therefore can't ride the workspace-scoped feed (chicken/egg).
const OPS_CHANNEL: &str = "ops_changes";
const USER_CHANNEL: &str = "user_changes";
const BUFFER: usize = 64;

#[derive(Default)]
pub struct Hub {
    chans: Mutex<HashMap<Uuid, broadcast::Sender<i64>>>,
    users: Mutex<HashMap<Uuid, broadcast::Sender<()>>>,
}

impl Hub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Get-or-create the broadcast sender for a workspace. Cheap to call on
    /// every notify; the entry sticks around forever (one channel per active
    /// workspace, fine for our scale).
    fn sender(&self, ws: Uuid) -> broadcast::Sender<i64> {
        let mut g = self.chans.lock().unwrap();
        g.entry(ws)
            .or_insert_with(|| broadcast::channel(BUFFER).0)
            .clone()
    }

    fn user_sender(&self, user_id: Uuid) -> broadcast::Sender<()> {
        let mut g = self.users.lock().unwrap();
        g.entry(user_id)
            .or_insert_with(|| broadcast::channel(BUFFER).0)
            .clone()
    }

    pub fn subscribe(&self, ws: Uuid) -> broadcast::Receiver<i64> {
        self.sender(ws).subscribe()
    }

    pub fn subscribe_user(&self, user_id: Uuid) -> broadcast::Receiver<()> {
        self.user_sender(user_id).subscribe()
    }

    /// Local fan-out. Called from the listener task; never call this from the
    /// write path (writes go through pg_notify so other instances see them).
    fn dispatch(&self, ws: Uuid, seq: i64) {
        // send() Err only when no receivers — that's normal (no clients
        // connected for this workspace right now), drop silently.
        let _ = self.sender(ws).send(seq);
    }

    fn dispatch_user(&self, user_id: Uuid) {
        let _ = self.user_sender(user_id).send(());
    }

    /// Cross-instance user nudge. Emit this from any handler that mutates a
    /// user's workspace surface (membership added/removed, role changed,
    /// workspace renamed/deleted). The opaque signal tells the client to
    /// refetch listMyWorkspaces and reconcile.
    pub async fn notify_user(&self, pool: &PgPool, user_id: Uuid) -> sqlx::Result<()> {
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(USER_CHANNEL)
            .bind(user_id.to_string())
            .execute(pool)
            .await?;
        Ok(())
    }
}

/// Spawns the LISTEN task. Runs forever; reconnects after backoff on errors.
pub fn start_listener_task(pool: PgPool, hub: Arc<Hub>) {
    tokio::spawn(async move {
        loop {
            match listen_loop(&pool, &hub).await {
                Ok(()) => {
                    tracing::warn!("pg listener exited cleanly, restarting");
                }
                Err(e) => {
                    tracing::warn!("pg listener error: {e:#}, restarting in 5s");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn listen_loop(pool: &PgPool, hub: &Hub) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(OPS_CHANNEL).await?;
    listener.listen(USER_CHANNEL).await?;
    tracing::info!("pg listener subscribed to {OPS_CHANNEL}, {USER_CHANNEL}");
    loop {
        let n = listener.recv().await?;
        match n.channel() {
            OPS_CHANNEL => match parse_ops_payload(n.payload()) {
                Some((ws, seq)) => hub.dispatch(ws, seq),
                None => tracing::warn!("malformed ops_changes payload: {:?}", n.payload()),
            },
            USER_CHANNEL => match Uuid::parse_str(n.payload()) {
                Ok(uid) => hub.dispatch_user(uid),
                Err(_) => tracing::warn!("malformed user_changes payload: {:?}", n.payload()),
            },
            other => tracing::warn!("unexpected listen channel {other}"),
        }
    }
}

fn parse_ops_payload(s: &str) -> Option<(Uuid, i64)> {
    let (ws_str, seq_str) = s.split_once(':')?;
    let ws = Uuid::parse_str(ws_str).ok()?;
    let seq = seq_str.parse::<i64>().ok()?;
    Some((ws, seq))
}

/// Build the payload format the ops listener expects. Kept here so the write
/// path and the parser stay in lockstep.
pub fn format_payload(ws: Uuid, seq: i64) -> String {
    format!("{ws}:{seq}")
}
