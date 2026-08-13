// WebSocket nudge client.
//
// Two flavours, both opaque-nudge-then-refetch:
//   - openNudgeSocket(workspaceId, onNudge): per-workspace, scoped to in-
//     workspace data ops. Server emits {"new_cursor": N}.
//   - openUserSocket(onNudge): per-session, scoped to "your workspace
//     surface changed" events (membership, roles, workspace add/rename/
//     delete). Server emits {"user_changed": true}.
//
// The poll-based fetchers remain the source of truth; WS only nudges. So
// reconnect logic is best-effort: on close, back off and retry forever.
// While disconnected the existing poll fallbacks cover gaps.

import { syncLog } from './synclog';

type Nudge = { new_cursor: number };
type UserNudge = { user_changed: true };

// How many sockets are actually established right now, across both flavours.
// Reported on every open/close line so the log answers "did that leak?" by
// itself rather than by counting lines.
//
// Steady state is 2 (one workspace + one user), 0 once the tab goes idle.
// Seeing it climb past 2 while awake is the real leak signal — as opposed to
// the open/close churn at startup, which is React StrictMode double-mounting
// effects in dev and settles back to 2.
//
// Counted in onopen/onclose rather than at construction, because a socket
// that never connects (server down) fires onclose without ever firing onopen;
// the per-connection `counted` flag keeps those from driving the total
// negative.
let liveSockets = 0;

export interface WsHandle {
  close(): void;
}

export function openNudgeSocket(workspaceId: string, onNudge: () => void): WsHandle {
  let socket: WebSocket | null = null;
  let closed = false;
  let backoffMs = 1000;
  let reconnectTimer: number | null = null;

  const url = (() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/api/ws?workspace_id=${encodeURIComponent(workspaceId)}`;
  })();

  const connect = () => {
    if (closed) return;
    let counted = false; // scoped per connection attempt, not per handle
    socket = new WebSocket(url);
    socket.onopen = () => {
      counted = true;
      liveSockets += 1;
      syncLog(`  ✓ workspace socket open (ws ${workspaceId.slice(0, 8)}, ${liveSockets} live)`);
      backoffMs = 1000; // reset on a successful open
      // React StrictMode mounts the effect twice in dev — by the time the
      // second mount runs its cleanup the socket may already be open. If
      // closure was requested while we were still CONNECTING, honour it now
      // rather than triggering "closed before established" in the browser.
      if (closed) socket?.close();
    };
    socket.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data) as Nudge;
        if (typeof msg.new_cursor === 'number') onNudge();
      } catch {
        // Ignore non-JSON frames (server doesn't send any today, but a
        // future heartbeat or version banner shouldn't break the client).
      }
    };
    socket.onclose = () => {
      if (counted) { liveSockets -= 1; counted = false; }
      socket = null;
      if (closed) {
        // Deliberate teardown — going idle, or switching workspace.
        syncLog(`  ✗ workspace socket closed, intentional (${liveSockets} live)`);
        return;
      }
      // Cap at 30s — long enough that we're not hammering on a bad network,
      // short enough that the socket recovers quickly when it can.
      const delay = Math.min(backoffMs, 30_000);
      backoffMs = Math.min(backoffMs * 2, 30_000);
      syncLog(`  ✗ workspace socket dropped (${liveSockets} live) — reconnecting in ${delay / 1000}s`);
      reconnectTimer = window.setTimeout(connect, delay);
    };
    socket.onerror = () => {
      // onclose will follow; nothing to do here.
    };
  };

  connect();

  return {
    close() {
      closed = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      // Only close if the handshake is past CONNECTING — otherwise let
      // onopen pick up the `closed` flag and close cleanly.
      if (socket && socket.readyState === WebSocket.OPEN) socket.close();
    },
  };
}

export function openUserSocket(onNudge: () => void): WsHandle {
  let socket: WebSocket | null = null;
  let closed = false;
  let backoffMs = 1000;
  let reconnectTimer: number | null = null;

  const url = (() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/api/ws/user`;
  })();

  const connect = () => {
    if (closed) return;
    let counted = false;
    socket = new WebSocket(url);
    socket.onopen = () => {
      counted = true;
      liveSockets += 1;
      syncLog(`  ✓ user socket open (${liveSockets} live)`);
      backoffMs = 1000;
      if (closed) socket?.close();
    };
    socket.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data) as UserNudge;
        if (msg.user_changed === true) onNudge();
      } catch {
        // Future heartbeat or version banner shouldn't break the client.
      }
    };
    socket.onclose = () => {
      if (counted) { liveSockets -= 1; counted = false; }
      socket = null;
      if (closed) {
        syncLog(`  ✗ user socket closed, intentional (${liveSockets} live)`);
        return;
      }
      const delay = Math.min(backoffMs, 30_000);
      backoffMs = Math.min(backoffMs * 2, 30_000);
      syncLog(`  ✗ user socket dropped (${liveSockets} live) — reconnecting in ${delay / 1000}s`);
      reconnectTimer = window.setTimeout(connect, delay);
    };
    socket.onerror = () => { /* onclose follows */ };
  };

  connect();

  return {
    close() {
      closed = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      if (socket && socket.readyState === WebSocket.OPEN) socket.close();
    },
  };
}
