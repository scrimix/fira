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

type Nudge = { new_cursor: number };
type UserNudge = { user_changed: true };

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
    socket = new WebSocket(url);
    socket.onopen = () => {
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
      socket = null;
      if (closed) return;
      // Cap at 30s — long enough that we're not hammering on a bad network,
      // short enough that the socket recovers quickly when it can.
      const delay = Math.min(backoffMs, 30_000);
      backoffMs = Math.min(backoffMs * 2, 30_000);
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
    socket = new WebSocket(url);
    socket.onopen = () => {
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
      socket = null;
      if (closed) return;
      const delay = Math.min(backoffMs, 30_000);
      backoffMs = Math.min(backoffMs * 2, 30_000);
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
