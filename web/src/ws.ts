// WebSocket nudge client.
//
// Opens /api/ws?workspace_id=<id> and on each `{"new_cursor": N}` message
// fires the supplied callback (which the app uses to call pollChanges()).
// The poll-based fetcher remains the source of truth; WS only nudges. So
// reconnect logic is best-effort: on close, back off and retry forever.
// While disconnected the existing 60s poll fallback covers gaps.

type Nudge = { new_cursor: number };

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
      socket?.close();
    },
  };
}
