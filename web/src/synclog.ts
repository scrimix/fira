// Tracing for the background-sync lifecycle.
//
// The idle/wake behaviour is invisible from the UI by design: sockets close a
// couple of minutes after you switch tabs, timers stand down, a catch-up runs
// on the way back — and none of it draws a pixel. When someone reports "it
// stopped syncing", their console is the only place that can answer why, so
// the lifecycle tier ships to production.
//
// Two tiers:
//   syncLog     — state changes. Sleep, wake, sockets connecting and dropping.
//                 A handful of lines per session. Always on.
//   syncLogDev  — heartbeat detail. Timer ticks, nudges. One line per tick, so
//                 it would be steady noise in a long-lived tab. Dev only; Vite
//                 replaces `import.meta.env.DEV` with a literal `false` and the
//                 minifier drops the calls from production bundles.
//
// Deliberately *not* logged: effect setup/teardown. It duplicates what SLEEP
// and WAKE already say, and reports intent rather than outcome — the socket
// lines below report what the connection actually did.

function emit(msg: string, rest: unknown[]): void {
  const t = new Date().toLocaleTimeString();
  // eslint-disable-next-line no-console
  console.log(
    `%c[sync]%c ${t}  ${msg}`,
    'color:#4c8dff;font-weight:600',
    'color:inherit',
    ...rest,
  );
}

export function syncLog(msg: string, ...rest: unknown[]): void {
  emit(msg, rest);
}

export function syncLogDev(msg: string, ...rest: unknown[]): void {
  if (!import.meta.env.DEV) return;
  emit(msg, rest);
}

// Human-readable elapsed time for the log lines above ("8m 12s"). Coarse on
// purpose — this is for reading at a glance, not for measurement.
export function fmtElapsed(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}
