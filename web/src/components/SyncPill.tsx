import { Check, CloudOff, Loader2, AlertTriangle } from 'lucide-react';
import { useFira } from '../store';

// Compact status indicator for outbox sync. Reads three slices of state to
// decide what to show:
//   - syncStatus.kind drives icon + tone (idle / syncing / error / offline)
//   - outbox.length drives the "N pending" hint while idle
//   - lastSyncedAt powers the tooltip ("synced 12s ago")
export function SyncPill() {
  const status = useFira((s) => s.syncStatus);
  const pending = useFira((s) =>
    s.outbox.filter((o) => o.status !== 'syncing').length
  );
  const lastSyncedAt = useFira((s) => s.lastSyncedAt);
  const syncOutbox = useFira((s) => s.syncOutbox);

  let label: string;
  let tone: 'ok' | 'pending' | 'syncing' | 'error' | 'offline';
  let Icon = Check;
  let title = '';

  if (status.kind === 'syncing') {
    label = 'Syncing…';
    tone = 'syncing';
    Icon = Loader2;
    title = 'Sending edits to the server';
  } else if (status.kind === 'error') {
    label = `Error · ${status.failedOpIds.length}`;
    tone = 'error';
    Icon = AlertTriangle;
    title = `${status.message} — click to retry`;
  } else if (status.kind === 'offline') {
    label = 'Offline';
    tone = 'offline';
    Icon = CloudOff;
    title = `Couldn't reach server (${status.message}) — will retry automatically`;
  } else if (pending > 0) {
    label = `${pending} pending`;
    tone = 'pending';
    Icon = Loader2;
    title = `${pending} edit${pending === 1 ? '' : 's'} queued`;
  } else {
    label = 'Synced';
    tone = 'ok';
    Icon = Check;
    title = lastSyncedAt
      ? `All edits saved · ${fmtRelative(Date.now() - lastSyncedAt)} ago`
      : 'All edits saved';
  }

  return (
    <button
      className="sync-pill"
      data-tone={tone}
      onClick={() => { void syncOutbox(); }}
      title={title}
    >
      <Icon
        size={11}
        strokeWidth={2}
        className={tone === 'syncing' ? 'sync-pill-spin' : undefined}
      />
      <span>{label}</span>
    </button>
  );
}

function fmtRelative(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  return `${h}h`;
}
