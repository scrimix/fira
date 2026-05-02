import { useEffect, useRef, useState } from 'react';
import { Check, CloudOff, Loader2, AlertTriangle, X, RefreshCw } from 'lucide-react';
import { useFira } from '../store';

// Compact status indicator for outbox sync. Combines two signals into one
// label when they overlap — "Offline · 5 pending" is what the user actually
// wants to see when the api is down and they kept editing.
//
// Click the pill to expand a popover that lists failed ops (server-rejected
// edits) with per-op Retry / Discard actions. This is the place where the
// "rust returned 400 on a malformed url" case becomes visible: the op stays
// in the outbox, the user sees what kind it was and the error message, and
// can choose to retry (after fixing the input that caused it) or discard.
export function SyncPill() {
  const status = useFira((s) => s.syncStatus);
  const outbox = useFira((s) => s.outbox);
  const lastSyncedAt = useFira((s) => s.lastSyncedAt);
  const syncOutbox = useFira((s) => s.syncOutbox);
  const retryOp = useFira((s) => s.retryOp);
  const discardOp = useFira((s) => s.discardOp);
  const retryAllFailed = useFira((s) => s.retryAllFailed);
  const discardAllFailed = useFira((s) => s.discardAllFailed);

  const pending = outbox.filter((o) => o.status === 'queued' || o.status === 'syncing').length;
  const failed = outbox.filter((o) => o.status === 'error');
  const failedCount = failed.length;

  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  // Suppress the "Syncing…" flicker on fast round-trips. The 2 s tick fires
  // syncOutbox + pollChanges every cycle; when both finish in <300 ms, the
  // pill would flash through "Syncing… → Synced" on every tick, which reads
  // as visual noise. We only flip to the syncing label after a short delay.
  // While the delay is in flight we also pretend the kind is whatever it
  // was last — so e.g. "Offline · 1 pending" doesn't briefly drop the
  // "Offline" prefix during each tick's sync attempt.
  const [showSyncing, setShowSyncing] = useState(false);
  const lastResolvedKind = useRef<typeof status.kind>(status.kind);
  useEffect(() => {
    if (status.kind !== 'syncing') {
      lastResolvedKind.current = status.kind;
      setShowSyncing(false);
      return;
    }
    const t = window.setTimeout(() => setShowSyncing(true), 300);
    return () => window.clearTimeout(t);
  }, [status.kind]);

  // Effective kind for label/icon decisions: while a quick sync is in
  // flight, fall back to the previous resolved kind so the pill text
  // stays stable.
  const effectiveKind: typeof status.kind =
    status.kind === 'syncing' && !showSyncing
      ? lastResolvedKind.current
      : status.kind;

  // Tone resolution. Order matters — failed ops are the most attention-
  // worthy state and beat "offline" / "pending" for top-billing in the pill.
  let label: string;
  let tone: 'ok' | 'pending' | 'syncing' | 'error' | 'offline';
  let Icon = Check;
  let title: string;

  // Non-error states are icon-only (plus the count for pending /
  // offline-with-pending). The tooltip carries the human-readable
  // text. Failed edits keep the explicit "N failed" label since that
  // state demands attention, not a glance.
  if (failedCount > 0) {
    label = `${failedCount} failed`;
    tone = 'error';
    Icon = AlertTriangle;
    title = 'Some edits were rejected by the server — click for details';
  } else if (effectiveKind === 'syncing') {
    label = '';
    tone = 'syncing';
    Icon = Loader2;
    title = 'Sending edits to the server';
  } else if (effectiveKind === 'offline') {
    label = pending > 0 ? String(pending) : '';
    tone = 'offline';
    Icon = CloudOff;
    title = status.kind === 'offline'
      ? `Offline (${status.message})${pending > 0 ? ` · ${pending} pending` : ''} — will retry automatically`
      : `Offline · retrying${pending > 0 ? ` · ${pending} pending` : ''}…`;
  } else if (pending > 0) {
    label = String(pending);
    tone = 'pending';
    Icon = Loader2;
    title = `${pending} edit${pending === 1 ? '' : 's'} queued`;
  } else {
    label = '';
    tone = 'ok';
    Icon = Check;
    title = lastSyncedAt
      ? `All edits saved · ${fmtRelative(Date.now() - lastSyncedAt)} ago`
      : 'All edits saved';
  }

  // Click behavior: with failures, open the popover; without, force a
  // sync tick. The popover button ("Retry all") is what re-queues failed
  // ops once the user confirms.
  const onClick = () => {
    if (failedCount > 0) {
      setOpen((v) => !v);
    } else {
      void syncOutbox();
    }
  };

  return (
    <div className="sync-pill-wrap" ref={wrapRef}>
      <button
        className="sync-pill"
        data-tone={tone}
        onClick={onClick}
        title={title}
      >
        <Icon
          size={11}
          strokeWidth={2}
          className={tone === 'syncing' ? 'sync-pill-spin' : undefined}
        />
        {label && <span>{label}</span>}
      </button>
      {open && failedCount > 0 && (
        <div className="sync-popover">
          <div className="sync-popover-head">
            <span>Failed edits ({failedCount})</span>
            <span className="grow" />
            <button
              className="sync-popover-action"
              onClick={() => { retryAllFailed(); setOpen(false); }}
              title="Move every failed op back into the queue"
            >
              <RefreshCw size={11} strokeWidth={1.75} /> Retry all
            </button>
            <button
              className="sync-popover-action sync-popover-danger"
              onClick={() => { discardAllFailed(); setOpen(false); }}
              title="Drop every failed op from the outbox"
            >
              <X size={12} strokeWidth={2} /> Discard all
            </button>
          </div>
          <div className="sync-popover-list">
            {failed.map((op) => (
              <div key={op.op_id} className="sync-popover-row">
                <span className="sync-popover-kind">{op.payload.kind}</span>
                <span className="sync-popover-err" title={describeOpTarget(op)}>
                  {/* The store keeps op.payload but not the rejection message;
                      we reuse `status.message` for now. Per-op error text is
                      a small follow-up. */}
                  {op.status === 'error' ? 'rejected' : op.status}
                </span>
                <button
                  className="sync-popover-mini"
                  onClick={() => retryOp(op.op_id)}
                  title="Re-queue"
                >
                  <RefreshCw size={11} strokeWidth={1.75} />
                </button>
                <button
                  className="sync-popover-mini sync-popover-danger"
                  onClick={() => discardOp(op.op_id)}
                  title="Discard"
                >
                  <X size={12} strokeWidth={2} />
                </button>
              </div>
            ))}
          </div>
          {status.kind === 'error' && (
            <div className="sync-popover-foot">
              Last error: <span>{status.message}</span>
            </div>
          )}
        </div>
      )}
    </div>
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

// Best-effort description of what the op was acting on, used as the
// tooltip on the row so the user can recognise which edit it was.
function describeOpTarget(op: { payload: { kind: string } & Record<string, unknown> }): string {
  const p = op.payload as Record<string, unknown>;
  const target = (p.task_id ?? p.block_id ?? p.subtask_id ?? p.project_id) as string | undefined;
  return target ? `${op.payload.kind} · ${String(target).slice(0, 8)}` : op.payload.kind;
}
