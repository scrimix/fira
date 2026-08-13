import { useCallback, useEffect, useRef } from 'react';
import { useFira } from './store';
import { buildTaskLink, parseTaskLink } from './deeplink';
import { openNudgeSocket, openUserSocket } from './ws';
import { useAppActive } from './hooks';
import { syncLog, syncLogDev } from './synclog';

import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { CalendarView } from './components/CalendarView';
import { ListView } from './components/ListView';
import { TaskModal } from './components/TaskModal';
import { TaskModalDraft } from './components/TaskModalDraft';
import { ProjectModal } from './components/ProjectModal';
import { WorkspaceModal } from './components/WorkspaceModal';
import { LinkAccountModal } from './components/LinkAccountModal';
import { AccountSettingsModal } from './components/AccountSettingsModal';
import { WorkspaceInviteModal } from './components/WorkspaceInviteModal';
import { Login } from './components/Login';
import { Toasts } from './components/Toasts';

// Counts automatic reloads in this tab, so a mismatch that survives one can't
// turn into a refresh loop. Session-scoped, so a fresh tab starts over.
const BUILD_RELOAD_KEY = 'fira:autoReloadCount';

// Would reloading right now throw away anything the user cares about? Un-pushed
// edits in the outbox, or an open modal / draft they're in the middle of.
function safeToReload(s: ReturnType<typeof useFira.getState>): boolean {
  return s.outbox.length === 0
    && s.openTaskId === null
    && s.creatingDraft === null
    && s.projectModal === null
    && s.workspaceModal === null
    && !s.linkModalOpen
    && !s.accountModalOpen;
}

// One automatic reload per tab, and only when nothing is in flight. Returns
// false if it declined, so the caller can fall back to telling the user.
function tryAutoReload(): boolean {
  if (!safeToReload(useFira.getState())) return false;
  let used = 0;
  try {
    used = Number(sessionStorage.getItem(BUILD_RELOAD_KEY) ?? '0') || 0;
  } catch { /* private mode — decline and let the caller announce */ }
  if (used >= 1) return false;
  syncLog('new build, clean wake, nothing in flight — reloading into it');
  try { sessionStorage.setItem(BUILD_RELOAD_KEY, String(used + 1)); } catch { /* ignore */ }
  window.location.reload();
  return true;
}

export default function App() {
  const authChecked = useFira((s) => s.authChecked);
  const loaded = useFira((s) => s.loaded);
  const meId = useFira((s) => s.meId);
  const error = useFira((s) => s.error);
  const view = useFira((s) => s.view);
  const openTaskId = useFira((s) => s.openTaskId);
  const creatingDraft = useFira((s) => s.creatingDraft);
  const projectModal = useFira((s) => s.projectModal);
  const workspaceModal = useFira((s) => s.workspaceModal);
  const linkModalOpen = useFira((s) => s.linkModalOpen);
  const accountModalOpen = useFira((s) => s.accountModalOpen);
  const syncOutbox = useFira((s) => s.syncOutbox);
  const pollChanges = useFira((s) => s.pollChanges);
  const rehydrate = useFira((s) => s.rehydrate);
  const checkBuildVersion = useFira((s) => s.checkBuildVersion);
  const reloadWorkspaces = useFira((s) => s.reloadWorkspaces);
  const reloadLinks = useFira((s) => s.reloadLinks);
  const reloadWorkspaceInvites = useFira((s) => s.reloadWorkspaceInvites);
  const loadLinkedCalendar = useFira((s) => s.loadLinkedCalendar);
  const loadPersonalCalendar = useFira((s) => s.loadPersonalCalendar);
  const loadWorkCalendar = useFira((s) => s.loadWorkCalendar);
  const inTeamWorkspace = useFira((s) => {
    const ws = s.workspaces.find((w) => w.id === s.activeWorkspaceId);
    return ws ? !ws.is_personal : false;
  });
  const hasAcceptedLink = useFira((s) =>
    s.links.some((l) => l.status === 'accepted'),
  );
  // A pending received request forces the modal open. The link row is
  // server-persisted, so it survives refresh / shows on every tab — and
  // the only way to dismiss is Accept or Decline (both clear the row).
  const hasPendingReceived = useFira((s) =>
    s.links.some((l) => l.direction === 'received' && l.status === 'pending'),
  );
  // Workspace invite addressed to me. Sticky like account-link's
  // received pending — the only dismissals are Accept / Decline. If
  // multiple are pending, show the oldest first; the others wait their
  // turn (selecting min by created_at).
  const pendingWorkspaceInvite = useFira((s) => {
    const received = s.workspaceInvites.filter(
      (i) => i.direction === 'received' && i.status === 'pending',
    );
    if (received.length === 0) return null;
    return received.reduce((a, b) => (a.created_at <= b.created_at ? a : b));
  });
  const editingProject = useFira((s) => {
    const m = s.projectModal;
    return m?.kind === 'edit' ? s.projects.find((p) => p.id === m.id) ?? null : null;
  });
  const editingWorkspace = useFira((s) => {
    const m = s.workspaceModal;
    return m?.kind === 'edit' ? s.workspaces.find((w) => w.id === m.id) ?? null : null;
  });
  const hydrate = useFira((s) => s.hydrate);
  const activeWorkspaceId = useFira((s) => s.activeWorkspaceId);
  const playgroundMode = useFira((s) => s.playgroundMode);

  // Background sync stands down when the tab has been out of sight for a
  // couple of minutes, and catches up when it comes back. See the polling
  // and socket effects below for what each side of that flip controls.
  const appActive = useAppActive();

  // Told once per tab, whichever path notices the deploy first.
  const buildToastedRef = useRef(false);
  const announceNewBuild = useCallback(() => {
    if (buildToastedRef.current) return;
    buildToastedRef.current = true;
    useFira.getState().showToast(
      'A new version of Fira is available — refresh when convenient',
      'info',
    );
  }, []);

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  // ─── Task deep links ──────────────────────────────────────────────────
  // The open task is mirrored in a hash URL (`#/w/<ws>/t/<task>`) so a task
  // is shareable, refresh-safe, and back-button dismissable. Three effects
  // keep store ⇄ URL in sync; pushState/replaceState don't fire hashchange
  // or popstate, so writing the URL never re-triggers the readers below.

  // Initial load: once bootstrap is ready and auth is confirmed, honor the
  // task hash in the address bar. Store the original page-load hash in a ref
  // to avoid any intermediate mutation or React refresh race from changing it.
  const initialTaskHashRef = useRef(parseTaskLink(window.location.hash));
  const deepLinkedRef = useRef(false);
  useEffect(() => {
    if (!authChecked || !loaded || deepLinkedRef.current) return;
    deepLinkedRef.current = true;
    const parsed = initialTaskHashRef.current;
    if (parsed) void useFira.getState().openTaskByDeepLink(parsed.workspaceId, parsed.taskId);
  }, [authChecked, loaded]);

  // Back/forward (and manual hash edits, pasted links into the running app):
  // reconcile the open task to whatever the URL now says.
  useEffect(() => {
    const onNav = () => {
      const parsed = parseTaskLink(window.location.hash);
      const cur = useFira.getState().openTaskId;
      if (parsed && parsed.taskId !== cur) {
        void useFira.getState().openTaskByDeepLink(parsed.workspaceId, parsed.taskId);
      } else if (!parsed && cur) {
        useFira.getState().openTask(null);
      }
    };
    window.addEventListener('popstate', onNav);
    window.addEventListener('hashchange', onNav);
    return () => {
      window.removeEventListener('popstate', onNav);
      window.removeEventListener('hashchange', onNav);
    };
  }, []);

  // Store → URL. Opening a task pushes a history entry (so Back closes the
  // modal); closing replaces it away (no dangling entry). Skips the first
  // run so a fresh deep-link load doesn't clobber its own hash before the
  // initial-load effect above gets to read it.
  // Depends on openTaskId only: the workspace is read at commit time via
  // getState(), so a deep-link-driven workspace switch (which leaves
  // openTaskId null until the task actually opens) can't run this mid-flight
  // and clobber the hash.
  const urlSyncMountedRef = useRef(false);
  useEffect(() => {
    if (!urlSyncMountedRef.current) { urlSyncMountedRef.current = true; return; }
    const parsed = parseTaskLink(window.location.hash);
    if (openTaskId) {
      if (!parsed || parsed.taskId !== openTaskId) {
        const ws = useFira.getState().activeWorkspaceId;
        window.history.pushState(null, '', buildTaskLink(ws, openTaskId));
      }
    } else if (parsed) {
      window.history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  }, [openTaskId]);

  // Outbox push: fast cadence so locally-queued mutations hit the server
  // within 2s of the user making the change. Without this, the slow read-side
  // poll below would also gate writes — a click would only POST minutes later.
  useEffect(() => {
    const flush = () => { void syncOutbox(); };
    const id = window.setInterval(flush, 2000);
    window.addEventListener('focus', flush);
    window.addEventListener('online', flush);
    return () => {
      window.clearInterval(id);
      window.removeEventListener('focus', flush);
      window.removeEventListener('online', flush);
    };
  }, [syncOutbox]);

  // Change-feed pull: WS nudges are the real-time path. This 60s timer is a
  // fallback for missed nudges (transient disconnect, dropped frames) so
  // remote changes still surface even if the socket is unhappy.
  useEffect(() => {
    if (!appActive) return;
    const id = window.setInterval(() => {
      syncLogDev('  · change-feed poll tick');
      void pollChanges();
    }, 60_000);
    return () => window.clearInterval(id);
  }, [pollChanges, appActive]);

  // Full bootstrap refresh every 30 min. The change-feed catches incremental
  // ops, but it can drift if a nudge is missed AND the cursor advances past
  // it (e.g. a transient WS reconnect that swallows a frame). Rehydrating
  // the bootstrap snapshot at a coarse cadence is the belt-and-braces fix —
  // outbox + UI state are preserved, only the server-derived collections
  // get overwritten.
  //
  // This is the single most expensive thing an idle tab does: a full
  // workspace snapshot, and a Google Calendar sync behind it (the bootstrap
  // handler kicks one off per request). The 60s change-feed poll above
  // already covers the drift case, so this only has to be a coarse backstop —
  // hence 30 min rather than 5.
  useEffect(() => {
    if (!appActive) return;
    const id = window.setInterval(() => {
      syncLogDev('  · bootstrap refresh tick');
      void rehydrate();
    }, 30 * 60_000);
    return () => window.clearInterval(id);
  }, [rehydrate, appActive]);

  // Coming back from idle. The timers above resume on their own, but they'd
  // leave the user staring at stale data until the next tick, and a cursor
  // that sat still for eight hours may be further behind than one /changes
  // page can drain. A rehydrate settles both — it resets the cursor to the
  // bootstrap watermark — and refreshes the calendar on the way in, which is
  // exactly what you want when returning to the app. Skips the first run:
  // the initial hydrate() has just done this.
  //
  // The user-channel reloads ride along: those nudges (membership, roles,
  // invites, account links) are fire-and-forget, so anything that happened
  // while the socket was down is simply gone. Refetching is the only way to
  // learn about it.
  // Waits for `loaded` rather than firing on mount: a tab backgrounded while
  // the initial hydrate is still in flight would otherwise fire this against
  // a half-built store. The first pass through is consumed as the skip —
  // hydrate() has just fetched everything this effect would refetch.
  const wakeMountedRef = useRef(false);
  useEffect(() => {
    if (!loaded) return;
    if (!wakeMountedRef.current) { wakeMountedRef.current = true; return; }
    if (!appActive || playgroundMode) return;
    syncLog('  ⟳ wake catch-up: rehydrate + workspaces/links/invites');
    void rehydrate();
    void reloadWorkspaces();
    void reloadLinks();
    void reloadWorkspaceInvites();
    // Sequenced rather than fired-and-forgotten: the reload decision has to be
    // made against a fresh answer, and this is the one moment where reloading
    // costs the user nothing — they've just arrived back at the tab and, by
    // definition of having been idle, aren't part-way through anything.
    void checkBuildVersion().then(() => {
      if (!useFira.getState().newBuildAvailable) return;
      if (!tryAutoReload()) announceNewBuild();
    });
  }, [loaded, appActive, playgroundMode, rehydrate, reloadWorkspaces, reloadLinks,
      reloadWorkspaceInvites, checkBuildVersion, announceNewBuild]);

  // Version check. Establishes the baseline once the app is up, then re-checks
  // on a slow timer for tabs that stay open all day. The wake path below is the
  // case that actually matters — a tab asleep since yesterday is the one most
  // likely to be running superseded code — so the baseline call is guarded to
  // avoid both paths fetching /version on the same wake.
  //
  // A deploy noticed *mid-session* only ever announces itself. Reloading
  // someone's page while they're using it is never worth it, however clean the
  // state looks: "safe" is about lost data, not lost attention.
  useEffect(() => {
    if (!loaded || playgroundMode || !appActive) return;
    if (useFira.getState().bootBuild === null) void checkBuildVersion();
    const id = window.setInterval(() => {
      void checkBuildVersion().then(() => {
        if (useFira.getState().newBuildAvailable) announceNewBuild();
      });
    }, 30 * 60_000);
    return () => window.clearInterval(id);
  }, [loaded, appActive, playgroundMode, checkBuildVersion, announceNewBuild]);

  // WS nudge channel: open one socket per active workspace. Each nudge
  // triggers the same syncOutbox+pollChanges sequence as the interval, so
  // ordering and idempotency stay identical to the polled path. Playground
  // mode has no server, so no socket — the open would just spin in
  // reconnect backoff.
  //
  // Nudges are coalesced. The server emits one nudge per committed op, so a
  // workspace under write load can fire hundreds a second — but a nudge
  // only means "the cursor moved", and a single /changes pull (up to 500
  // ops) drains the whole backlog. So: a short debounce collapses a burst
  // into one sync, and an in-flight guard + `pending` flag guarantees at
  // most one extra catch-up pass. Without this the tab fires one fetch per
  // nudge and falls over.
  //
  // Dropped entirely while the tab is idle: the socket is what keeps the
  // connection (and, on Fly, the machine serving it) alive all night. The
  // 60s poll fallback is documented as covering any gap while disconnected,
  // and the wake effect above does a full rehydrate on the way back.
  useEffect(() => {
    if (!activeWorkspaceId || playgroundMode || !appActive) return;
    let debounceTimer: number | null = null;
    let syncing = false;
    let pending = false;
    let cancelled = false;

    const runSync = async () => {
      if (syncing) { pending = true; return; }
      syncing = true;
      do {
        pending = false;
        await syncOutbox();
        if (cancelled) break;
        await pollChanges();
      } while (pending && !cancelled);
      syncing = false;
    };

    const onNudge = () => {
      if (debounceTimer !== null) return; // a sync is already scheduled
      debounceTimer = window.setTimeout(() => {
        debounceTimer = null;
        // Logged after the debounce, not per nudge — a burst is one line.
        syncLogDev('  · nudge → sync');
        void runSync();
      }, 200);
    };

    const handle = openNudgeSocket(activeWorkspaceId, onNudge);
    return () => {
      cancelled = true;
      if (debounceTimer !== null) window.clearTimeout(debounceTimer);
      handle.close();
    };
  }, [activeWorkspaceId, syncOutbox, pollChanges, playgroundMode, appActive]);

  // User-channel socket: opaque "your workspace surface changed" nudges.
  // Independent of which workspace is active, because the events that
  // *grant* membership can't ride the workspace-scoped feed (chicken/egg).
  // Account links share the same channel — a link request / accept /
  // cancel needs to reach a partner who may be looking at a different
  // workspace, so the per-user transport is the only one that fits.
  // Idle-gated for the same reason as the workspace socket above.
  useEffect(() => {
    if (!meId || playgroundMode || !appActive) return;
    const handle = openUserSocket(() => {
      void reloadWorkspaces();
      void reloadLinks();
      void reloadWorkspaceInvites();
    });
    return () => handle.close();
  }, [meId, playgroundMode, appActive, reloadWorkspaces, reloadLinks, reloadWorkspaceInvites]);

  // Bootstrap may include an already-accepted link — pull the partner's
  // calendar overlay once so the toggle has data to show as soon as the
  // user flips it on. Re-runs on workspace switch (the active workspace
  // shapes which one of the partner's tabs the user is checking against).
  useEffect(() => {
    if (!hasAcceptedLink || playgroundMode) return;
    void loadLinkedCalendar();
  }, [hasAcceptedLink, activeWorkspaceId, playgroundMode, loadLinkedCalendar]);

  // Personal-workspace overlay: only meaningful in a team workspace.
  // Reload on workspace switch so the projection always matches the
  // currently-active team context.
  useEffect(() => {
    if (!inTeamWorkspace || playgroundMode) return;
    void loadPersonalCalendar();
  }, [inTeamWorkspace, activeWorkspaceId, playgroundMode, loadPersonalCalendar]);

  // Work-workspace overlay: the inverse — only meaningful when the active
  // workspace is the personal one. Aggregates blocks across every team
  // workspace the user belongs to.
  useEffect(() => {
    if (inTeamWorkspace || playgroundMode) return;
    void loadWorkCalendar();
  }, [inTeamWorkspace, activeWorkspaceId, playgroundMode, loadWorkCalendar]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.matches('input, textarea, [contenteditable="true"]')) return;
      if (e.key === 'Escape') {
        useFira.getState().openTask(null);
        useFira.getState().closeCreate();
        useFira.getState().closeProjectModal();
        useFira.getState().closeWorkspaceModal();
        // Received pending link is sticky — only Accept/Decline can clear it.
        const sticky = useFira
          .getState()
          .links.some((l) => l.direction === 'received' && l.status === 'pending');
        if (!sticky) useFira.getState().closeLinkModal();
      }
      if (e.key === 'g') useFira.getState().setView('calendar');
      if (e.key === 'i') useFira.getState().setView('list');
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  if (error) {
    return (
      <div style={{ padding: 24, fontFamily: 'var(--font-mono)' }}>
        <h2 style={{ color: 'var(--danger)' }}>Failed to load</h2>
        <pre>{error}</pre>
        <p style={{ color: 'var(--ink-3)' }}>
          Is the API running? Try <code>docker compose up api</code>.
        </p>
      </div>
    );
  }

  if (!authChecked) {
    return (
      <div style={{ padding: 24, color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: 'calc(12px * var(--fs-scale))' }}>
        loading…
      </div>
    );
  }

  if (!meId) {
    return <Login />;
  }

  if (!loaded) {
    return (
      <div style={{ padding: 24, color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: 'calc(12px * var(--fs-scale))' }}>
        loading…
      </div>
    );
  }

  return (
    <div className="app">
      <Sidebar />
      <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <TopBar />
        {view === 'calendar' ? <CalendarView /> : <ListView />}
      </div>
      {openTaskId && <TaskModal taskId={openTaskId} />}
      {creatingDraft && !openTaskId && <TaskModalDraft draft={creatingDraft} />}
      {projectModal?.kind === 'new' && <ProjectModal />}
      {projectModal?.kind === 'edit' && editingProject && (
        <ProjectModal key={editingProject.id} project={editingProject} />
      )}
      {workspaceModal?.kind === 'new' && <WorkspaceModal />}
      {workspaceModal?.kind === 'edit' && editingWorkspace && (
        <WorkspaceModal key={editingWorkspace.id} workspace={editingWorkspace} />
      )}
      {(linkModalOpen || hasPendingReceived) && <LinkAccountModal />}
      {accountModalOpen && <AccountSettingsModal />}
      {pendingWorkspaceInvite && (
        <WorkspaceInviteModal
          key={pendingWorkspaceInvite.id}
          invite={pendingWorkspaceInvite}
        />
      )}
      <Toasts />
    </div>
  );
}

