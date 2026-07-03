import { useEffect, useRef } from 'react';
import { useFira } from './store';
import { buildTaskLink, parseTaskLink } from './deeplink';
import { openNudgeSocket, openUserSocket } from './ws';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { CalendarView } from './components/CalendarView';
import { InboxView } from './components/InboxView';
import { TaskModal } from './components/TaskModal';
import { TaskModalDraft } from './components/TaskModalDraft';
import { ProjectModal } from './components/ProjectModal';
import { WorkspaceModal } from './components/WorkspaceModal';
import { LinkAccountModal } from './components/LinkAccountModal';
import { AccountSettingsModal } from './components/AccountSettingsModal';
import { WorkspaceInviteModal } from './components/WorkspaceInviteModal';
import { Login } from './components/Login';
import { Toasts } from './components/Toasts';

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
    const id = window.setInterval(() => { void pollChanges(); }, 60_000);
    return () => window.clearInterval(id);
  }, [pollChanges]);

  // Full bootstrap refresh every 5 min. The change-feed catches incremental
  // ops, but it can drift if a nudge is missed AND the cursor advances past
  // it (e.g. a transient WS reconnect that swallows a frame). Rehydrating
  // the bootstrap snapshot at a coarse cadence is the belt-and-braces fix —
  // outbox + UI state are preserved, only the server-derived collections
  // get overwritten.
  useEffect(() => {
    const id = window.setInterval(() => { void rehydrate(); }, 5 * 60_000);
    return () => window.clearInterval(id);
  }, [rehydrate]);

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
  useEffect(() => {
    if (!activeWorkspaceId || playgroundMode) return;
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
        void runSync();
      }, 200);
    };

    const handle = openNudgeSocket(activeWorkspaceId, onNudge);
    return () => {
      cancelled = true;
      if (debounceTimer !== null) window.clearTimeout(debounceTimer);
      handle.close();
    };
  }, [activeWorkspaceId, syncOutbox, pollChanges, playgroundMode]);

  // User-channel socket: opaque "your workspace surface changed" nudges.
  // Independent of which workspace is active, because the events that
  // *grant* membership can't ride the workspace-scoped feed (chicken/egg).
  // Account links share the same channel — a link request / accept /
  // cancel needs to reach a partner who may be looking at a different
  // workspace, so the per-user transport is the only one that fits.
  useEffect(() => {
    if (!meId || playgroundMode) return;
    const handle = openUserSocket(() => {
      void reloadWorkspaces();
      void reloadLinks();
      void reloadWorkspaceInvites();
    });
    return () => handle.close();
  }, [meId, playgroundMode, reloadWorkspaces, reloadLinks, reloadWorkspaceInvites]);

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
      if (e.key === 'i') useFira.getState().setView('inbox');
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
        {view === 'calendar' ? <CalendarView /> : <InboxView />}
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

