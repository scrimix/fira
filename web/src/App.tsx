import { useEffect } from 'react';
import { useFira } from './store';
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
  const syncOutbox = useFira((s) => s.syncOutbox);
  const pollChanges = useFira((s) => s.pollChanges);
  const reloadWorkspaces = useFira((s) => s.reloadWorkspaces);
  const reloadLinks = useFira((s) => s.reloadLinks);
  const loadLinkedCalendar = useFira((s) => s.loadLinkedCalendar);
  const hasAcceptedLink = useFira((s) =>
    s.links.some((l) => l.status === 'accepted'),
  );
  // A pending received request forces the modal open. The link row is
  // server-persisted, so it survives refresh / shows on every tab — and
  // the only way to dismiss is Accept or Decline (both clear the row).
  const hasPendingReceived = useFira((s) =>
    s.links.some((l) => l.direction === 'received' && l.status === 'pending'),
  );
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

  // WS nudge channel: open one socket per active workspace. Each nudge
  // triggers the same syncOutbox+pollChanges sequence as the interval, so
  // ordering and idempotency stay identical to the polled path. Playground
  // mode has no server, so no socket — the open would just spin in
  // reconnect backoff.
  useEffect(() => {
    if (!activeWorkspaceId || playgroundMode) return;
    const handle = openNudgeSocket(activeWorkspaceId, () => {
      void syncOutbox().then(() => pollChanges());
    });
    return () => handle.close();
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
    });
    return () => handle.close();
  }, [meId, playgroundMode, reloadWorkspaces, reloadLinks]);

  // Bootstrap may include an already-accepted link — pull the partner's
  // calendar overlay once so the toggle has data to show as soon as the
  // user flips it on. Re-runs on workspace switch (the active workspace
  // shapes which one of the partner's tabs the user is checking against).
  useEffect(() => {
    if (!hasAcceptedLink || playgroundMode) return;
    void loadLinkedCalendar();
  }, [hasAcceptedLink, activeWorkspaceId, playgroundMode, loadLinkedCalendar]);

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
      <Toasts />
    </div>
  );
}

