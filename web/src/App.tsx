import { useEffect } from 'react';
import { useFira } from './store';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { CalendarView } from './components/CalendarView';
import { InboxView } from './components/InboxView';
import { TaskModal } from './components/TaskModal';
import { TaskModalDraft } from './components/TaskModalDraft';
import { ProjectModal } from './components/ProjectModal';
import { WorkspaceModal } from './components/WorkspaceModal';
import { Login } from './components/Login';

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
  const syncOutbox = useFira((s) => s.syncOutbox);
  const pollChanges = useFira((s) => s.pollChanges);
  const editingProject = useFira((s) => {
    const m = s.projectModal;
    return m?.kind === 'edit' ? s.projects.find((p) => p.id === m.id) ?? null : null;
  });
  const editingWorkspace = useFira((s) => {
    const m = s.workspaceModal;
    return m?.kind === 'edit' ? s.workspaces.find((w) => w.id === m.id) ?? null : null;
  });
  const hydrate = useFira((s) => s.hydrate);

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  // Sync workers: every 2s push outbox edits, then pull change-feed rows
  // for anything written by other clients. Push-then-pull keeps the local
  // appliedOpIds-set in front of the echo so we don't double-apply our own
  // ops. Both bail out cleanly if there's nothing to do.
  useEffect(() => {
    const tick = () => {
      void syncOutbox().then(() => pollChanges());
    };
    const id = window.setInterval(tick, 2000);
    window.addEventListener('focus', tick);
    window.addEventListener('online', tick);
    return () => {
      window.clearInterval(id);
      window.removeEventListener('focus', tick);
      window.removeEventListener('online', tick);
    };
  }, [syncOutbox, pollChanges]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.matches('input, textarea, [contenteditable="true"]')) return;
      if (e.key === 'Escape') {
        useFira.getState().openTask(null);
        useFira.getState().closeCreate();
        useFira.getState().closeProjectModal();
        useFira.getState().closeWorkspaceModal();
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
      <div style={{ padding: 24, color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        loading…
      </div>
    );
  }

  if (!meId) {
    return <Login />;
  }

  if (!loaded) {
    return (
      <div style={{ padding: 24, color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
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
    </div>
  );
}
