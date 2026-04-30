import { useEffect } from 'react';
import { useFira } from './store';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { CalendarView } from './components/CalendarView';
import { InboxView } from './components/InboxView';
import { TaskModal } from './components/TaskModal';
import { TaskModalDraft } from './components/TaskModalDraft';
import { ProjectModal } from './components/ProjectModal';
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
  const editingProject = useFira((s) => {
    const m = s.projectModal;
    return m?.kind === 'edit' ? s.projects.find((p) => p.id === m.id) ?? null : null;
  });
  const hydrate = useFira((s) => s.hydrate);

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.matches('input, textarea, [contenteditable="true"]')) return;
      if (e.key === 'Escape') {
        useFira.getState().openTask(null);
        useFira.getState().closeCreate();
        useFira.getState().closeProjectModal();
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
    </div>
  );
}
