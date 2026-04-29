import { useFira } from '../store';

export function TopBar() {
  const view = useFira((s) => s.view);
  const me = useFira((s) => s.users.find((u) => u.id === s.meId) ?? null);
  const project = useFira((s) =>
    s.projects.find((p) => p.id === s.inboxFilter.project_id) ?? null
  );
  const outboxLen = useFira((s) => s.outbox.length);

  const title = view === 'calendar'
    ? 'Week of Apr 27, 2026'
    : project?.title ?? 'Inbox';

  return (
    <div className="topbar">
      <span className="crumb">Fira</span>
      <span className="crumb-sep">/</span>
      <span className="crumb">{me?.name ?? ''}</span>
      <span className="crumb-sep">/</span>
      <span className="title">{title}</span>
      <div className="grow" />
      {outboxLen > 0 && (
        <span className="outbox-pill" title="Pending mutations (no sync worker yet)">
          outbox: {outboxLen}
        </span>
      )}
      <span className="kbd">⌘K</span>
    </div>
  );
}
