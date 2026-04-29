import { useFira } from '../store';
import { weekStartFor, fmtWeekRange } from '../time';

export function TopBar() {
  const view = useFira((s) => s.view);
  const meId = useFira((s) => s.meId);
  const activePersonId = useFira((s) => s.activePersonId);
  const activePerson = useFira((s) =>
    s.users.find((u) => u.id === s.activePersonId) ?? null
  );
  const project = useFira((s) =>
    s.projects.find((p) => p.id === s.inboxFilter.project_id) ?? null
  );
  const weekOffset = useFira((s) => s.weekOffset);

  const personLabel = activePerson
    ? `${activePerson.name}${activePersonId === meId ? ' (you)' : ''}`
    : '';
  const title = view === 'calendar'
    ? `Week of ${fmtWeekRange(weekStartFor(weekOffset))}`
    : project?.title ?? 'Inbox';

  return (
    <div className="topbar">
      <span className="crumb">Fira</span>
      <span className="crumb-sep">/</span>
      <span className="crumb">{personLabel}</span>
      <span className="crumb-sep">/</span>
      <span className="title">{title}</span>
      <div className="grow" />
    </div>
  );
}
