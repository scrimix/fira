import { useFira } from '../store';
import { fmtMin, fmtClockShort, taskCompletedMin, taskPlannedMin, taskTimeLeft, blockToGrid, DAY_LABELS } from '../time';

interface Props { taskId: string }

export function TaskModal({ taskId }: Props) {
  const task = useFira((s) => s.tasks.find((t) => t.id === taskId) ?? null);
  const project = useFira((s) =>
    task ? s.projects.find((p) => p.id === task.project_id) ?? null : null
  );
  const assignee = useFira((s) =>
    task ? s.users.find((u) => u.id === task.assignee_id) ?? null : null
  );
  const blocks = useFira((s) => s.blocks);
  const close = useFira((s) => s.openTask);
  const tickSubtask = useFira((s) => s.tickSubtask);

  if (!task || !project) return null;

  const completed = taskCompletedMin(task, blocks);
  const planned = taskPlannedMin(task, blocks);
  const left = taskTimeLeft(task, blocks);
  const total = task.estimate_min ?? (completed + planned);
  const compPct = total ? (completed / total) * 100 : 0;
  const planPct = total ? (planned / total) * 100 : 0;

  const taskBlocks = blocks
    .filter((b) => b.task_id === task.id)
    .map((b) => ({ b, ...blockToGrid(b.start_at, b.end_at) }))
    .sort((a, c) => a.day - c.day || a.start_min - c.start_min);

  const sourceLabel = task.source === 'jira' ? `Jira · ${task.external_id ?? 'unsynced'}`
    : task.source === 'notion' ? `Notion · ${task.external_id ?? 'unsynced'}`
    : 'Local task';

  return (
    <div className="modal-backdrop" onClick={() => close(null)}>
      <div className="modal" onClick={(e) => e.stopPropagation()}
           style={{ ['--proj-color' as string]: project.color }}>
        <div className="modal-head">
          <span style={{ width: 10, height: 10, background: project.color, display: 'inline-block' }} />
          <span className="ext">{project.title}</span>
          <span style={{ color: 'var(--ink-4)' }}>/</span>
          <span className="ext">{sourceLabel}</span>
          <span className="grow" />
          <span className="chip" data-tone={task.status === 'done' ? 'done' : task.status === 'in_progress' ? 'now' : ''}>
            {task.status.replace('_', ' ')}
          </span>
          <button className="icon-btn" onClick={() => close(null)} title="Close (Esc)">×</button>
        </div>
        <div className="modal-body">
          <div className="modal-main">
            <h2 className="task-title-big">{task.title}</h2>

            {task.estimate_min != null && (
              <>
                <div className="est-bar">
                  <div className="seg-spent" style={{ width: `${Math.min(100, compPct)}%` }} />
                  <div className="seg-planned" style={{ width: `${Math.min(100 - compPct, planPct)}%` }} />
                </div>
                <div className="est-meta">
                  <span><strong>{fmtMin(completed)}</strong> done</span>
                  <span><strong>{fmtMin(planned)}</strong> planned</span>
                  <span><strong>{fmtMin(left ?? 0)}</strong> left</span>
                  <span style={{ marginLeft: 'auto' }}>of {fmtMin(task.estimate_min)} estimate</span>
                </div>
              </>
            )}

            <h5 style={modalH5}>Description</h5>
            <div className="desc-md">{task.description_md || 'No description.'}</div>

            {task.subtasks.length > 0 && (
              <>
                <h5 style={modalH5}>
                  Subtasks · {task.subtasks.filter((s) => s.done).length}/{task.subtasks.length}
                </h5>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {task.subtasks.map((s) => (
                    <div key={s.id} className="subtask" data-done={s.done}>
                      <span className="sc" onClick={() => tickSubtask(task.id, s.id)}>{s.done ? '✓' : ''}</span>
                      <span className="sname">{s.title}</span>
                    </div>
                  ))}
                </div>
              </>
            )}

            <div style={{ marginTop: 16 }}>
              <h5 style={modalH5}>Time blocks · {taskBlocks.length}</h5>
              {taskBlocks.length === 0 ? (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink-4)', padding: '8px 0' }}>
                  No blocks yet.
                </div>
              ) : taskBlocks.map(({ b, day, start_min, dur_min }) => (
                <div key={b.id} style={blockRow}>
                  <span style={{ color: 'var(--ink-2)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    {DAY_LABELS[day]} {27 + day > 30 ? 27 + day - 30 : 27 + day}
                  </span>
                  <span style={{ color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    {fmtClockShort(start_min)} – {fmtClockShort(start_min + dur_min)}
                  </span>
                  <span style={{ color: 'var(--ink-2)', fontFamily: 'var(--font-mono)', fontSize: 11, textAlign: 'right' }}>
                    {fmtMin(dur_min)}
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.08em',
                    textTransform: 'uppercase', textAlign: 'right',
                    color: b.state === 'completed' ? 'var(--done)' : b.state === 'planned' ? 'var(--accent)' : 'var(--ink-4)',
                  }}>{b.state}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="modal-side">
            <Field label="Project" value={
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 10, height: 10, background: project.color, display: 'inline-block' }} />
                {project.title}
              </span>
            } />
            <Field label="Assignee" value={
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {assignee && <div className="avatar">{assignee.initials}</div>}
                {assignee?.name ?? 'Unassigned'}
              </span>
            } />
            <Field label="Status" mono value={task.status.replace('_', ' ')} />
            <Field label="Priority" mono value={task.priority ?? '—'} />
            <Field label="Estimate" mono value={task.estimate_min != null ? fmtMin(task.estimate_min) : '—'} />
            <Field label="Time left" mono value={left != null ? fmtMin(left) : '—'} />
            <Field label="Tags" value={
              task.tags.length === 0 ? <span style={{ color: 'var(--ink-4)' }}>—</span> :
              <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {task.tags.map((tg) => <span key={tg} className="chip">{tg}</span>)}
              </span>
            } />
            <Field label="Source" mono value={sourceLabel} />
            <Field label="Section" mono value={task.section} />
          </div>
        </div>
      </div>
    </div>
  );
}

const modalH5: React.CSSProperties = {
  margin: '18px 0 4px',
  fontFamily: 'var(--font-mono)',
  fontSize: 10,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
  color: 'var(--ink-3)',
  fontWeight: 500,
};
const blockRow: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '60px 1fr 70px 80px',
  gap: 10,
  padding: '4px 0',
  borderBottom: '1px solid var(--rule)',
  alignItems: 'center',
};

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="field">
      <h5>{label}</h5>
      <div style={{
        fontSize: 'var(--fs-md)',
        color: 'var(--ink)',
        fontFamily: mono ? 'var(--font-mono)' : 'inherit',
        fontVariantNumeric: mono ? 'tabular-nums' : 'normal',
      }}>{value}</div>
    </div>
  );
}
