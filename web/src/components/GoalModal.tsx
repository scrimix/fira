// Goal editor. One modal for create and edit — a goal is small enough
// that a full-form submit is the natural shape, which is also why
// `goal.update` replaces the whole definition rather than patching it.

import { useMemo, useState } from 'react';
import { Trash2, X } from 'lucide-react';
import { useFira } from '../store';
import { fmtMin, parseEstimate } from '../time';
import { Select } from './Select';
import type { SelectOption } from './Select';
import type { GoalCadence, GoalDirection, UUID } from '../types';

const NONE = '__none__';

export function GoalModal({ goalId }: { goalId: UUID | null }) {
  const close = useFira((s) => s.closeGoalModal);
  const createGoal = useFira((s) => s.createGoal);
  const updateGoal = useFira((s) => s.updateGoal);
  const deleteGoal = useFira((s) => s.deleteGoal);
  const projects = useFira((s) => s.projects);
  const tags = useFira((s) => s.tags);
  const tasks = useFira((s) => s.tasks);
  const existing = useFira((s) => s.goals.find((g) => g.id === goalId) ?? null);

  const [name, setName] = useState(existing?.name ?? '');
  const [cadence, setCadence] = useState<GoalCadence>(existing?.cadence ?? 'daily');
  const [direction, setDirection] = useState<GoalDirection>(existing?.direction ?? 'at_least');
  const [target, setTarget] = useState(
    existing?.target_min != null ? fmtMin(existing.target_min) : '',
  );
  const [projectId, setProjectId] = useState<string>(existing?.project_id ?? NONE);
  const [tagId, setTagId] = useState<string>(existing?.tag_id ?? NONE);
  const [taskId, setTaskId] = useState<string>(existing?.task_id ?? NONE);

  // Tags and tasks are project-scoped, so narrowing the project narrows
  // both pickers. Without this the tag list is every tag in the
  // workspace and picking one silently contradicts the chosen project.
  const scopedTags = useMemo(
    () => (projectId === NONE ? tags : tags.filter((t) => t.project_id === projectId)),
    [tags, projectId],
  );
  const scopedTasks = useMemo(
    () => (projectId === NONE ? tasks : tasks.filter((t) => t.project_id === projectId)),
    [tasks, projectId],
  );

  const targetMin = target.trim() ? parseEstimate(target) : null;
  const targetInvalid = target.trim() !== '' && targetMin == null;
  // A cap needs something to cap — mirrors the `goals_cap_needs_target`
  // constraint so the user is stopped here rather than by a rejected op.
  const capNeedsTarget = direction === 'at_most' && targetMin == null;
  const valid = name.trim().length > 0 && !targetInvalid && !capNeedsTarget;

  const submit = () => {
    if (!valid) return;
    const fields = {
      name: name.trim(),
      cadence,
      direction,
      target_min: targetMin,
      project_id: projectId === NONE ? null : (projectId as UUID),
      tag_id: tagId === NONE ? null : (tagId as UUID),
      task_id: taskId === NONE ? null : (taskId as UUID),
    };
    if (existing) {
      updateGoal({ ...existing, ...fields });
    } else {
      createGoal(fields);
    }
    close();
  };

  const opt = <T extends string>(
    items: { id: string; label: string }[],
    noneLabel: string,
  ): SelectOption<T>[] => [
    { value: NONE as T, label: noneLabel },
    ...items.map((i) => ({ value: i.id as T, label: i.label })),
  ];

  return (
    <div className="modal-backdrop" onClick={close}>
      <div className="modal goal-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="ext">{name.trim() || (existing ? existing.name : 'New goal')}</span>
          <span className="grow" />
          {existing && (
            <button
              className="icon-btn modal-head-danger"
              onClick={() => { deleteGoal(existing.id); close(); }}
              title="Delete goal"
            >
              <Trash2 size={15} strokeWidth={1.75} />
            </button>
          )}
          <button className="icon-btn" onClick={close} title="Close (Esc)" aria-label="Close">
            <X size={15} strokeWidth={1.75} />
          </button>
        </div>

        <div className="np-body">
          <label className="np-label">Name</label>
          <input
            className="np-title"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Deep work on Atlas"
            maxLength={80}
            autoFocus
            onKeyDown={(e) => {
              if (e.key === 'Enter' && valid) { e.preventDefault(); submit(); }
              if (e.key === 'Escape') close();
            }}
          />

          <label className="np-label">Target</label>
          <div className="goal-target-row">
            <Select<GoalDirection>
              value={direction}
              onChange={setDirection}
              options={[
                { value: 'at_least', label: 'at least', hint: 'A floor to reach' },
                { value: 'at_most', label: 'at most', hint: 'A cap to stay under' },
              ]}
              menuMinWidth={190}
            />
            <input
              className="np-title goal-target-input"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={direction === 'at_most' ? '30m' : '1h30'}
              aria-label="Target duration"
            />
            <Select<GoalCadence>
              value={cadence}
              onChange={setCadence}
              options={[
                { value: 'daily', label: 'daily' },
                { value: 'weekly', label: 'weekly' },
              ]}
              menuMinWidth={140}
            />
          </div>
          <p className="goal-hint">
            {targetInvalid
              ? <span className="goal-hint-err">Couldn't read that duration — try "1h30", "90m" or "2h".</span>
              : capNeedsTarget
                ? <span className="goal-hint-err">A cap needs a target — "at most" what?</span>
                : targetMin == null
                  ? 'No target: any matching block counts, so the period is met just by showing up.'
                  : direction === 'at_most'
                    ? `Met on a ${cadence === 'weekly' ? 'week' : 'day'} you stay under ${fmtMin(targetMin)}. An empty ${cadence === 'weekly' ? 'week' : 'day'} passes.`
                    : `Met on a ${cadence === 'weekly' ? 'week' : 'day'} you reach ${fmtMin(targetMin)}.`}
          </p>

          <label className="np-label">Counts blocks matching</label>
          <div className="goal-scope">
            <Select<string>
              value={projectId}
              onChange={(v) => {
                setProjectId(v);
                // The old tag/task belong to the old project; keeping
                // them would make an unsatisfiable AND.
                setTagId(NONE);
                setTaskId(NONE);
              }}
              options={opt(projects.map((p) => ({ id: p.id, label: p.title })), 'Any project')}
            />
            <Select<string>
              value={tagId}
              onChange={setTagId}
              options={opt(
                scopedTags.map((t) => ({ id: t.id, label: `#${t.title}` })),
                'Any tag',
              )}
            />
            <Select<string>
              value={taskId}
              onChange={setTaskId}
              options={opt(
                scopedTasks.map((t) => ({ id: t.id, label: t.title })),
                'Any task',
              )}
            />
          </div>
          <p className="goal-hint">
            All three are combined with AND. Tags belong to a project, so
            picking one already narrows the project.
          </p>
        </div>

        <div className="modal-footer">
          <button className="btn" onClick={close}>Cancel</button>
          <button className="btn create-primary" onClick={submit} disabled={!valid}>
            {existing ? 'Save' : 'Create goal'}
          </button>
        </div>
      </div>
    </div>
  );
}
