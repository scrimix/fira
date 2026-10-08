// Outbox: append-only log of mutations to be drained by a sync worker.

export type OpKind =
  | { kind: 'task.create'; task: import('../types').Task }
  | { kind: 'task.tick'; task_id: string; done: boolean }
  | { kind: 'task.set_status'; task_id: string; status: 'backlog' | 'todo' | 'in_progress' | 'done' }
  | { kind: 'task.set_section'; task_id: string; section: 'now' | 'later' | 'done' | 'someday' | 'recurring' }
  | { kind: 'task.set_assignee'; task_id: string; assignee_id: string | null }
  | { kind: 'task.set_estimate'; task_id: string; estimate_min: number | null }
  | { kind: 'task.reorder'; project_id: string; section: 'now' | 'later' | 'done' | 'someday' | 'recurring'; ordered: string[] }
  | { kind: 'task.set_title'; task_id: string; title: string }
  | { kind: 'task.set_description'; task_id: string; description_md: string }
  | { kind: 'task.set_external_id'; task_id: string; external_id: string | null }
  | { kind: 'task.set_external_url'; task_id: string; external_url: string | null }
  | { kind: 'task.delete'; task_id: string }
  | { kind: 'subtask.create'; subtask: import('../types').Subtask }
  | { kind: 'subtask.tick'; subtask_id: string; done: boolean }
  | { kind: 'subtask.set_title'; subtask_id: string; title: string }
  | { kind: 'subtask.delete'; subtask_id: string }
  | { kind: 'subtask.reorder'; task_id: string; ordered: string[] }
  | { kind: 'block.create'; block: import('../types').TimeBlock }
  | { kind: 'block.update'; block_id: string; patch: Partial<import('../types').TimeBlock> }
  | { kind: 'block.delete'; block_id: string }
  | { kind: 'tag.create'; tag: import('../types').Tag }
  | { kind: 'tag.set_title'; tag_id: string; title: string }
  | { kind: 'tag.set_color'; tag_id: string; color: string }
  | { kind: 'tag.delete'; tag_id: string }
  | { kind: 'task.set_tags'; task_id: string; tag_ids: string[] }
  // Plan-board ops. Narrow per-field setters, like task.set_assignee:
  // `track_id` is meaningfully nullable ("No track") and sprints are
  // edited by drag rather than a form, so neither goal.update's
  // whole-entity shape nor block.update's `patch` fits.
  | { kind: 'track.create'; track: import('../types').Track }
  | { kind: 'track.set_title'; track_id: string; title: string }
  | { kind: 'track.set_color'; track_id: string; color: string }
  | { kind: 'track.reorder'; project_id: string; ordered: string[] }
  | { kind: 'track.delete'; track_id: string }
  | { kind: 'sprint.create'; sprint: import('../types').Sprint }
  | { kind: 'sprint.set_title'; sprint_id: string; title: string }
  // One op for two columns: a span is a single value, and move and
  // resize both emit it. `ends_on` is exclusive.
  | { kind: 'sprint.set_dates'; sprint_id: string; starts_on: string; ends_on: string }
  | { kind: 'sprint.set_track'; sprint_id: string; track_id: string | null }
  | { kind: 'sprint.delete'; sprint_id: string }
  | { kind: 'task.set_sprint'; task_id: string; sprint_id: string | null }
  | { kind: 'task.add_attachment'; task_id: string; attachment: import('../types').Attachment }
  | { kind: 'task.remove_attachment'; task_id: string; attachment: import('../types').Attachment }
  | { kind: 'task.move_attachment'; from_task_id: string; to_task_id: string; attachment: import('../types').Attachment }
  // Goal ops carry the goal's *whole* definition rather than a partial
  // patch: target_min and all three scope refs are meaningfully
  // nullable, so a patch couldn't distinguish "leave alone" from
  // "clear". The editor is a modal that submits the full form anyway.
  //
  // These are private ops — the server delivers them only back to their
  // author, so unlike every other kind here they never reach another
  // client. `workspace_id` / `user_id` are set server-side from the
  // session and are deliberately absent from the payload.
  | { kind: 'goal.create'; goal: import('../types').Goal }
  | { kind: 'goal.update'; goal: import('../types').Goal }
  | { kind: 'goal.delete'; goal_id: string }

/// Server-only op kinds — synthesized in REST handlers and delivered via
/// /changes. Clients never enqueue these; they only apply them.
export type RemoteOnlyOpKind =
  | { kind: 'project.create'; project: import('../types').Project }
  | { kind: 'project.update'; project: import('../types').Project }
  | { kind: 'project.set_members'; project_id: string; members: import('../types').ProjectMember[] }
  | { kind: 'project.delete'; project_id: string }
  | { kind: 'workspace.set_members'; workspace_id: string; members: import('../types').WorkspaceMember[] }
  | { kind: 'workspace.set_member_role'; workspace_id: string; user_id: string; role: import('../types').WorkspaceRole }
  // A task changing project. Written to the change log *twice* by the
  // server — once scoped to the source project, once to the target —
  // because `processed_ops.project_id` is a single column and the move
  // has two audiences with opposite needs (source members must drop the
  // task, target members must gain it). Both rows carry this same
  // payload; the apply branches on whether `to_project_id` is visible,
  // so a client in both projects applies the same upsert twice.
  | {
      kind: 'task.move_project';
      from_project_id: string;
      to_project_id: string;
      task: import('../types').Task;
      // The task's blocks ride along: they're reached through
      // task → project, so a target-project member who wasn't in the
      // source has never seen them and would otherwise gain the task
      // with none of its history until the next hydrate.
      blocks: import('../types').TimeBlock[];
    };

export type AnyOpKind = OpKind | RemoteOnlyOpKind;

/// One row of the server's change log.
export interface ChangeEntry {
  project_id: string | null;
  seq: number;
  op_id: string;
  kind: string;
  payload: AnyOpKind;
  applied_at: string;
}

export interface Op {
  op_id: string;
  created_at: string;
  status: 'queued' | 'syncing' | 'synced' | 'error';
  payload: OpKind;
  // Ordered list of ops that, when applied via applyOpToState, undo the
  // local effect of `payload`. Computed at push time from pre-mutation
  // state so each op carries its own snapshot. Discard applies these in
  // order so local state stays consistent with what the server has.
  inverse?: OpKind[];
}

export function newOp(payload: OpKind, inverse?: OpKind[]): Op {
  return {
    op_id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    status: 'queued',
    payload,
    inverse,
  };
}
