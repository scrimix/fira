// Outbox: append-only log of mutations to be drained by a sync worker.

export type OpKind =
  | { kind: 'task.create'; task: import('../types').Task }
  | { kind: 'task.tick'; task_id: string; done: boolean }
  | { kind: 'task.set_status'; task_id: string; status: 'backlog' | 'todo' | 'in_progress' | 'done' }
  | { kind: 'task.set_section'; task_id: string; section: 'now' | 'later' | 'done' }
  | { kind: 'task.set_assignee'; task_id: string; assignee_id: string | null }
  | { kind: 'task.set_estimate'; task_id: string; estimate_min: number | null }
  | { kind: 'task.reorder'; project_id: string; section: 'now' | 'later' | 'done'; ordered: string[] }
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
  | { kind: 'task.set_tags'; task_id: string; tag_ids: string[] };

/// Server-only op kinds — synthesized in REST handlers and delivered via
/// /changes. Clients never enqueue these; they only apply them.
export type RemoteOnlyOpKind =
  | { kind: 'project.create'; project: import('../types').Project }
  | { kind: 'project.update'; project: import('../types').Project }
  | { kind: 'project.set_members'; project_id: string; members: import('../types').ProjectMember[] }
  | { kind: 'project.delete'; project_id: string }
  | { kind: 'workspace.set_members'; workspace_id: string; members: import('../types').WorkspaceMember[] }
  | { kind: 'workspace.set_member_role'; workspace_id: string; user_id: string; role: import('../types').WorkspaceRole };

export type AnyOpKind = OpKind | RemoteOnlyOpKind;

/// One row of the server's change log.
export interface ChangeEntry {
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
