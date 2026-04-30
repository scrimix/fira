// Outbox: append-only log of mutations to be drained by a sync worker.
//
// For v1 the worker is a stub — ops accumulate and never go anywhere.
// What matters now is the *shape* and the seam:
//
//   - Every store action that mutates persistable state appends an Op here.
//   - When write endpoints land, the worker drains ops in order.
//   - Op shape is "intent", not "diff": "tick_subtask" not "subtasks[2].done = true".
//     This matches how Linear/Replicache model offline mutations and survives
//     concurrent edits better than diff-based replay.
//
// The op_id is what the server uses for idempotency: a retry of the same op_id
// is a no-op. Generate it client-side.

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
  | { kind: 'subtask.create'; subtask: import('../types').Subtask }
  | { kind: 'subtask.tick'; subtask_id: string; done: boolean }
  | { kind: 'subtask.set_title'; subtask_id: string; title: string }
  | { kind: 'subtask.delete'; subtask_id: string }
  | { kind: 'block.create'; block: import('../types').TimeBlock }
  | { kind: 'block.update'; block_id: string; patch: Partial<import('../types').TimeBlock> }
  | { kind: 'block.delete'; block_id: string };

/// Server-only op kinds — synthesized in REST handlers and delivered via
/// /changes. Clients never enqueue these; they only apply them.
export type RemoteOnlyOpKind =
  | { kind: 'project.create'; project: import('../types').Project }
  | { kind: 'project.update'; project: import('../types').Project }
  | { kind: 'project.set_members'; project_id: string; members: string[] };

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
}

export function newOp(payload: OpKind): Op {
  return {
    op_id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    status: 'queued',
    payload,
  };
}
