// What moving a task to another project actually costs.
//
// `project_id` isn't a label on a task: it's the scope key for who can
// see the task, for who can see the time blocks logged against it
// (blocks are reached through task → project, not through their own
// owner), and for the four things a task points at — tags, epic, sprint,
// issue-link template. All of that changes on a move, and the confirm
// dialog is the only place in the product where any of it is ever
// surfaced. If a consequence isn't reported here, it happens invisibly.
//
// Computed entirely from local state — the store already holds project
// members, blocks, tags, epics and sprints, all correctly scoped — so
// the dialog renders on picker change with no preflight round trip. The
// server recomputes the `strandedUsers` half as the authority and
// refuses an unacknowledged move with 409.

import type { Epic, Project, Sprint, Tag, Task, TimeBlock, User, UUID } from './types';

export interface StrandedUser {
  user: User;
  /// Blocks of theirs on this task that stop being visible. Reported
  /// per-person because one lost block and forty are very different
  /// decisions.
  blockCount: number;
  /// Flagged inline rather than as a separate row, so someone who is
  /// both assignee and block owner appears once.
  isAssignee: boolean;
}

export interface MoveImpact {
  /// People with a stake in the task — the assignee and every block
  /// owner — who can't see the target project. Recoverable: their blocks
  /// are never deleted, and adding them to the target brings everything
  /// back on the next hydrate.
  stranded: StrandedUser[];
  /// Dropped from the task for good. Moving it back doesn't restore any
  /// of these.
  droppedTags: Tag[];
  droppedEpic: Epic | null;
  droppedSprint: Sprint | null;
  /// True when the move costs nothing — the dialog still shows, but as a
  /// one-line confirm.
  harmless: boolean;
}

/// Whether `userId` can see `project`. Must match the server's
/// `require_project_access` predicate or the dialog and the server
/// disagree about who gets stranded.
///
/// `role === 'inactive'` still counts as access: inactive is a display
/// state that hides someone from inbox assignee groups, not an
/// authorization state. Don't add a role filter here.
export function hasProjectAccess(
  project: Project,
  userId: UUID,
  workspaceOwnerIds: ReadonlySet<UUID>,
): boolean {
  return project.members.some((m) => m.user_id === userId)
    || workspaceOwnerIds.has(userId);
}

export function computeMoveImpact(
  task: Task,
  toProject: Project,
  ctx: {
    users: User[];
    blocks: TimeBlock[];
    tags: Tag[];
    epics: Epic[];
    sprints: Sprint[];
    workspaceOwnerIds: ReadonlySet<UUID>;
  },
): MoveImpact {
  const taskBlocks = ctx.blocks.filter((b) => b.task_id === task.id);

  // Assignee + every block owner, deduped. `created_by` is deliberately
  // absent: it's attribution for a past event, and the creator has no
  // ongoing need for the row.
  const involved = new Set<UUID>(taskBlocks.map((b) => b.user_id));
  if (task.assignee_id) involved.add(task.assignee_id);

  const stranded: StrandedUser[] = [];
  for (const userId of involved) {
    if (hasProjectAccess(toProject, userId, ctx.workspaceOwnerIds)) continue;
    const user = ctx.users.find((u) => u.id === userId);
    if (!user) continue; // outside our directory; server is the authority
    stranded.push({
      user,
      blockCount: taskBlocks.filter((b) => b.user_id === userId).length,
      isAssignee: task.assignee_id === userId,
    });
  }
  stranded.sort((a, b) => a.user.name.localeCompare(b.user.name));

  const droppedTags = task.tag_ids
    .map((id) => ctx.tags.find((t) => t.id === id))
    .filter((t): t is Tag => t != null)
    .sort((a, b) => a.title.localeCompare(b.title));
  const droppedEpic = task.epic_id
    ? ctx.epics.find((e) => e.id === task.epic_id) ?? null
    : null;
  const droppedSprint = task.sprint_id
    ? ctx.sprints.find((sp) => sp.id === task.sprint_id) ?? null
    : null;

  return {
    stranded,
    droppedTags,
    droppedEpic,
    droppedSprint,
    harmless: stranded.length === 0
      && droppedTags.length === 0
      && droppedEpic == null
      && droppedSprint == null,
  };
}
