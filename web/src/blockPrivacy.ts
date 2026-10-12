import type { Project, Task, TimeBlock, UUID } from './types';

/** Apply a project's dev privacy rule to cached and incoming time blocks. */
export function visibleProjectBlocks(
  blocks: TimeBlock[], tasks: Pick<Task, 'id' | 'project_id'>[], projects: Project[], meId: UUID | null,
): TimeBlock[] {
  const restricted = new Set(projects.filter((project) =>
    project.members.some((member) => member.user_id === meId && member.role === 'dev'),
  ).map((project) => project.id));
  const hiddenTasks = new Set(tasks.filter((task) => restricted.has(task.project_id)).map((task) => task.id));
  return blocks.filter((block) => block.user_id === meId || !hiddenTasks.has(block.task_id));
}

/** Derive presence before dropping cached teammate blocks on a role change. */
export function withPrivateTime(tasks: Task[], blocks: TimeBlock[], projects: Project[], meId: UUID | null): Task[] {
  const restricted = new Set(projects.filter((project) => project.members.some((m) =>
    m.user_id === meId && m.role === 'dev')).map((p) => p.id));
  const hiddenTasks = new Set(blocks.filter((b) => b.user_id !== meId).map((b) => b.task_id));
  return tasks.map((task) => ({ ...task, has_private_time: restricted.has(task.project_id)
    && (!!task.has_private_time || hiddenTasks.has(task.id)) }));
}
