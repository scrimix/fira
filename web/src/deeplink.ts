import type { UUID } from './types';

// Shareable task links are hash-based so they need no server-side routing:
// a full page load of `…/#/w/<workspace>/t/<task>` still serves the SPA,
// which then reads the hash and opens the task. The workspace segment lets
// a recipient in a different workspace auto-switch on open. Legacy/short
// links without the workspace segment (`#/t/<task>`) still parse.
const TASK_HASH_RE = /^#\/(?:w\/([^/]+)\/)?t\/([^/]+)\/?$/;

export function buildTaskLink(workspaceId: UUID | null, taskId: UUID): string {
  const base = window.location.origin + window.location.pathname + window.location.search;
  const path = workspaceId
    ? `#/w/${encodeURIComponent(workspaceId)}/t/${encodeURIComponent(taskId)}`
    : `#/t/${encodeURIComponent(taskId)}`;
  return base + path;
}

export function parseTaskLink(hash: string): { workspaceId: UUID | null; taskId: UUID } | null {
  const m = TASK_HASH_RE.exec(hash);
  if (!m) return null;
  return {
    workspaceId: (m[1] ? decodeURIComponent(m[1]) : null) as UUID | null,
    taskId: decodeURIComponent(m[2]) as UUID,
  };
}
