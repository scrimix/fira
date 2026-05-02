import type { Bootstrap, LinkedCalendar, PersonalCalendar, User, UserLink, Workspace, WorkspaceRole } from './types';

// Always go through the Vite dev proxy at /api. The proxy target is
// configured server-side in vite.config.ts (env: VITE_API_PROXY_TARGET),
// which means the browser sees a same-origin URL regardless of whether
// the api is on localhost or behind a docker service name.
const BASE = '/api';

export class HttpError extends Error {
  constructor(public status: number, public path: string, body?: string) {
    super(body && body.length > 0 ? body : `${path} -> ${status}`);
  }
}

// Module-level mutable header. Routes that need a workspace context (every
// scoped read + every write) ride on this. The store sets it after the user
// picks a workspace (default: their personal one).
let activeWorkspaceId: string | null = null;
export function setActiveWorkspaceId(id: string | null) {
  activeWorkspaceId = id;
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (activeWorkspaceId) headers['x-workspace-id'] = activeWorkspaceId;
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'same-origin',
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    // Server error envelope is `{ "error": "..." }`. Fall back to the raw
    // text if it's not JSON, so dev/proxy errors aren't swallowed silently.
    let msg: string | undefined;
    try {
      const body = await res.text();
      try {
        const parsed = JSON.parse(body) as { error?: unknown };
        if (parsed && typeof parsed.error === 'string') msg = parsed.error;
        else if (body.length > 0) msg = body;
      } catch {
        if (body.length > 0) msg = body;
      }
    } catch { /* body read failed; fall through to default message */ }
    throw new HttpError(res.status, path, msg);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export interface OpResult {
  op_id: string;
  status: 'ok' | 'error';
  error?: string;
}

export interface ChangesResponse {
  ops: import('./store/outbox').ChangeEntry[];
  cursor: number;
}

export const api = {
  me: () => req<User>('GET', '/me'),
  bootstrap: () => req<Bootstrap>('GET', '/bootstrap'),
  authConfig: () => req<{ dev_auth: boolean }>('GET', '/auth/config'),
  /// Dev-only: drop a session for an existing fixture user. Doesn't touch
  /// data — re-seeding is a separate CLI step (`cargo run --bin seed -- --drop`).
  devLogin: (email: string) =>
    fetch(`${BASE}/auth/dev-login?email=${encodeURIComponent(email)}`, {
      credentials: 'same-origin',
      redirect: 'manual',
    }),
  logout: () => req<void>('POST', '/auth/logout'),
  createProject: (input: { title: string; icon: string; color: string }) =>
    req<import('./types').Project>('POST', '/projects', input),
  updateProject: (
    id: string,
    // external_url_template is intentionally `string | null` (not optional):
    // null clears the field, string sets, omitting the key leaves it alone.
    patch: Partial<{
      title: string;
      icon: string;
      color: string;
      external_url_template: string | null;
    }>,
  ) => req<import('./types').Project>('PATCH', `/projects/${id}`, patch),
  setProjectMembers: (
    id: string,
    members: { user_id: string; role: import('./types').ProjectRole }[],
  ) => req<import('./types').Project>('PUT', `/projects/${id}/members`, { members }),
  deleteProject: (id: string) => req<void>('DELETE', `/projects/${id}`),
  listMyWorkspaces: () => req<Workspace[]>('GET', '/workspaces'),
  createWorkspace: (title: string) =>
    req<Workspace>('POST', '/workspaces', { title }),
  renameWorkspace: (id: string, title: string) =>
    req<Workspace>('PATCH', `/workspaces/${id}`, { title }),
  setWorkspaceMembers: (
    id: string,
    members: { user_id: string; role: WorkspaceRole }[],
  ) => req<Workspace>('PUT', `/workspaces/${id}/members`, { members }),
  setWorkspaceMemberRole: (id: string, userId: string, role: WorkspaceRole) =>
    req<Workspace>('PATCH', `/workspaces/${id}/members/${userId}`, { role }),
  deleteWorkspace: (id: string) => req<void>('DELETE', `/workspaces/${id}`),
  listWorkspaceUsers: (id: string) =>
    req<User[]>('GET', `/workspaces/${id}/users`),
  /// Owner-only: every user in the system, including ones not yet in any
  /// shared workspace — needed when adding a brand-new Google sign-in.
  listAllUsersForWorkspace: (id: string) =>
    req<User[]>('GET', `/workspaces/${id}/all-users`),
  postOps: (ops: import('./store/outbox').Op[]) =>
    req<{ results: OpResult[] }>('POST', '/ops', { ops }),
  getChanges: (since: number) =>
    req<ChangesResponse>('GET', `/changes?since=${since}`),
  listLinks: () => req<UserLink[]>('GET', '/links'),
  createLink: (email: string) =>
    req<UserLink>('POST', '/links', { email }),
  acceptLink: (id: string) =>
    req<UserLink>('POST', `/links/${id}/accept`),
  deleteLink: (id: string) => req<void>('DELETE', `/links/${id}`),
  linkedCalendar: () => req<LinkedCalendar>('GET', '/linked/calendar'),
  personalCalendar: () => req<PersonalCalendar>('GET', '/personal/calendar'),
};

// Server-driven; the browser navigates here so cookies and the OAuth redirect
// chain work without us re-implementing them on the client.
export const loginUrl = `${BASE}/auth/google/login`;
