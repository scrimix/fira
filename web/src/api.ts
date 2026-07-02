import type { AccountSummary, Attachment, Bootstrap, LinkedCalendar, PersonalCalendar, User, UserLink, UUID, WorkCalendar, Workspace, WorkspaceInvite, WorkspaceRole } from './types';

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

async function parseJsonResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
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
    throw new HttpError(res.status, res.url, msg);
  }
  if (res.status === 204) {
    return undefined as unknown as T;
  }
  const text = await res.text();
  if (text.length === 0) {
    return undefined as unknown as T;
  }
  return JSON.parse(text) as T;
}

async function parseBlobResponse(res: Response): Promise<Blob> {
  if (!res.ok) {
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
    throw new HttpError(res.status, res.url, msg);
  }
  return res.blob() as Promise<Blob>;
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
  return parseJsonResponse<T>(res);
}

async function uploadAttachment(file: File, task_id: UUID): Promise<{ attachment_id: UUID, storage_path: string }> {
  const formData = new FormData();
  formData.append('file', file);
  
  const headers: Record<string, string> = {};
  if (activeWorkspaceId) headers['x-workspace-id'] = activeWorkspaceId;

  const res = await fetch(`${BASE}/attachments/upload/${task_id}`, {
    method: 'POST',
    credentials: 'same-origin',
    body: formData,
    headers,
  });

  return parseJsonResponse<{ attachment_id: UUID, storage_path: string }>(res);
}

async function getAttachmentBlobUrl(attachment_id: UUID): Promise<string> {
  const headers: Record<string, string> = {};
  if (activeWorkspaceId) headers['x-workspace-id'] = activeWorkspaceId;

  const res = await fetch(`${BASE}/attachments/${attachment_id}`, {
    method: 'GET',
    credentials: 'same-origin',
    headers,
  });

  let blob = await parseBlobResponse(res);
  let url = URL.createObjectURL(blob);
  return url;
}

function triggerDownloadAttachment(attachment: Attachment, content: string) {
  const link = document.createElement('a')
  link.href = content;
  link.download = attachment.filename;
  document.body.appendChild(link);
  link.click();

  document.body.removeChild(link);
  URL.revokeObjectURL(content);
}

function getAttachmentUrl(attachment_id: UUID): string {
  const params = new URLSearchParams();
  if (activeWorkspaceId) params.append('workspace_id', activeWorkspaceId);
  const query = params.toString();
  return `/api/attachments/${attachment_id}${query ? '?' + query : ''}`;
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
  /// Accounts that have a live session in this browser's session group
  /// (the `sg` cookie). Used by the login picker and the in-app
  /// "Switch to Personal/Work" affordance to skip the Google round-trip.
  /// Returns [] when there's no group cookie or no live siblings.
  listAccounts: () => req<AccountSummary[]>('GET', '/auth/accounts'),
  /// Rotate the `sid` cookie to point at the latest live session for
  /// `user_id` in the current group. 404 if there's no live session
  /// (caller should fall back to /auth/google/login).
  switchAccount: (user_id: string) =>
    req<void>('POST', '/auth/switch', { user_id }),
  /// Hard sign-out: deletes every session in the group and clears `sg`.
  /// Use for "leaving this device" — plain `logout()` only kills the
  /// current session and leaves siblings around for the picker.
  signOutEverywhere: () =>
    req<void>('POST', '/auth/sign-out-everywhere'),
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
  removeWorkspaceMember: (id: string, userId: string) =>
    req<Workspace>('DELETE', `/workspaces/${id}/members/${userId}`),
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
  workCalendar: () => req<WorkCalendar>('GET', '/work/calendar'),
  listInvites: () => req<WorkspaceInvite[]>('GET', '/invites'),
  createInvite: (workspace_id: string, email: string, role?: WorkspaceRole) =>
    req<WorkspaceInvite>('POST', '/invites', { workspace_id, email, role }),
  cancelInvite: (id: string) =>
    req<WorkspaceInvite>('DELETE', `/invites/${id}`),
  acceptInvite: (id: string) =>
    req<WorkspaceInvite>('POST', `/invites/${id}/accept`),
  declineInvite: (id: string) =>
    req<WorkspaceInvite>('POST', `/invites/${id}/decline`),
  /// Patch the caller's account-scoped settings. Pass an explicit `null`
  /// to clear a field; omit a field to leave it unchanged.
  patchMySettings: (patch: { account_badge?: 'personal' | 'work' | null }) =>
    req<import('./types').UserSettings>('PATCH', '/me/settings', patch),
  disconnectGcal: () => req<void>('POST', '/gcal/disconnect'),

  uploadAttachment,
  getAttachmentBlobUrl,
  getAttachmentUrl,
  deleteAttachment: (attachment_id: string) =>
    req<void>('DELETE', `/attachments/${attachment_id}`),
  triggerDownloadAttachment,
};

// Server-driven; the browser navigates here so cookies and the OAuth redirect
// chain work without us re-implementing them on the client.
export const loginUrl = `${BASE}/auth/google/login`;
// Connect flow: full-page redirect to Google's incremental-authorization
// consent screen for `calendar.readonly`. The server stores credentials
// on the callback and redirects back to the SPA.
export const gcalConnectUrl = `${BASE}/gcal/connect`;
