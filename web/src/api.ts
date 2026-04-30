import type { Bootstrap, User } from './types';

// Always go through the Vite dev proxy at /api. The proxy target is
// configured server-side in vite.config.ts (env: VITE_API_PROXY_TARGET),
// which means the browser sees a same-origin URL regardless of whether
// the api is on localhost or behind a docker service name.
const BASE = '/api';

export class HttpError extends Error {
  constructor(public status: number, public path: string) {
    super(`${path} -> ${status}`);
  }
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'same-origin',
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new HttpError(res.status, path);
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
  devSeed: () => req<void>('POST', '/auth/dev-seed'),
  logout: () => req<void>('POST', '/auth/logout'),
  createProject: (input: { title: string; icon: string; color: string }) =>
    req<import('./types').Project>('POST', '/projects', input),
  updateProject: (
    id: string,
    patch: Partial<{ title: string; icon: string; color: string }>,
  ) => req<import('./types').Project>('PATCH', `/projects/${id}`, patch),
  setProjectMembers: (id: string, members: string[]) =>
    req<import('./types').Project>('PUT', `/projects/${id}/members`, { members }),
  listAllUsers: () => req<User[]>('GET', '/users'),
  postOps: (ops: import('./store/outbox').Op[]) =>
    req<{ results: OpResult[] }>('POST', '/ops', { ops }),
  getChanges: (since: number) =>
    req<ChangesResponse>('GET', `/changes?since=${since}`),
};

// Server-driven; the browser navigates here so cookies and the OAuth redirect
// chain work without us re-implementing them on the client.
export const loginUrl = `${BASE}/auth/google/login`;
