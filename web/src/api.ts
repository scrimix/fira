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

export const api = {
  me: () => req<User>('GET', '/me'),
  bootstrap: () => req<Bootstrap>('GET', '/bootstrap'),
  logout: () => req<void>('POST', '/auth/logout'),
  createProject: (input: { title: string; icon: string; color: string }) =>
    req<import('./types').Project>('POST', '/projects', input),
  updateProject: (id: string, patch: Partial<{ title: string; icon: string; color: string }>) =>
    req<import('./types').Project>('PATCH', `/projects/${id}`, patch),
};

// Server-driven; the browser navigates here so cookies and the OAuth redirect
// chain work without us re-implementing them on the client.
export const loginUrl = `${BASE}/auth/google/login`;
