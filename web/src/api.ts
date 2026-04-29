import type { Bootstrap } from './types';

// Always go through the Vite dev proxy at /api. The proxy target is
// configured server-side in vite.config.ts (env: VITE_API_PROXY_TARGET),
// which means the browser sees a same-origin URL regardless of whether
// the api is on localhost or behind a docker service name.
const BASE = '/api';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  bootstrap: () => get<Bootstrap>('/bootstrap'),
};
