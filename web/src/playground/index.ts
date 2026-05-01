// Playground mode entry/exit + flag.
//
// "Playground" means the app runs against an in-memory seed instead of the
// real backend. The flag lives in localStorage so a reload stays in
// playground (otherwise the user would lose their tinkering on every refresh).
// All persistence flows through the existing zustand persist middleware —
// playground doesn't get its own storage layer, just its own seed source.

const FLAG_KEY = 'fira:playground';

export function isPlayground(): boolean {
  try {
    return localStorage.getItem(FLAG_KEY) === '1';
  } catch {
    return false;
  }
}

export function markPlayground() {
  try { localStorage.setItem(FLAG_KEY, '1'); } catch { /* private mode */ }
}

export function clearPlayground() {
  try { localStorage.removeItem(FLAG_KEY); } catch { /* private mode */ }
}

export { buildPlaygroundSeed } from './seed';
export type { PlaygroundSeed } from './seed';
