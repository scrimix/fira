// IndexedDB-backed storage for the zustand `persist` middleware.
//
// The persisted snapshot holds the whole workspace (tasks, blocks, outbox…)
// and outgrew localStorage's ~5MB per-origin quota (sprint 27 §4). IndexedDB
// has a far larger quota and stores structured-clone values, so there's no
// JSON.stringify of the full snapshot on every write, and Maps
// (appliedOpIds) round-trip natively.
//
// Migration: a snapshot still sitting in localStorage from an older build is
// read once, copied into IndexedDB (outbox included), then removed.
//
// Fallback: where IndexedDB is unavailable (some private modes), it falls
// back to JSON in localStorage. Write failures (quota, clone errors) are
// logged and swallowed in both paths. A failed cache write must never break
// the caller's set().

import { get, set, del } from 'idb-keyval';
import type { PersistStorage, StorageValue } from 'zustand/middleware';

// JSON can't round-trip a Map (we use one for appliedOpIds), so the
// JSON form tags it and the reviver rebuilds it on load. Only the legacy
// localStorage path and the localStorage fallback use these.
const replacer = (_k: string, v: unknown) =>
  v instanceof Map
    ? { __type: 'Map', entries: Array.from(v.entries()) }
    : v;
const reviver = (_k: string, v: unknown) => {
  if (v && typeof v === 'object' && (v as { __type?: string }).__type === 'Map') {
    return new Map((v as { entries: [string, number][] }).entries);
  }
  return v;
};

const hasIdb = typeof indexedDB !== 'undefined';

function lsGet<S>(name: string): StorageValue<S> | null {
  try {
    const raw = localStorage.getItem(name);
    return raw ? (JSON.parse(raw, reviver) as StorageValue<S>) : null;
  } catch { return null; }
}
function lsSet(name: string, value: unknown) {
  try {
    localStorage.setItem(name, JSON.stringify(value, replacer));
  } catch (e) {
    console.warn('[persist] localStorage write failed', e);
  }
}
function lsRemove(name: string) {
  try { localStorage.removeItem(name); } catch { /* private mode */ }
}

// Set while the snapshot is being cleared (logout / account switch) so a
// state change between the delete and the page reload can't write the
// previous session's data back.
let paused = false;

export function createIdbStorage<S>(): PersistStorage<S> {
  return {
    getItem: async (name) => {
      if (!hasIdb) return lsGet<S>(name);
      try {
        const stored = await get<StorageValue<S>>(name);
        if (stored) return stored;
      } catch {
        // IndexedDB present but refusing to open (private mode).
        return lsGet<S>(name);
      }
      // One-time migration from the pre-IndexedDB localStorage snapshot.
      // Drop the legacy key only once the IndexedDB copy is committed, so
      // a failed write can't lose queued outbox ops.
      const legacy = lsGet<S>(name);
      if (legacy) {
        try { await set(name, legacy); lsRemove(name); } catch { /* keep legacy */ }
      }
      return legacy;
    },
    setItem: async (name, value) => {
      if (paused) return;
      if (!hasIdb) { lsSet(name, value); return; }
      try {
        await set(name, value);
      } catch (e) {
        if (e instanceof DOMException && e.name === 'DataCloneError') {
          // Something non-cloneable slipped into partialize. Store its
          // JSON-equivalent rather than silently losing the cache.
          try {
            await set(name, JSON.parse(JSON.stringify(value, replacer), reviver));
            return;
          } catch { /* fall through to warn */ }
        }
        console.warn('[persist] IndexedDB write failed', e);
      }
    },
    removeItem: async (name) => {
      if (hasIdb) { try { await del(name); } catch { /* unavailable */ } }
      lsRemove(name);
    },
  };
}

/// Stop persisting and delete the snapshot. Await this before a hard reload
/// on logout / account switch, or the next session could rehydrate the
/// previous user's data.
export async function clearPersistedStore(name = 'fira:store-v1'): Promise<void> {
  paused = true;
  if (hasIdb) { try { await del(name); } catch { /* unavailable */ } }
  lsRemove(name);
}
