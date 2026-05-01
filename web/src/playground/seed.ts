// Playground snapshot loader.
//
// Reads `bootstrap.json` — the JSON dump of `/api/bootstrap` produced by
// `cargo run --bin dump-bootstrap` — and hands it back in the shape the
// store's hydrate flow expects. The dumped JSON is a literal frozen
// snapshot: `snapshot_at` is the moment it was taken, every timestamp
// inside (`time_blocks.start_at`, `gcal.start_at`, etc.) is relative to
// that moment.
//
// The frontend doesn't re-anchor any of those timestamps. Instead the
// playground hydrate calls `setFrozenNow(snapshot.snapshot_at)`, which
// makes `time.ts`'s `weekStartMs()` / `todayDayIndex()` / `nowTimeMin()`
// return values relative to the snapshot. Everything else is identical
// to a real bootstrap.

import type { Bootstrap, User, Workspace } from '../types';
import snapshotJson from './bootstrap.json';

interface PlaygroundSnapshot {
  snapshot_at: string;
  me: User;
  workspace: Workspace;
  bootstrap: Bootstrap;
}

export function loadPlaygroundSnapshot(): PlaygroundSnapshot {
  // The JSON import is statically typed as the file's literal shape; widen
  // to the protocol type. The dump-bootstrap bin is the only writer of this
  // file so structural drift would surface there, not here.
  return snapshotJson as unknown as PlaygroundSnapshot;
}
