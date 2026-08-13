import { useEffect, useState } from 'react';
import { fmtElapsed, syncLog } from './synclog';

// matchMedia subscription as a hook. Re-renders when the query flips.
// Mobile breakpoint is centralized here so all components answer the
// same question instead of each one inlining its own width threshold.
export function useMediaQuery(query: string): boolean {
  const [match, setMatch] = useState(() =>
    typeof window !== 'undefined' && window.matchMedia(query).matches,
  );
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia(query);
    const onChange = () => setMatch(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [query]);
  return match;
}

export function useIsMobile(): boolean {
  return useMediaQuery('(max-width: 700px)');
}

// "Is anyone actually looking at this tab?"
//
// `visibilitychange` is the browser's own signal that the page moved to or
// from the background — the user switched tabs, minimized the window, locked
// the screen, or pocketed their phone. We use it to stand the background sync
// down: an app left open overnight otherwise keeps polling and holding a
// socket open until morning, for nobody.
//
// The grace period is the point. Flicking to another tab for ten seconds
// shouldn't tear down a WebSocket and rebuild it on the way back, so only a
// sustained absence counts as idle. Note that the browser throttles timers in
// hidden tabs (~1/min after five minutes), so the grace timer can fire late —
// harmless here, it only delays the stand-down.
export function useAppActive(graceMs = 2 * 60_000): boolean {
  const [active, setActive] = useState(() =>
    typeof document === 'undefined' || document.visibilityState === 'visible',
  );
  useEffect(() => {
    if (typeof document === 'undefined') return;
    let timer: number | null = null;
    // Timestamps for the dev log only — when the tab went out of sight, and
    // when the grace period actually expired. The gap between them is the
    // difference between "stepped away" and "asleep".
    let hiddenAt: number | null = null;
    let idleSince: number | null = null;
    const clear = () => {
      if (timer !== null) {
        window.clearTimeout(timer);
        timer = null;
      }
    };
    const onChange = () => {
      if (document.visibilityState === 'visible') {
        const wasPending = timer !== null;
        clear();
        if (idleSince !== null) {
          syncLog(`WAKE — visible after ${fmtElapsed(Date.now() - idleSince)} idle`);
          idleSince = null;
        } else if (wasPending) {
          const away = hiddenAt !== null ? fmtElapsed(Date.now() - hiddenAt) : '?';
          syncLog(`visible again after ${away} — within grace, sync never stood down`);
        }
        hiddenAt = null;
        setActive(true);
      } else if (timer === null) {
        hiddenAt = Date.now();
        syncLog(`tab hidden — standing down in ${Math.round(graceMs / 1000)}s unless you come back`);
        timer = window.setTimeout(() => {
          timer = null;
          idleSince = Date.now();
          syncLog('SLEEP — grace elapsed, background sync stopping');
          setActive(false);
        }, graceMs);
      }
    };
    document.addEventListener('visibilitychange', onChange);
    return () => {
      document.removeEventListener('visibilitychange', onChange);
      clear();
    };
  }, [graceMs]);
  return active;
}
