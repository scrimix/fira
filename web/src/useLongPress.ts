import { useEffect, useRef, useState } from 'react';

interface Options {
  /** Milliseconds the user must hold before the press is "long". */
  holdMs?: number;
  /** Pixel travel that cancels the press before the timer fires. */
  cancelPx?: number;
  /** Mouse / pen pointers in addition to touch. Defaults to touch only. */
  acceptMouse?: boolean;
}

interface Result {
  /** True between the timer firing and pointerup/cancel. Drives the visual. */
  isPressing: boolean;
  /** Spread onto the target element. Inline styles only — no portals. */
  bind: {
    onPointerDown: (e: React.PointerEvent) => void;
    onPointerMove: (e: React.PointerEvent) => void;
    onPointerUp: (e: React.PointerEvent) => void;
    onPointerCancel: (e: React.PointerEvent) => void;
    onContextMenu: (e: React.MouseEvent) => void;
  };
  /**
   * True if the most recent pointerup followed a successful long-press
   * within ~50 ms. Caller can read this in `onClick` and bail out so the
   * synthetic click that iOS dispatches after pointerup doesn't trigger
   * a tap action (e.g. opening the task modal) on top of the drag.
   */
  shouldSuppressClick: () => boolean;
}

/**
 * Long-press detection on touch (and optionally mouse). Calls
 * `onLongPress` when the user has held still for `holdMs` (default
 * 220 ms) and movement stayed within `cancelPx` (default 8 px). The
 * `isPressing` flag flips true the moment the timer fires and stays
 * true until the gesture ends — perfect for a `data-pressing="true"`
 * attribute that drives a CSS visual.
 *
 * The hook deliberately uses pointer events for state (so cleanup is
 * trivial) but does *not* try to suppress page scroll itself. If the
 * caller needs the page to stop scrolling once the long-press has
 * fired, it should attach its own non-passive `touchmove` listener
 * inside the `onLongPress` callback.
 */
export function useLongPress(
  onLongPress: (e: React.PointerEvent) => void,
  options: Options = {},
): Result {
  const { holdMs = 220, cancelPx = 8, acceptMouse = false } = options;
  const [isPressing, setPressing] = useState(false);

  const stateRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    timer: number | null;
    locked: boolean;
    cancelled: boolean;
    suppressClickUntil: number;
  } | null>(null);

  // Keep the latest `onLongPress` callback in a ref so the hook's own
  // closures don't go stale when the caller re-renders with a new fn.
  const onLongPressRef = useRef(onLongPress);
  onLongPressRef.current = onLongPress;

  const cleanup = () => {
    const s = stateRef.current;
    if (!s) return;
    if (s.timer != null) window.clearTimeout(s.timer);
    stateRef.current = null;
  };

  // Make sure timers don't outlive the component.
  useEffect(() => () => cleanup(), []);

  const onPointerDown = (e: React.PointerEvent) => {
    if (e.pointerType === 'touch') {
      // continue
    } else if (e.pointerType === 'mouse' || e.pointerType === 'pen') {
      if (!acceptMouse) return;
    } else {
      return;
    }
    cleanup();
    const event = e;
    const timer = window.setTimeout(() => {
      const s = stateRef.current;
      if (!s) return;
      s.locked = true;
      s.timer = null;
      setPressing(true);
      onLongPressRef.current(event);
    }, holdMs);
    stateRef.current = {
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      timer,
      locked: false,
      cancelled: false,
      suppressClickUntil: 0,
    };
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const s = stateRef.current;
    if (!s || e.pointerId !== s.pointerId || s.locked) return;
    const dx = Math.abs(e.clientX - s.startX);
    const dy = Math.abs(e.clientY - s.startY);
    if (dx > cancelPx || dy > cancelPx) {
      // Movement before the timer fired — treat as a scroll/drag-cancel.
      // We still suppress the upcoming click since the user clearly
      // didn't mean a tap either (they were swiping).
      s.cancelled = true;
      s.suppressClickUntil = Date.now() + 50;
      if (s.timer != null) window.clearTimeout(s.timer);
      s.timer = null;
    }
  };

  const finish = (e: React.PointerEvent) => {
    const s = stateRef.current;
    if (!s || e.pointerId !== s.pointerId) return;
    if (s.locked) {
      // The gesture committed to a long-press; the synthetic click that
      // iOS dispatches right after pointerup should be swallowed so
      // it doesn't double-fire as a tap.
      s.suppressClickUntil = Date.now() + 50;
    }
    if (s.timer != null) window.clearTimeout(s.timer);
    setPressing(false);
    // Hold the suppression window readable for the click handler, then
    // drop the ref.
    const expiresAt = s.suppressClickUntil;
    stateRef.current = expiresAt > Date.now() ? { ...s, timer: null } : null;
    if (expiresAt > Date.now()) {
      window.setTimeout(() => {
        if (stateRef.current && stateRef.current.suppressClickUntil <= Date.now()) {
          stateRef.current = null;
        }
      }, expiresAt - Date.now() + 5);
    }
  };

  return {
    isPressing,
    bind: {
      onPointerDown,
      onPointerMove,
      onPointerUp: finish,
      onPointerCancel: finish,
      onContextMenu: (e) => e.preventDefault(),
    },
    shouldSuppressClick: () => {
      const s = stateRef.current;
      return !!s && s.suppressClickUntil > Date.now();
    },
  };
}
