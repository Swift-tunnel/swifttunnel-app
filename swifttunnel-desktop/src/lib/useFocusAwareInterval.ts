import { useEffect, useRef } from "react";

import { useSettingsStore } from "../stores/settingsStore";

/**
 * Interval that slows right down while the window is not focused.
 *
 * The UI runs inside WebView2. While connected, the Connect tab polls
 * throughput every 500ms, state every 2s and ping every 3s, and each one is an
 * IPC round trip into Rust followed by a React re-render. None of it is being
 * read once the player alt-tabs into a game, but it keeps costing CPU in the
 * WebView process and competing with the game for frames. Users have reported
 * this as SwiftTunnel making their game stutter and traced it to Edge WebView
 * themselves.
 *
 * LiveGraph already throttles its own render loop on `document.hasFocus()`;
 * this is the same idea applied to the polling that feeds it.
 *
 * Unfocused ticks are not stopped altogether, only slowed: coming back to a
 * window showing numbers from ten minutes ago looks broken. Returning to focus
 * fires the callback immediately so the UI is current by the time it is
 * looked at.
 *
 * Honours the `idle_when_unfocused` setting, so anyone watching the graph on a
 * second monitor can keep the fast rate.
 */
/**
 * How long to wait before the next poll.
 *
 * Split out from the hook so the rule can be tested without a DOM: this is the
 * whole behaviour, and the rest is timer plumbing.
 */
export function pollPeriodMs(
  activeMs: number,
  idleMs: number,
  state: { idleWhenUnfocused: boolean; hasFocus: boolean },
): number {
  if (!state.idleWhenUnfocused) return activeMs;
  return state.hasFocus ? activeMs : idleMs;
}

export function useFocusAwareInterval(
  callback: () => void,
  activeMs: number,
  options?: { enabled?: boolean; idleMs?: number },
) {
  const enabled = options?.enabled ?? true;
  // 15s: slow enough to be negligible next to a game, frequent enough that a
  // glance at the window is never badly out of date.
  const idleMs = options?.idleMs ?? 15_000;
  const idleWhenUnfocused = useSettingsStore(
    (s) => s.settings.idle_when_unfocused,
  );

  // Kept in a ref so changing the callback identity each render does not
  // restart the timer, which would starve any interval longer than a render.
  const savedCallback = useRef(callback);
  savedCallback.current = callback;

  useEffect(() => {
    if (!enabled) return;

    let timer: number | undefined;
    let cancelled = false;

    const period = () =>
      pollPeriodMs(activeMs, idleMs, {
        idleWhenUnfocused,
        hasFocus: document.hasFocus(),
      });

    const schedule = () => {
      if (cancelled) return;
      timer = window.setTimeout(() => {
        savedCallback.current();
        schedule();
      }, period());
    };

    const onFocus = () => {
      if (cancelled) return;
      // Catch up immediately rather than waiting out the idle period that was
      // already in flight.
      savedCallback.current();
      if (timer !== undefined) window.clearTimeout(timer);
      schedule();
    };

    schedule();
    window.addEventListener("focus", onFocus);

    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
      window.removeEventListener("focus", onFocus);
    };
  }, [enabled, activeMs, idleMs, idleWhenUnfocused]);
}
