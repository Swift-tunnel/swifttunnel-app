import { useEffect, useRef, useState } from "react";
import type { StoreApi, UseBoundStore } from "zustand";

import { useSettingsStore } from "../stores/settingsStore";
import { shouldPauseAnimations } from "./animationIdle";

/**
 * Whether the window has focus, kept current from focus/blur events.
 */
export function useWindowFocused(): boolean {
  const [focused, setFocused] = useState(
    () => typeof document === "undefined" || document.hasFocus(),
  );

  useEffect(() => {
    const sync = () => setFocused(document.hasFocus());
    window.addEventListener("focus", sync);
    window.addEventListener("blur", sync);
    document.addEventListener("visibilitychange", sync);
    sync();
    return () => {
      window.removeEventListener("focus", sync);
      window.removeEventListener("blur", sync);
      document.removeEventListener("visibilitychange", sync);
    };
  }, []);

  return focused;
}

/**
 * Whether cosmetic live updates (graphs, ticking clocks) should be drawn now.
 *
 * False while the player is in a game: the window is in the background and
 * `idle_when_unfocused` is on, which it is by default. Every redraw then is
 * GPU and CPU time taken from the game for pixels nobody is looking at.
 * Callers keep collecting their data and draw it when the window comes back.
 *
 * Same rule as the animation pause in `animationIdle.ts`, so turning the
 * setting off (for a graph on a second monitor) keeps everything live.
 */
export function useLiveUpdates(): boolean {
  const idleWhenUnfocused = useSettingsStore(
    (s) => s.settings.idle_when_unfocused,
  );
  const hasFocus = useWindowFocused();
  return !shouldPauseAnimations({ idleWhenUnfocused, hasFocus });
}

/** Returned by a paused selector instead of the store's value. */
export const PAUSED_VALUE: unique symbol = Symbol("paused live value");

/**
 * Wrap a store selector so it reads nothing while live updates are paused.
 *
 * A paused selector returns the same constant for every store write, so the
 * subscribing component is not re-rendered at all. Holding the old value in
 * a ref is not enough on its own: the subscription still re-renders the
 * component on every write, and for something like the Connect tab that is
 * the whole tab and every region row, once a second behind the game.
 */
export function liveSelector<S, T>(
  live: boolean,
  selector: (state: S) => T,
): (state: S) => T | typeof PAUSED_VALUE {
  return live ? selector : () => PAUSED_VALUE;
}

/**
 * A store value that follows the store while live updates are on, and holds
 * its last value without re-rendering while the player is in game.
 *
 * Use it for readouts only (ping, game CPU/RAM/FPS, session statistics).
 * Anything that decides behaviour must read the store directly.
 */
export function useLiveStoreValue<S, T>(
  store: UseBoundStore<StoreApi<S>>,
  selector: (state: S) => T,
): T {
  const live = useLiveUpdates();
  const selected = store(liveSelector(live, selector));
  const shown = useRef<{ value: T } | null>(null);
  if (selected !== PAUSED_VALUE) {
    shown.current = { value: selected as T };
  } else if (shown.current === null) {
    // Mounted while paused: show the current value once.
    shown.current = { value: selector(store.getState()) };
  }
  return shown.current.value;
}
