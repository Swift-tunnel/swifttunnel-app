import { useEffect, useRef, useState } from "react";
import type { StoreApi, UseBoundStore } from "zustand";

import { useSettingsStore } from "../stores/settingsStore";
import { shouldPauseAnimations } from "./animationIdle";
import { isMainWindowHidden, subscribeMainWindowVisibility } from "./mainWindowVisibility";

function readWindowState() {
  return typeof document === "undefined"
    ? { hasFocus: true, hidden: false }
    : { hasFocus: document.hasFocus(), hidden: isMainWindowHidden() };
}

/**
 * Hidden windows pause. The idle setting also pauses visible windows that
 * are out of focus. Turning it off keeps a visible second monitor live.
 */
export function useLiveUpdates(): boolean {
  const idleWhenUnfocused = useSettingsStore(
    (s) => s.settings.idle_when_unfocused,
  );
  const [windowState, setWindowState] = useState(readWindowState);
  useEffect(() => {
    const sync = () => {
      const next = readWindowState();
      setWindowState(previous => (
        previous.hasFocus === next.hasFocus && previous.hidden === next.hidden
          ? previous
          : next
      ));
    };
    window.addEventListener("focus", sync);
    window.addEventListener("blur", sync);
    const stopWatchingVisibility = subscribeMainWindowVisibility(sync);
    sync();
    return () => {
      window.removeEventListener("focus", sync);
      window.removeEventListener("blur", sync);
      stopWatchingVisibility();
    };
  }, []);

  return !shouldPauseAnimations({ idleWhenUnfocused, ...windowState });
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
