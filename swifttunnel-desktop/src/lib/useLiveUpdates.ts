import { useEffect, useState } from "react";

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
