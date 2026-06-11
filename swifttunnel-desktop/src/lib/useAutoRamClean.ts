import { useEffect, useRef } from "react";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import { boostCleanRam } from "./commands";
import { showRamOverlay } from "../components/overlay/RamOverlay";

/**
 * When "Auto RAM Clean" is enabled, clean RAM once each time a game launches
 * (robloxRunning false -> true) and surface the result in the always-on-top
 * overlay window.
 *
 * `robloxRunning` only updates while something polls metrics (BoostTab/GamesTab)
 * - which it isn't when the user is in-game with the window minimized. So while
 * the feature is enabled we poll metrics ourselves; the webview keeps running
 * timers even minimized to tray, so the false->true edge is caught in-game.
 */
export function useAutoRamClean() {
  const robloxRunning = useBoostStore((s) => s.robloxRunning);
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const autoClean = useSettingsStore(
    (s) => s.settings.config.system_optimization.auto_ram_clean,
  );
  // `undefined` until the first observation so we never auto-clean on app
  // startup just because a game was already running.
  const prev = useRef<boolean | undefined>(undefined);
  const busy = useRef(false);

  // Keep robloxRunning fresh in the background while the feature is on.
  useEffect(() => {
    if (!autoClean) return;
    void fetchMetrics();
    const id = window.setInterval(() => void fetchMetrics(), 2500);
    return () => window.clearInterval(id);
  }, [autoClean, fetchMetrics]);

  useEffect(() => {
    const was = prev.current;
    prev.current = robloxRunning;
    if (was === undefined) return; // baseline only
    if (!autoClean) return;
    if (was || !robloxRunning) return; // only on false -> true
    if (busy.current) return;

    busy.current = true;
    void (async () => {
      try {
        const result = await boostCleanRam();
        await showRamOverlay(result.freed_mb);
      } catch {
        // Auto-clean is best-effort; never surface an error in-game.
      } finally {
        busy.current = false;
      }
    })();
  }, [robloxRunning, autoClean]);
}
