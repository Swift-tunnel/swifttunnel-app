import { useEffect } from "react";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import { boostCleanRam } from "./commands";
import { showRamOverlay } from "../components/overlay/RamOverlay";

const POLL_MS = 2500;

/**
 * When "Auto RAM Clean" is enabled, clean RAM once each time a game *launches*
 * (the Roblox process goes from not-running to running while the app is up) and
 * surface the result in the always-on-top overlay window.
 *
 * Self-contained polling, deliberately NOT driven by the reactive `robloxRunning`
 * store value, because:
 *  - That value only updates while a tab is polling metrics; the user is in-game
 *    with the window minimized, so we must poll ourselves (the webview keeps
 *    running timers even minimized to tray).
 *  - The FIRST poll establishes the baseline and never triggers. This is what
 *    fixes "it cleaned the moment the app launched": if Roblox was already
 *    running at startup that's the baseline, not a fresh launch. Only a later
 *    not-running -> running edge counts.
 */
export function useAutoRamClean() {
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const autoClean = useSettingsStore(
    (s) => s.settings.config.system_optimization.auto_ram_clean,
  );

  useEffect(() => {
    if (!autoClean) return;

    let disposed = false;
    let prev: boolean | null = null; // null = baseline not yet established
    let busy = false;

    const tick = async () => {
      if (disposed) return;
      try {
        await fetchMetrics();
        const running = useBoostStore.getState().robloxRunning;
        if (prev === null) {
          prev = running; // first real read = baseline, never triggers
          return;
        }
        if (!prev && running && !busy) {
          busy = true;
          try {
            const result = await boostCleanRam();
            if (!disposed) await showRamOverlay(result.freed_mb);
          } finally {
            busy = false;
          }
        }
        prev = running;
      } catch {
        // Auto-clean is best-effort; never surface an error in-game.
      }
    };

    void tick();
    const id = window.setInterval(() => void tick(), POLL_MS);
    return () => {
      disposed = true;
      window.clearInterval(id);
    };
  }, [autoClean, fetchMetrics]);
}
