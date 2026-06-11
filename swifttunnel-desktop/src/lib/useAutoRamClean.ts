import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import { boostCleanRam } from "./commands";
import { showRamOverlay } from "../components/overlay/RamOverlay";

const ROBLOX_GAME_JOINED = "roblox-game-joined";
const STARTUP_GRACE_MS = 6000;
const DEBOUNCE_MS = 20000;

/**
 * When "Auto RAM Clean" is enabled, clean RAM each time Roblox *joins a game*
 * and show the in-game overlay.
 *
 * Guards against false fires: the log watcher re-reads the recent join line when
 * Roblox's log rotates on exit, so before cleaning we confirm Roblox is the
 * FOREGROUND window. (Its process can linger a second or two while closing, so
 * "running" isn't enough - but the window is gone the instant you close it.)
 */
export function useAutoRamClean() {
  const autoClean = useSettingsStore(
    (s) => s.settings.config.system_optimization.auto_ram_clean,
  );
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const autoCleanRef = useRef(autoClean);
  autoCleanRef.current = autoClean;

  useEffect(() => {
    const mountedAt = Date.now();
    let lastClean = 0;
    let busy = false;
    let disposed = false;
    let unlisten: (() => void) | undefined;

    void listen(ROBLOX_GAME_JOINED, async () => {
      if (disposed || !autoCleanRef.current || busy) return;
      const now = Date.now();
      if (now - mountedAt < STARTUP_GRACE_MS) return;
      if (now - lastClean < DEBOUNCE_MS) return;

      busy = true;
      try {
        // Confirm Roblox is actually in front (not a rotate-on-exit re-read,
        // which fires when its window has already closed).
        await fetchMetrics();
        if (disposed || !useBoostStore.getState().robloxForeground) return;
        lastClean = now;
        const result = await boostCleanRam();
        if (!disposed) await showRamOverlay(result.freed_mb);
      } catch {
        // best-effort; never surface an error in-game
      } finally {
        busy = false;
      }
    }).then((u) => {
      if (disposed) u();
      else unlisten = u;
    });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [fetchMetrics]);
}
