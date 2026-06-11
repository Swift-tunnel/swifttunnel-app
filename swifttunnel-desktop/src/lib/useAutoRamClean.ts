import { useEffect, useRef } from "react";
import { emit } from "@tauri-apps/api/event";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import { boostCleanRam } from "./commands";
import { RAM_OVERLAY_EVENT } from "../components/overlay/RamOverlay";

/**
 * When "Auto RAM Clean" is enabled, clean RAM once each time a game launches
 * (robloxRunning false -> true) and surface the result in the always-on-top
 * overlay window. Runs in the main window only; the webview keeps processing
 * metric events even when minimized to tray, so it fires while the user is
 * in-game.
 */
export function useAutoRamClean() {
  const robloxRunning = useBoostStore((s) => s.robloxRunning);
  const autoClean = useSettingsStore(
    (s) => s.settings.config.system_optimization.auto_ram_clean,
  );
  // `undefined` until the first observation so we never auto-clean on app
  // startup just because a game was already running.
  const prev = useRef<boolean | undefined>(undefined);
  const busy = useRef(false);

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
        await emit(RAM_OVERLAY_EVENT, { freedMb: result.freed_mb });
      } catch {
        // Auto-clean is best-effort; never surface an error in-game.
      } finally {
        busy.current = false;
      }
    })();
  }, [robloxRunning, autoClean]);
}
