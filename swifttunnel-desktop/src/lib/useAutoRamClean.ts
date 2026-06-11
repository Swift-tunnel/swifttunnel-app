import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useSettingsStore } from "../stores/settingsStore";
import { boostCleanRam } from "./commands";
import { showRamOverlay } from "../components/overlay/RamOverlay";

const ROBLOX_GAME_JOINED = "roblox-game-joined";
/** Ignore joins right after launch: the log watcher reads the last 64KB of the
 *  current log on start, which may contain a join from a game already in
 *  progress. We don't want to clean just because the app opened mid-game. */
const STARTUP_GRACE_MS = 6000;
/** One clean per join; absorbs the extra events from server hops / multi-IP
 *  joins so we don't clean repeatedly within a single session. */
const DEBOUNCE_MS = 20000;

/**
 * When "Auto RAM Clean" is enabled, clean RAM each time Roblox *joins a game*
 * (not merely when the process starts) and show the in-game overlay.
 *
 * Driven by the backend `roblox-game-joined` event, which the log watcher emits
 * on the "Joining game ... at <ip>" log line - so it fires when you join a game
 * even if Roblox was already open at the menu.
 */
export function useAutoRamClean() {
  const autoClean = useSettingsStore(
    (s) => s.settings.config.system_optimization.auto_ram_clean,
  );
  // Read the latest setting inside the once-registered listener without
  // re-subscribing on every toggle.
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
      lastClean = now;
      busy = true;
      try {
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
  }, []);
}
