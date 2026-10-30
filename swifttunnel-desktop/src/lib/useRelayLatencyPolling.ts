import { useCallback, useEffect } from "react";

import { useBoostStore } from "../stores/boostStore";
import { useServerStore } from "../stores/serverStore";
import { useFocusAwareInterval } from "./useFocusAwareInterval";

/** Refresh the picker automatically only while Roblox is closed. */
export function useRelayLatencyPolling() {
  const robloxRunning = useBoostStore((s) => s.robloxRunning);
  const hasLoadedMetrics = useBoostStore((s) => s.hasLoadedMetrics);
  const fetchLatencies = useServerStore((s) => s.fetchLatencies);
  const fleetLoaded = useServerStore((s) => s.hasLoaded);
  const enabled = fleetLoaded && hasLoadedMetrics && !robloxRunning;

  const scan = useCallback(() => {
    // A queued focus/timer callback can run before React handles a process
    // change. Read the current state so it cannot start a scan mid-game.
    const state = useBoostStore.getState();
    if (state.hasLoadedMetrics && !state.robloxRunning) void fetchLatencies();
  }, [fetchLatencies]);

  // Mounting the picker and closing Roblox each need one fresh round. Wait
  // for the existing process sampler at startup rather than assuming idle.
  useEffect(() => {
    if (enabled) scan();
    else if (fleetLoaded && hasLoadedMetrics && robloxRunning) void fetchLatencies(true);
  }, [enabled, scan, fleetLoaded, hasLoadedMetrics, robloxRunning, fetchLatencies]);
  useFocusAwareInterval(scan, 15_000, { idleMs: 60_000, enabled });
}
