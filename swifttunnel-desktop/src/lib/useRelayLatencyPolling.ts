import { useCallback, useEffect } from "react";

import { useBoostStore } from "../stores/boostStore";
import { useServerStore } from "../stores/serverStore";
import { useFocusAwareInterval } from "./useFocusAwareInterval";

/** Refresh the picker automatically only while Roblox is closed. */
export function useRelayLatencyPolling() {
  const robloxRunning = useBoostStore((s) => s.robloxRunning);
  const hasLoadedMetrics = useBoostStore((s) => s.hasLoadedMetrics);
  const fetchLatencies = useServerStore((s) => s.fetchLatencies);
  const enabled = hasLoadedMetrics && !robloxRunning;

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
  }, [enabled, scan]);
  useFocusAwareInterval(scan, 15_000, { idleMs: 60_000, enabled });
}
