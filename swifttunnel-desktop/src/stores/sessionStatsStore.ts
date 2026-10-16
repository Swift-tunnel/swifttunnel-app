import { create } from "zustand";

import { useVpnStore } from "./vpnStore";
import { useBoostStore } from "./boostStore";

/**
 * Ping statistics for the tunnel session in progress, and for the one before
 * it once that ends, for the Connect tab's session card.
 *
 * Built from the same ping readings the rest of the UI takes (the Connect tab
 * and the in-game overlay), counted only while Roblox is running. Idle relay
 * checks still keep the connection healthy but do not affect game statistics.
 */
export interface SessionStats {
  region: string | null;
  startedAt: number;
  endedAt: number | null;
  samples: number;
  lowest: number | null;
  total: number;
  /** Sum of the change between consecutive samples, for mean jitter. */
  swing: number;
  jitterSamples: number;
  previous: number | null;
}

interface SessionStatsState {
  current: SessionStats | null;
  last: SessionStats | null;
  begin: (region: string | null, startedAt: number) => void;
  record: (pingMs: number) => void;
  pause: () => void;
  finish: (endedAt: number) => void;
}

export const useSessionStatsStore = create<SessionStatsState>((set, get) => ({
  current: null,
  last: null,
  begin: (region, startedAt) =>
    set({
      current: {
        region,
        startedAt,
        endedAt: null,
        samples: 0,
        lowest: null,
        total: 0,
        swing: 0,
        jitterSamples: 0,
        previous: null,
      },
    }),
  record: (pingMs) => {
    const cur = get().current;
    if (!cur || !useBoostStore.getState().robloxRunning) return;
    set({
      current: {
        ...cur,
        samples: cur.samples + 1,
        lowest: cur.lowest === null ? pingMs : Math.min(cur.lowest, pingMs),
        total: cur.total + pingMs,
        swing: cur.previous === null ? cur.swing : cur.swing + Math.abs(pingMs - cur.previous),
        jitterSamples: cur.jitterSamples + (cur.previous === null ? 0 : 1),
        previous: pingMs,
      },
    });
  },
  pause: () => {
    const cur = get().current;
    // The first reading after a pause is not consecutive with the previous
    // game's last reading and must not create an artificial jitter spike.
    if (cur && cur.previous !== null) set({ current: { ...cur, previous: null } });
  },
  finish: (endedAt) => {
    const cur = get().current;
    if (!cur) return;
    set({ current: null, last: { ...cur, endedAt } });
  },
}));

export function averagePing(stats: SessionStats): number | null {
  return stats.samples > 0 ? Math.round(stats.total / stats.samples) : null;
}

/** Mean change between consecutive readings, the usual meaning of jitter. */
export function jitter(stats: SessionStats): number | null {
  return stats.jitterSamples > 0 ? Math.round(stats.swing / stats.jitterSamples) : null;
}

/**
 * Follow the tunnel: a session starts when it connects, game-time readings
 * are counted, and the session closes when the tunnel drops. Returns the
 * unsubscribe function.
 */
export function trackTunnelSessions(): () => void {
  const initial = useVpnStore.getState();
  if (initial.state === "connected" && initial.connectedAt !== null) {
    useSessionStatsStore.getState().begin(initial.region, initial.connectedAt);
  }
  const stopMetrics = useBoostStore.subscribe((s, prev) => {
    if (prev.robloxRunning && !s.robloxRunning) useSessionStatsStore.getState().pause();
  });
  const stopVpn = useVpnStore.subscribe((s, prev) => {
    const stats = useSessionStatsStore.getState();
    const on = s.state === "connected" && s.connectedAt !== null;
    const wasOn = prev.state === "connected" && prev.connectedAt !== null;
    if (on && (!wasOn || s.connectedAt !== prev.connectedAt)) {
      stats.begin(s.region, s.connectedAt as number);
    }
    if (!on && wasOn) stats.finish(Date.now());
    if (on && s.ping !== null && s.pingReadings !== prev.pingReadings) {
      useSessionStatsStore.getState().record(s.ping);
    }
  });
  return () => { stopMetrics(); stopVpn(); };
}
