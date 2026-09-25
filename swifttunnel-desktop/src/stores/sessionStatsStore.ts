import { create } from "zustand";

import { useVpnStore } from "./vpnStore";

/**
 * Ping statistics for the tunnel session in progress, and for the one before
 * it once that ends, for the Connect tab's session card.
 *
 * Built from the same ping readings the rest of the UI takes (the Connect tab
 * and the in-game overlay), so it only sees samples taken while one of those
 * was asking. That is enough for a summary; a count kept by the backend would
 * see every relay reply.
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
  previous: number | null;
}

interface SessionStatsState {
  current: SessionStats | null;
  last: SessionStats | null;
  begin: (region: string | null, startedAt: number) => void;
  record: (pingMs: number) => void;
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
        previous: null,
      },
    }),
  record: (pingMs) => {
    const cur = get().current;
    if (!cur) return;
    set({
      current: {
        ...cur,
        samples: cur.samples + 1,
        lowest: cur.lowest === null ? pingMs : Math.min(cur.lowest, pingMs),
        total: cur.total + pingMs,
        swing: cur.previous === null ? cur.swing : cur.swing + Math.abs(pingMs - cur.previous),
        previous: pingMs,
      },
    });
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
  return stats.samples > 1 ? Math.round(stats.swing / (stats.samples - 1)) : null;
}

/**
 * Follow the tunnel: a session starts when it connects, every ping reading
 * is counted, and the session closes when the tunnel drops. Returns the
 * unsubscribe function.
 */
export function trackTunnelSessions(): () => void {
  return useVpnStore.subscribe((s, prev) => {
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
}
