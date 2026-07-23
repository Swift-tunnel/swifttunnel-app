import { create } from "zustand";
import type { ServerRegion, ServerInfo } from "../lib/types";
import {
  serverGetList,
  serverGetLatencies,
  serverRefresh,
  serverSmartSelect,
} from "../lib/commands";
import { reportError } from "../lib/errors";

interface ServerStore {
  regions: ServerRegion[];
  servers: ServerInfo[];
  latencies: Map<string, number | null>;
  source: string;
  isLoading: boolean;
  /** True once the first list fetch has resolved (success OR failure). The
   *  launch loading screen waits on this so regions are on-screen before the
   *  UI reveals, instead of popping in a beat later. */
  hasLoaded: boolean;
  error: string | null;

  // Actions
  fetchList: () => Promise<void>;
  fetchLatencies: () => Promise<void>;
  refresh: () => Promise<void>;
  smartSelect: (regionId: string) => Promise<string | null>;
  getLatency: (region: string) => number | null;
}

export const useServerStore = create<ServerStore>((set, get) => ({
  regions: [],
  servers: [],
  latencies: new Map(),
  source: "",
  isLoading: false,
  hasLoaded: false,
  error: null,

  fetchList: async () => {
    try {
      set({ isLoading: true });
      const resp = await serverGetList();
      set({
        regions: resp.regions,
        servers: resp.servers,
        source: resp.source,
        isLoading: false,
        hasLoaded: true,
        error: null,
      });
    } catch (e) {
      // Even a failed fetch counts as "loaded" so the launch screen can't hang
      // waiting on an unreachable backend.
      set({ isLoading: false, hasLoaded: true, error: String(e) });
    }
  },

  fetchLatencies: async () => {
    try {
      const entries = await serverGetLatencies();
      const latencies = new Map<string, number | null>();
      for (const entry of entries) {
        latencies.set(entry.region, entry.latency_ms);
      }
      set({ latencies });
    } catch (error) {
      reportError("Failed to fetch server latencies", error, {
        dedupeKey: "server-fetch-latencies",
      });
    }
  },

  refresh: async () => {
    try {
      set({ isLoading: true });
      await serverRefresh();
      await get().fetchList();
    } catch (e) {
      set({ isLoading: false, error: String(e) });
    }
  },

  smartSelect: async (regionId) => {
    try {
      return await serverSmartSelect(regionId);
    } catch {
      return null;
    }
  },

  getLatency: (region) => {
    return get().latencies.get(region) ?? null;
  },
}));
