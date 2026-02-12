import { create } from "zustand";
import type { ServerRegion, ServerInfo } from "../lib/types";
import {
  serverGetList,
  serverGetLatencies,
  serverRefresh,
  serverSmartSelect,
} from "../lib/commands";

interface ServerStore {
  regions: ServerRegion[];
  servers: ServerInfo[];
  latencies: Map<string, number | null>;
  source: string;
  isLoading: boolean;
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
        error: null,
      });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
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
    } catch {
      // Silently ignore
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
