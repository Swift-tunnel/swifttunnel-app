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
  error: string | null;

  // Actions
  fetchList: () => Promise<void>;
  fetchLatencies: () => Promise<void>;
  refresh: () => Promise<void>;
  smartSelect: (regionId: string) => Promise<string | null>;
  getLatency: (region: string) => number | null;
}

export const useServerStore = create<ServerStore>((set, get) => {
  let listRunSeq = 0;
  let refreshRunSeq = 0;
  let latencyRunSeq = 0;

  return {
    regions: [],
    servers: [],
    latencies: new Map(),
    source: "",
    isLoading: false,
    error: null,

    fetchList: async () => {
      const runId = ++listRunSeq;
      try {
        set({ isLoading: true });
        const resp = await serverGetList();
        if (runId === listRunSeq) {
          set({
            regions: resp.regions,
            servers: resp.servers,
            source: resp.source,
            isLoading: false,
            error: null,
          });
        }
      } catch (e) {
        if (runId === listRunSeq) {
          set({ isLoading: false, error: String(e) });
        }
      }
    },

    fetchLatencies: async () => {
      const runId = ++latencyRunSeq;
      try {
        const entries = await serverGetLatencies();
        const latencies = new Map<string, number | null>();
        for (const entry of entries) {
          latencies.set(entry.region, entry.latency_ms);
        }
        if (runId === latencyRunSeq) {
          set({ latencies });
        }
      } catch (error) {
        if (runId === latencyRunSeq) {
          reportError("Failed to fetch server latencies", error, {
            dedupeKey: "server-fetch-latencies",
          });
        }
      }
    },

    refresh: async () => {
      const runId = ++refreshRunSeq;
      listRunSeq++;
      try {
        set({ isLoading: true });
        await serverRefresh();
        if (runId !== refreshRunSeq) {
          // This superseded refresh may resolve while the newer refresh still owns loading.
          return;
        }

        await get().fetchList();
      } catch (e) {
        if (runId === refreshRunSeq) {
          set({ isLoading: false, error: String(e) });
        }
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
  };
});
