import { create } from "zustand";
import type { ServerRegion, ServerInfo } from "../lib/types";
import {
  serverGetList,
  serverGetLatencies,
  serverRefresh,
  serverSmartSelect,
} from "../lib/commands";
import { formatErrorMessage, reportError } from "../lib/errors";

// A scan probes every relay and can wait behind connection setup. Timer ticks,
// focus changes and refresh clicks must share it instead of queuing more scans.
let pendingLatencies: Promise<void> | null = null;

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

export const useServerStore = create<ServerStore>((set, get) => {
  let pendingList: Promise<void> | null = null;
  let pendingRefresh: Promise<void> | null = null;
  let listRevision = 0;
  let fleetRevision = 0;
  let fleetSignature = "";

  function loadList(): Promise<void> {
    if (pendingList) return pendingList;
    const revision = ++listRevision;
    set({ isLoading: true });
    const work = (async () => {
      try {
        const resp = await serverGetList();
        if (revision !== listRevision) return;
        const signature = JSON.stringify([
          resp.servers.map(s => [s.region, s.ip, s.port, s.relay_port, s.relay_available]),
          resp.regions.map(r => [r.id, r.servers]),
        ]);
        if (signature !== fleetSignature) {
          fleetSignature = signature;
          ++fleetRevision;
          set({ latencies: new Map() });
        }
        set({ regions: resp.regions, servers: resp.servers, source: resp.source,
          isLoading: false, hasLoaded: true, error: null });
      } catch (error) {
        if (revision !== listRevision) return;
        // Failure still completes startup, but retains the last usable list.
        set({ isLoading: false, hasLoaded: true, error: formatErrorMessage(error) });
      }
    })().finally(() => { if (pendingList === work) pendingList = null; });
    pendingList = work;
    return work;
  }

  return {
  regions: [],
  servers: [],
  latencies: new Map(),
  source: "",
  isLoading: false,
  hasLoaded: false,
  error: null,

  fetchList: () => pendingRefresh ?? loadList(),

  fetchLatencies: () => {
    if (pendingLatencies) return pendingLatencies;
    const revision = fleetRevision;
    pendingLatencies = (async () => {
      try {
        const entries = await serverGetLatencies();
        if (revision !== fleetRevision) return;
        const latencies = new Map<string, number | null>();
        for (const entry of entries) {
          latencies.set(entry.server_id ? `relay:${entry.server_id}` : entry.region, entry.latency_ms);
        }
        set({ latencies });
      } catch (error) {
        reportError("Failed to fetch server latencies", error, {
          dedupeKey: "server-fetch-latencies",
        });
      }
    })().finally(() => { pendingLatencies = null; });
    return pendingLatencies;
  },

  refresh: () => {
    if (pendingRefresh) return pendingRefresh;
    // Old cached reads must not overwrite the fresh result or clear its spinner.
    ++listRevision;
    pendingList = null;
    set({ isLoading: true, error: null });
    pendingRefresh = (async () => {
      try {
        await serverRefresh();
        await loadList();
      } catch (error) {
        set({ isLoading: false, hasLoaded: true, error: formatErrorMessage(error) });
      }
    })().finally(() => { pendingRefresh = null; });
    return pendingRefresh;
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
