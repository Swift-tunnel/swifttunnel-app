import { create } from "zustand";
import type { ServerRegion, ServerInfo, ReferenceEstimate } from "../lib/types";
import {
  serverGetList,
  serverGetLatencies,
  serverRefresh,
  serverSmartSelect,
} from "../lib/commands";
import { formatErrorMessage, reportError } from "../lib/errors";
import { regionPresentation, serverPresentation } from "../lib/connectedServer";

// A scan probes every relay. Timer ticks,
// focus changes and refresh clicks must share it instead of queuing more scans.
let pendingLatencies: Promise<void> | null = null;
let pendingCachedOnly = false;

interface ServerStore {
  regions: ServerRegion[];
  servers: ServerInfo[];
  latencies: Map<string, number | null>;
  previews: ReferenceEstimate[];
  source: string;
  isLoading: boolean;
  /** True once the first list fetch has resolved (success OR failure). The
   *  launch loading screen waits on this so regions are on-screen before the
   *  UI reveals, instead of popping in a beat later. */
  hasLoaded: boolean;
  error: string | null;

  // Actions
  fetchList: () => Promise<void>;
  fetchLatencies: (cachedOnly?: boolean) => Promise<void>;
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
  let previewExpiry: ReturnType<typeof setTimeout> | undefined;
  function setPreviews(previews: ReferenceEstimate[]) {
    clearTimeout(previewExpiry);
    const fresh = previews.filter(row => row.expiresAt > performance.now());
    set({ previews: fresh });
    if (fresh.length) previewExpiry = setTimeout(() => setPreviews(get().previews),
      Math.max(1, Math.min(...fresh.map(row => row.expiresAt)) - performance.now()));
  }

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
          const previous = get();
          const unchanged = new Set(resp.servers.filter(server => server.relay_available && previous.servers.some(old =>
            old.region === server.region && old.ip === server.ip &&
            (old.relay_port ?? 51821) === (server.relay_port ?? 51821),
          )).map(server => server.region));
          // Fleet refreshes can land while game-time probing is paused. Keep
          // display readings for unchanged endpoints; Auto's native freshness
          // checks still decide whether a reading may select a route.
          const latencies = new Map([...previous.latencies].filter(([key]) =>
            key.startsWith("relay:") && unchanged.has(key.slice(6)),
          ));
          for (const region of resp.regions) {
            const known = region.servers.flatMap(id => {
              const ms = latencies.get(`relay:${id}`);
              return typeof ms === "number" ? [ms] : [];
            });
            const old = previous.regions.find(old => old.id === region.id);
            const sameMembers = old && old.servers.length === region.servers.length &&
              region.servers.every(id => unchanged.has(id) && old.servers.includes(id));
            const ms = known.length ? Math.min(...known) : sameMembers ? previous.latencies.get(region.id) : null;
            if (ms != null) latencies.set(region.id, ms);
          }
          set({ latencies });
          setPreviews([]);
        }
        set({ regions: resp.regions.map(regionPresentation), servers: resp.servers.map(serverPresentation), source: resp.source,
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
  previews: [],
  source: "",
  isLoading: false,
  hasLoaded: false,
  error: null,

  fetchList: () => pendingRefresh ?? loadList(),

  fetchLatencies: (cachedOnly = false) => {
    if (pendingLatencies) {
      if (!cachedOnly && pendingCachedOnly) {
        // Closing Roblox may request a fresh round while a cached-only read
        // is pending. Queue exactly one probe round after that read.
        pendingCachedOnly = false;
        const cached = pendingLatencies;
        const queued: Promise<void> = cached.then(() => {
          if (pendingLatencies === queued) pendingLatencies = null;
          return get().fetchLatencies();
        });
        pendingLatencies = queued;
      }
      return pendingLatencies;
    }
    pendingCachedOnly = cachedOnly;
    const revision = fleetRevision;
    const work = (async () => {
      try {
        const started = performance.now();
        const entries = await serverGetLatencies(cachedOnly);
        if (revision !== fleetRevision) return;
        const latencies = new Map<string, number | null>();
        for (const entry of entries) {
          latencies.set(entry.server_id ? `relay:${entry.server_id}` : entry.region, entry.latency_ms);
        }
        set({ latencies });
        if (!cachedOnly) setPreviews(entries.flatMap(entry => entry.preview ? [{ ...entry.preview,
          expiresAt: started + Math.min(45_000, entry.preview.valid_for_ms) }] : []));
      } catch (error) {
        if (!cachedOnly && revision === fleetRevision) setPreviews([]);
        reportError("Failed to fetch server latencies", error, {
          dedupeKey: "server-fetch-latencies",
        });
      }
    })().finally(() => { if (pendingLatencies === work) pendingLatencies = null; });
    pendingLatencies = work;
    return work;
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
