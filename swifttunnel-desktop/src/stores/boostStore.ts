import { create } from "zustand";
import type {
  PerformanceMetricsEvent,
  RamCleanProgressEvent,
  RamCleanResultResponse,
  SystemMemorySnapshot,
  Config,
} from "../lib/types";
import {
  boostGetMetrics,
  boostGetSystemMemory,
  boostCleanRam,
  boostGetSystemInfo,
  boostUpdateConfig,
  boostSyncEffectiveConfig,
  boostRestartRoblox,
} from "../lib/commands";
import { reportError } from "../lib/errors";
import { notify } from "../lib/notifications";

interface BoostStore {
  // Metrics
  fps: number;
  cpuUsage: number;
  ramUsage: number;
  ramTotal: number;
  ping: number;
  robloxRunning: boolean;
  processId: number | null;

  // System memory (RAM cleaner)
  systemMem: SystemMemorySnapshot | null;
  isCleaningRam: boolean;
  ramCleanStage: string | null;
  ramCleanTrimmedCount: number;
  ramCleanCurrentProcess: string | null;
  ramCleanResult: RamCleanResultResponse | null;
  ramCleanStartSnapshot: SystemMemorySnapshot | null;
  ramCleanDoneSnapshot: SystemMemorySnapshot | null;

  error: string | null;

  // System info
  isAdmin: boolean;
  osVersion: string;
  cpuCount: number;

  // Actions
  fetchMetrics: () => Promise<void>;
  fetchSystemMemory: () => Promise<void>;
  fetchSystemInfo: () => Promise<void>;
  updateConfig: (configJson: string) => Promise<Config>;
  syncEffectiveConfig: () => Promise<Config | null>;
  restartRoblox: () => Promise<void>;
  cleanRam: () => Promise<void>;
  clearError: () => void;
  handleMetricsEvent: (event: PerformanceMetricsEvent) => void;
  handleRamCleanProgress: (event: RamCleanProgressEvent) => void;
}

export const useBoostStore = create<BoostStore>((set) => ({
  fps: 0,
  cpuUsage: 0,
  ramUsage: 0,
  ramTotal: 0,
  ping: 0,
  robloxRunning: false,
  processId: null,
  systemMem: null,
  isCleaningRam: false,
  ramCleanStage: null,
  ramCleanTrimmedCount: 0,
  ramCleanCurrentProcess: null,
  ramCleanResult: null,
  ramCleanStartSnapshot: null,
  ramCleanDoneSnapshot: null,
  error: null,
  isAdmin: false,
  osVersion: "",
  cpuCount: 1,

  fetchMetrics: async () => {
    try {
      const m = await boostGetMetrics();
      set({
        fps: m.fps,
        cpuUsage: m.cpu_usage,
        ramUsage: m.ram_usage,
        ramTotal: m.ram_total,
        ping: m.ping,
        robloxRunning: m.roblox_running,
        processId: m.process_id,
      });
    } catch (error) {
      reportError("Failed to fetch performance metrics", error, {
        dedupeKey: "boost-fetch-metrics",
      });
    }
  },

  fetchSystemMemory: async () => {
    try {
      const mem = await boostGetSystemMemory();
      set({ systemMem: mem });
    } catch (error) {
      reportError("Failed to fetch system memory", error, {
        dedupeKey: "boost-fetch-system-memory",
      });
    }
  },

  fetchSystemInfo: async () => {
    try {
      const info = await boostGetSystemInfo();
      set({
        isAdmin: info.is_admin,
        osVersion: info.os_version,
        cpuCount: info.cpu_count,
      });
    } catch (error) {
      reportError("Failed to fetch system info", error, {
        dedupeKey: "boost-fetch-system-info",
      });
    }
  },

  updateConfig: async (configJson) => {
    try {
      set({ error: null });
      const result = await boostUpdateConfig(configJson);
      if (result.warnings.length > 0) {
        const message = result.warnings.join("; ");
        set({ error: message });
        await notify(
          "Boost applied with warnings",
          "Some optimizations could not be applied.",
        );
      }
      return result.applied_config ?? JSON.parse(configJson);
    } catch (e) {
      const message = String(e);
      set({ error: message });
      await notify("Boost config failed", "Could not save optimization profile.");
      throw e;
    }
  },

  syncEffectiveConfig: async () => {
    try {
      set({ error: null });
      const result = await boostSyncEffectiveConfig();
      if (result.warnings.length > 0) {
        set({ error: result.warnings.join("; ") });
      }
      return result.applied_config;
    } catch (error) {
      reportError("Failed to sync boost config state", error, {
        dedupeKey: "boost-sync-effective-config",
      });
      return null;
    }
  },

  cleanRam: async () => {
    try {
      set({
        error: null,
        isCleaningRam: true,
        ramCleanStage: "start",
        ramCleanTrimmedCount: 0,
        ramCleanCurrentProcess: null,
        ramCleanResult: null,
        ramCleanStartSnapshot: null,
        ramCleanDoneSnapshot: null,
      });

      // Refresh a baseline snapshot immediately on click. Polling can be stale by up to 1s,
      // which makes the UI look like the cleaner freed memory before it actually ran.
      const baseline = await boostGetSystemMemory().catch(() => null);
      if (baseline) {
        set({ systemMem: baseline, ramCleanStartSnapshot: baseline });
      }

      const result = await boostCleanRam();
      set((state) => ({
        isCleaningRam: false,
        ramCleanStage: "done",
        ramCleanResult: result,
        systemMem: result.after,
        ramCleanTrimmedCount: result.trimmed_count,
        ramCleanCurrentProcess: null,
        ramCleanDoneSnapshot: state.ramCleanDoneSnapshot ?? result.after,
      }));
    } catch (e) {
      const message = String(e);
      set({
        error: message,
        isCleaningRam: false,
        ramCleanStage: null,
        ramCleanStartSnapshot: null,
        ramCleanDoneSnapshot: null,
      });
      await notify("RAM cleaner failed", "Could not clean memory.");
    }
  },

  restartRoblox: async () => {
    try {
      await boostRestartRoblox();
    } catch (e) {
      const message = String(e);
      set({ error: message });
      await notify("Restart failed", "Could not restart Roblox.");
    }
  },

  clearError: () => {
    set({ error: null });
  },

  handleMetricsEvent: (event) => {
    set({
      fps: event.fps,
      cpuUsage: event.cpu_usage,
      ramUsage: event.ram_usage,
      ramTotal: event.ram_total,
      robloxRunning: event.roblox_running,
    });
  },

  handleRamCleanProgress: (event) => {
    set((state) => ({
      systemMem: {
        total_mb: event.total_mb,
        used_mb: event.used_mb,
        available_mb: event.available_mb,
        load_pct: event.load_pct,
        standby_mb: event.standby_mb,
        modified_mb: event.modified_mb,
      },
      ramCleanStage: event.stage,
      ramCleanTrimmedCount: event.trimmed_count,
      ramCleanCurrentProcess: event.current_process,
      ramCleanStartSnapshot:
        event.stage === "start" && !state.ramCleanStartSnapshot
          ? {
              total_mb: event.total_mb,
              used_mb: event.used_mb,
              available_mb: event.available_mb,
              load_pct: event.load_pct,
              standby_mb: event.standby_mb,
              modified_mb: event.modified_mb,
            }
          : state.ramCleanStartSnapshot,
      ramCleanDoneSnapshot:
        event.stage === "done"
          ? {
              total_mb: event.total_mb,
              used_mb: event.used_mb,
              available_mb: event.available_mb,
              load_pct: event.load_pct,
              standby_mb: event.standby_mb,
              modified_mb: event.modified_mb,
            }
          : state.ramCleanDoneSnapshot,
    }));
  },
}));
