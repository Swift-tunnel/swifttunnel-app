import { create } from "zustand";
import type { PerformanceMetricsEvent } from "../lib/types";
import {
  boostGetMetrics,
  boostToggle,
  boostGetSystemInfo,
  boostUpdateConfig,
  boostRestartRoblox,
} from "../lib/commands";
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

  // State
  isActive: boolean;
  isToggling: boolean;
  error: string | null;

  // System info
  isAdmin: boolean;
  osVersion: string;
  cpuCount: number;

  // Actions
  fetchMetrics: () => Promise<void>;
  toggle: (enable: boolean) => Promise<void>;
  fetchSystemInfo: () => Promise<void>;
  updateConfig: (configJson: string) => Promise<void>;
  restartRoblox: () => Promise<void>;
  syncActiveFromSettings: (isActive: boolean) => void;
  clearError: () => void;
  handleMetricsEvent: (event: PerformanceMetricsEvent) => void;
}

export const useBoostStore = create<BoostStore>((set) => ({
  fps: 0,
  cpuUsage: 0,
  ramUsage: 0,
  ramTotal: 0,
  ping: 0,
  robloxRunning: false,
  processId: null,
  isActive: false,
  isToggling: false,
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
    } catch {
      // Silently ignore
    }
  },

  toggle: async (enable) => {
    try {
      set({ isToggling: true, error: null });
      await boostToggle(enable);
      set({ isActive: enable, isToggling: false });
    } catch (e) {
      const message = String(e);
      set({ isToggling: false, error: message });
      await notify("Boost failed", "Could not apply optimization changes.");
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
    } catch {
      // Silently ignore
    }
  },

  updateConfig: async (configJson) => {
    try {
      set({ error: null });
      await boostUpdateConfig(configJson);
    } catch (e) {
      const message = String(e);
      set({ error: message });
      await notify("Boost config failed", "Could not save optimization profile.");
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

  syncActiveFromSettings: (isActive) => {
    set({ isActive });
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
}));
