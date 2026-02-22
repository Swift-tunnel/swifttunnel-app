import { create } from "zustand";
import type { AppSettings, TabId } from "../lib/types";
import { settingsLoad, settingsSave } from "../lib/commands";

const DEFAULT_SETTINGS: AppSettings = {
  theme: "dark",
  config: {
    profile: "Balanced",
    system_optimization: {
      set_high_priority: true,
      set_cpu_affinity: false,
      cpu_cores: [],
      disable_fullscreen_optimization: true,
      clear_standby_memory: true,
      disable_game_bar: true,
      power_plan: "HighPerformance",
      timer_resolution_1ms: true,
      mmcss_gaming_profile: true,
      game_mode_enabled: true,
    },
    roblox_settings: {
      graphics_quality: "Manual",
      unlock_fps: true,
      target_fps: 144,
      window_width: 1280,
      window_height: 720,
      window_fullscreen: false,
      ultraboost: false,
    },
    network_settings: {
      enable_network_boost: true,
      prioritize_roblox_traffic: true,
      disable_nagle: true,
      disable_network_throttling: true,
      optimize_mtu: false,
      gaming_qos: true,
    },
    auto_start_with_roblox: false,
    show_overlay: true,
  },
  window_state: { x: null, y: null, width: 560, height: 750, maximized: false },
  selected_region: "singapore",
  selected_server: "singapore",
  current_tab: "connect",
  update_settings: { auto_check: true, last_check: null },
  update_channel: "Stable",
  minimize_to_tray: false,
  run_on_startup: true,
  auto_reconnect: true,
  resume_vpn_on_startup: false,
  last_connected_region: null,
  expanded_boost_info: [],
  selected_game_presets: ["roblox"],
  forced_servers: {},
  artificial_latency_ms: 0,
  experimental_mode: false,
  custom_relay_server: "",
  enable_discord_rpc: true,
  auto_routing_enabled: false,
  whitelisted_regions: [],
  preferred_physical_adapter_guid: null,
  adapter_binding_mode: "smart_auto",
};

interface SettingsStore {
  settings: AppSettings;
  activeTab: TabId;
  isLoaded: boolean;

  // Actions
  load: () => Promise<void>;
  save: () => Promise<void>;
  update: (partial: Partial<AppSettings>) => void;
  setTab: (tab: TabId) => void;
}

export const useSettingsStore = create<SettingsStore>((set, get) => ({
  settings: DEFAULT_SETTINGS,
  activeTab: "connect",
  isLoaded: false,

  load: async () => {
    try {
      const resp = await settingsLoad();
      const raw = JSON.parse(resp.json) as Partial<AppSettings>;
      const settings: AppSettings = {
        ...DEFAULT_SETTINGS,
        ...raw,
      };
      set({
        settings,
        activeTab: (settings.current_tab as TabId) || "connect",
        isLoaded: true,
      });
    } catch {
      set({ isLoaded: true });
    }
  },

  save: async () => {
    try {
      const { settings, activeTab } = get();
      const toSave = { ...settings, current_tab: activeTab };
      await settingsSave(JSON.stringify(toSave));
    } catch {
      // Silently ignore save errors
    }
  },

  update: (partial) => {
    set((state) => ({
      settings: { ...state.settings, ...partial },
    }));
    // Debounced save handled by the component layer
  },

  setTab: (tab) => {
    set({ activeTab: tab });
    // Persist tab selection
    const { settings } = get();
    set({ settings: { ...settings, current_tab: tab } });
  },
}));
