import type { AppSettings } from "./types";

export const DEFAULT_SETTINGS: AppSettings = {
  theme: "dark",
  config: {
    profile: "Balanced",
    system_optimization: {
      set_high_priority: false,
      set_cpu_affinity: false,
      cpu_cores: [],
      disable_fullscreen_optimization: false,
      clear_standby_memory: false,
      disable_game_bar: false,
      power_plan: "Balanced",
      timer_resolution_1ms: false,
      mmcss_gaming_profile: false,
      game_mode_enabled: false,
    },
    roblox_settings: {
      graphics_quality: "Automatic",
      unlock_fps: false,
      target_fps: 144,
      window_width: 1280,
      window_height: 720,
      window_fullscreen: false,
      ultraboost: false,
    },
    network_settings: {
      enable_network_boost: false,
      prioritize_roblox_traffic: false,
      disable_nagle: false,
      disable_network_throttling: false,
      gaming_qos: false,
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
  run_on_startup: false,
  auto_reconnect: false,
  resume_vpn_on_startup: false,
  last_connected_region: null,
  expanded_boost_info: [],
  selected_game_presets: ["roblox"],
  network_test_results: {
    last_stability: null,
    last_speed: null,
  },
  forced_servers: {},
  artificial_latency_ms: 0,
  experimental_mode: false,
  custom_relay_server: "",
  enable_discord_rpc: true,
  auto_routing_enabled: false,
  whitelisted_regions: [],
  preferred_physical_adapter_guid: null,
  network_binding_overrides: {},
  adapter_binding_mode: "smart_auto",
  game_process_performance: {
    high_performance_gpu_binding: false,
    prefer_performance_cores: false,
    unbind_cpu0: false,
  },
  enable_api_tunneling: false,
};

export function mergeAppSettings(
  raw: Partial<AppSettings> | undefined,
): AppSettings {
  return {
    ...DEFAULT_SETTINGS,
    ...raw,
    config: {
      ...DEFAULT_SETTINGS.config,
      ...raw?.config,
      system_optimization: {
        ...DEFAULT_SETTINGS.config.system_optimization,
        ...raw?.config?.system_optimization,
      },
      roblox_settings: {
        ...DEFAULT_SETTINGS.config.roblox_settings,
        ...raw?.config?.roblox_settings,
      },
      network_settings: {
        ...DEFAULT_SETTINGS.config.network_settings,
        ...raw?.config?.network_settings,
      },
    },
    window_state: {
      ...DEFAULT_SETTINGS.window_state,
      ...raw?.window_state,
    },
    update_settings: {
      ...DEFAULT_SETTINGS.update_settings,
      ...raw?.update_settings,
    },
    network_test_results: {
      ...DEFAULT_SETTINGS.network_test_results,
      ...raw?.network_test_results,
    },
    network_binding_overrides: {
      ...DEFAULT_SETTINGS.network_binding_overrides,
      ...raw?.network_binding_overrides,
    },
    game_process_performance: {
      ...DEFAULT_SETTINGS.game_process_performance,
      ...raw?.game_process_performance,
    },
  };
}
