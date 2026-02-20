// Mock @tauri-apps/api/core for browser preview

const MOCK_SETTINGS = {
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
  optimizations_active: true,
  window_state: { x: null, y: null, width: 560, height: 750, maximized: false },
  selected_region: "singapore",
  selected_server: "singapore",
  current_tab: "connect",
  update_settings: { auto_check: true, last_check: 1739350000 },
  update_channel: "Stable",
  minimize_to_tray: false,
  run_on_startup: true,
  auto_reconnect: true,
  resume_vpn_on_startup: true,
  last_connected_region: "singapore",
  expanded_boost_info: [],
  selected_game_presets: ["roblox", "valorant"],
  forced_servers: {},
  artificial_latency_ms: 0,
  experimental_mode: false,
  custom_relay_server: "",
  enable_discord_rpc: true,
  auto_routing_enabled: false,
  whitelisted_regions: [],
};

let mockVpnConnected = false;

const handlers: Record<string, (...args: unknown[]) => unknown> = {
  auth_get_state: () => ({
    state: "logged_in",
    email: "evelyn@swifttunnel.net",
    user_id: "usr_abc123",
    is_tester: true,
  }),

  auth_start_oauth: () => "https://swifttunnel.net/login?mock=1",
  auth_poll_oauth: () => ({ completed: false, token: null, state: null }),
  auth_cancel_oauth: () => {},
  auth_complete_oauth: () => {},
  auth_logout: () => {},
  auth_refresh_profile: () => {},

  vpn_get_state: () =>
    mockVpnConnected
      ? {
          state: "connected",
          region: "Singapore",
          server_endpoint: "54.255.205.216:51821",
          assigned_ip: null,
          split_tunnel_active: true,
          tunneled_processes: ["RobloxPlayerBeta.exe", "valorant.exe"],
          error: null,
        }
      : {
          state: "disconnected",
          region: null,
          server_endpoint: null,
          assigned_ip: null,
          split_tunnel_active: false,
          tunneled_processes: [],
          error: null,
        },

  vpn_connect: async () => {
    mockVpnConnected = true;
    await new Promise((r) => setTimeout(r, 800));
  },

  vpn_disconnect: async () => {
    mockVpnConnected = false;
    await new Promise((r) => setTimeout(r, 300));
  },

  vpn_get_throughput: () =>
    mockVpnConnected
      ? {
          bytes_up: Math.floor(Math.random() * 500000) + 100000,
          bytes_down: Math.floor(Math.random() * 2000000) + 500000,
          packets_tunneled: Math.floor(Math.random() * 10000),
          packets_bypassed: Math.floor(Math.random() * 50000),
        }
      : null,

  vpn_get_ping: () =>
    mockVpnConnected ? 12 + Math.floor(Math.random() * 10) : null,

  vpn_get_diagnostics: () =>
    mockVpnConnected
      ? {
          adapter_name: "SwiftTunnel",
          adapter_guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
          selected_if_index: 7,
          resolved_if_index: 7,
          has_default_route: true,
          route_resolution_source: "internet_fallback",
          route_resolution_target_ip: "8.8.8.8",
          manual_binding_active: false,
          packets_tunneled: 42891,
          packets_bypassed: 128744,
        }
      : null,

  server_get_list: () => ({
    regions: [
      { id: "singapore", name: "Singapore", description: "Southeast Asia", country_code: "SG", servers: ["sg-1", "sg-2", "sg-3", "sg-4", "sg-5", "sg-6"] },
      { id: "mumbai", name: "Mumbai", description: "South Asia", country_code: "IN", servers: ["in-1", "in-2", "in-3", "in-4", "in-5"] },
      { id: "tokyo", name: "Tokyo", description: "East Asia", country_code: "JP", servers: ["jp-1", "jp-2", "jp-3", "jp-4"] },
      { id: "sydney", name: "Sydney", description: "Oceania", country_code: "AU", servers: ["au-1", "au-2", "au-3"] },
      { id: "germany", name: "Germany", description: "Central Europe", country_code: "DE", servers: ["de-1", "de-2", "de-3", "de-4"] },
      { id: "us-east", name: "US East", description: "New Jersey", country_code: "US", servers: ["us-east-nj"] },
      { id: "us-west", name: "US West", description: "Los Angeles", country_code: "US", servers: ["us-west-la"] },
      { id: "us-central", name: "US Central", description: "Dallas", country_code: "US", servers: ["us-central-dallas"] },
      { id: "korea", name: "Korea", description: "East Asia", country_code: "KR", servers: ["kr-1", "kr-2"] },
      { id: "london", name: "London", description: "Western Europe", country_code: "GB", servers: ["gb-1"] },
      { id: "paris", name: "Paris", description: "Western Europe", country_code: "FR", servers: ["fr-1"] },
      { id: "amsterdam", name: "Amsterdam", description: "Western Europe", country_code: "NL", servers: ["nl-1"] },
      { id: "brazil", name: "Brazil", description: "South America", country_code: "BR", servers: ["br-1"] },
    ],
    servers: [],
    source: "mock",
  }),

  server_get_latencies: () => [
    { region: "singapore", latency_ms: 18 },
    { region: "mumbai", latency_ms: 52 },
    { region: "tokyo", latency_ms: 35 },
    { region: "sydney", latency_ms: 89 },
    { region: "germany", latency_ms: 142 },
    { region: "us-east", latency_ms: 168 },
    { region: "us-west", latency_ms: 182 },
    { region: "us-central", latency_ms: 175 },
    { region: "korea", latency_ms: 42 },
    { region: "london", latency_ms: 155 },
    { region: "paris", latency_ms: 148 },
    { region: "amsterdam", latency_ms: 145 },
    { region: "brazil", latency_ms: 210 },
  ],

  server_refresh: () => {},
  server_smart_select: () => null,

  boost_get_metrics: () => ({
    fps: 144 + Math.floor(Math.random() * 30),
    cpu_usage: 35 + Math.random() * 15,
    ram_usage: 8192 + Math.floor(Math.random() * 2048),
    ram_total: 16384,
    ping: 14 + Math.floor(Math.random() * 8),
    roblox_running: true,
    process_id: 12480,
  }),

  boost_toggle: () => {},
  boost_update_config: () => {},
  boost_restart_roblox: async () => {
    await new Promise((r) => setTimeout(r, 1200));
  },

  boost_get_system_info: () => ({
    is_admin: true,
    os_version: "Windows 11 Pro 23H2",
    cpu_count: 12,
  }),

  network_start_stability_test: async () => {
    await new Promise((r) => setTimeout(r, 1500));
    return {
      avg_ping: 16.4,
      min_ping: 12,
      max_ping: 28,
      jitter: 3.2,
      packet_loss: 0.0,
      quality: "Excellent",
      sample_count: 100,
    };
  },

  network_start_speed_test: async () => {
    await new Promise((r) => setTimeout(r, 2000));
    return {
      download_mbps: 487.3,
      upload_mbps: 142.8,
      server: "Singapore - Singtel",
    };
  },

  network_start_bufferbloat_test: async () => {
    await new Promise((r) => setTimeout(r, 2500));
    return {
      idle_latency: 14,
      loaded_latency: 22,
      bufferbloat_ms: 8,
      grade: "A",
    };
  },

  settings_load: () => ({ json: JSON.stringify(MOCK_SETTINGS) }),
  settings_save: () => {},

  updater_check_channel: (args: unknown) => {
    const channel =
      typeof args === "object" &&
      args !== null &&
      "channel" in args &&
      (args as { channel?: string }).channel
        ? (args as { channel: string }).channel
        : "Stable";
    return {
      current_version: "1.0.45",
      available_version: null,
      release_tag: null,
      channel,
    };
  },
  updater_install_channel: () => ({
    installed_version: "1.0.45",
    release_tag: "v1.0.45",
  }),

  system_is_admin: () => ({ is_admin: true }),
  system_check_driver: () => ({ installed: true, version: "3.4.1" }),
  system_install_driver: () => {},
  system_open_url: () => {},
  system_restart_as_admin: () => {},
};

export async function invoke<T>(cmd: string, _args?: unknown): Promise<T> {
  const handler = handlers[cmd];
  if (handler) {
    const result = handler(_args);
    if (result instanceof Promise) return (await result) as T;
    return result as T;
  }
  console.warn(`[tauri-mock] unhandled invoke: ${cmd}`);
  return undefined as T;
}

export function transformCallback() {
  return 0;
}

export function convertFileSrc(path: string) {
  return path;
}
