// TypeScript types mirroring Rust backend structs

// ── Auth ──

export type AuthState =
  | "logged_out"
  | "logging_in"
  | "awaiting_oauth"
  | "logged_in"
  | `error:${string}`;

export interface AuthStateResponse {
  state: AuthState;
  email: string | null;
  user_id: string | null;
  is_tester: boolean;
}

export interface OAuthPollResult {
  completed: boolean;
  token: string | null;
  state: string | null;
}

// ── VPN ──

export type VpnState =
  | "disconnected"
  | "fetching_config"
  | "creating_adapter"
  | "connecting"
  | "configuring_split_tunnel"
  | "configuring_routes"
  | "connected"
  | "disconnecting"
  | "error";

export interface VpnStateResponse {
  state: VpnState;
  region: string | null;
  server_endpoint: string | null;
  assigned_ip: string | null;
  split_tunnel_active: boolean;
  tunneled_processes: string[];
  error: string | null;
}

export interface ThroughputResponse {
  bytes_up: number;
  bytes_down: number;
  packets_tunneled: number;
  packets_bypassed: number;
}

export interface DiagnosticsResponse {
  adapter_name: string | null;
  has_default_route: boolean;
  packets_tunneled: number;
  packets_bypassed: number;
}

// ── Servers ──

export interface ServerRegion {
  id: string;
  name: string;
  description: string;
  country_code: string;
  servers: string[];
}

export interface ServerInfo {
  region: string;
  name: string;
  country_code: string;
  ip: string;
  port: number;
}

export interface ServerListResponse {
  regions: ServerRegion[];
  servers: ServerInfo[];
  source: string;
}

export interface LatencyEntry {
  region: string;
  latency_ms: number | null;
}

// ── Boost / Optimizer ──

export interface PerformanceMetricsResponse {
  fps: number;
  cpu_usage: number;
  ram_usage: number;
  ram_total: number;
  ping: number;
  roblox_running: boolean;
  process_id: number | null;
}

export interface SystemInfoResponse {
  is_admin: boolean;
  os_version: string;
  cpu_count: number;
}

export type OptimizationProfile = "LowEnd" | "Balanced" | "HighEnd" | "Custom";
export type PowerPlan = "Balanced" | "HighPerformance" | "Ultimate";
export type GraphicsQuality =
  | "Automatic"
  | "Manual"
  | "Level1"
  | "Level2"
  | "Level3"
  | "Level4"
  | "Level5"
  | "Level6"
  | "Level7"
  | "Level8"
  | "Level9"
  | "Level10";
export interface SystemOptimizationConfig {
  set_high_priority: boolean;
  set_cpu_affinity: boolean;
  cpu_cores: number[];
  disable_fullscreen_optimization: boolean;
  clear_standby_memory: boolean;
  disable_game_bar: boolean;
  power_plan: PowerPlan;
  timer_resolution_1ms: boolean;
  mmcss_gaming_profile: boolean;
  game_mode_enabled: boolean;
}

export interface RobloxSettingsConfig {
  graphics_quality: GraphicsQuality;
  unlock_fps: boolean;
  target_fps: number;
  ultraboost: boolean;
}

export interface NetworkConfig {
  enable_network_boost: boolean;
  prioritize_roblox_traffic: boolean;
  disable_nagle: boolean;
  disable_network_throttling: boolean;
  optimize_mtu: boolean;
  gaming_qos: boolean;
}

export interface Config {
  profile: OptimizationProfile;
  system_optimization: SystemOptimizationConfig;
  roblox_settings: RobloxSettingsConfig;
  network_settings: NetworkConfig;
  auto_start_with_roblox: boolean;
  show_overlay: boolean;
}

// ── Network Tests ──

export interface StabilityResultResponse {
  avg_ping: number;
  min_ping: number;
  max_ping: number;
  jitter: number;
  packet_loss: number;
  quality: string;
  sample_count: number;
}

export interface SpeedResultResponse {
  download_mbps: number;
  upload_mbps: number;
  server: string;
}

export interface BufferbloatResultResponse {
  idle_latency: number;
  loaded_latency: number;
  bufferbloat_ms: number;
  grade: string;
}

// ── Settings ──

export type UpdateChannel = "Stable" | "Live";

export interface UpdateSettings {
  auto_check: boolean;
  last_check: number | null;
  dismissed_version?: string | null;
}

export interface WindowState {
  x: number | null;
  y: number | null;
  width: number;
  height: number;
  maximized: boolean;
}

export interface UpdaterCheckResponse {
  current_version: string;
  available_version: string | null;
  release_tag: string | null;
  channel: UpdateChannel;
}

export interface UpdaterInstallResponse {
  installed_version: string;
  release_tag: string;
}

export interface AppSettings {
  theme: string;
  config: Config;
  optimizations_active: boolean;
  window_state: WindowState;
  selected_region: string;
  selected_server: string;
  current_tab: string;
  update_settings: UpdateSettings;
  update_channel: UpdateChannel;
  minimize_to_tray: boolean;
  last_connected_region: string | null;
  expanded_boost_info: string[];
  selected_game_presets: string[];
  forced_servers: Record<string, string>;
  artificial_latency_ms: number;
  experimental_mode: boolean;
  custom_relay_server: string;
  enable_discord_rpc: boolean;
  auto_routing_enabled: boolean;
  whitelisted_regions: string[];
}

// ── System ──

export interface AdminCheckResponse {
  is_admin: boolean;
}

export interface DriverCheckResponse {
  installed: boolean;
  version: string | null;
}

// ── Events ──

export interface VpnStateEvent {
  state: VpnState;
  region: string | null;
  server_endpoint: string | null;
  assigned_ip: string | null;
  error: string | null;
}

export interface AuthStateEvent {
  state: string;
  email: string | null;
  user_id: string | null;
}

export interface ThroughputEvent {
  bytes_up: number;
  bytes_down: number;
  packets_tunneled: number;
  packets_bypassed: number;
}

export interface PerformanceMetricsEvent {
  cpu_usage: number;
  ram_usage: number;
  ram_total: number;
  fps: number;
  roblox_running: boolean;
}

// ── Tabs ──

export type TabId = "connect" | "boost" | "network" | "settings";
