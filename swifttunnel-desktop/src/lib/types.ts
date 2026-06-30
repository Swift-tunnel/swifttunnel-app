// TypeScript types mirroring Rust backend structs

// ── Auth ──

export type AuthState =
  | "logged_out"
  | "logging_in"
  | "awaiting_oauth"
  | "logged_in"
  | "banned"
  | `error:${string}`;

export interface AuthStateResponse {
  state: AuthState;
  email: string | null;
  user_id: string | null;
  is_tester: boolean;
  is_banned: boolean;
  banned_reason: string | null;
  banned_at: string | null;
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
  relay_auth_mode?: string | null;
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
  adapter_guid: string | null;
  selected_if_index: number | null;
  resolved_if_index: number | null;
  has_default_route: boolean;
  route_resolution_source: string | null;
  route_resolution_target_ip: string | null;
  manual_binding_active: boolean;
  binding_reason: string;
  binding_stage: string;
  cached_override_used: boolean;
  network_signature: string | null;
  last_validation_result: string;
  packets_tunneled: number;
  packets_bypassed: number;
}

export interface NetworkAdapterInfo {
  guid: string;
  friendly_name: string;
  description: string;
  if_index: number;
  is_up: boolean;
  is_default_route: boolean;
  kind: string;
}

export interface BindingCandidateInfo {
  guid: string;
  friendly_name: string;
  description: string;
  if_index: number | null;
  is_up: boolean;
  is_default_route: boolean;
  kind: string;
  stage: string;
  reason: string;
  score: number;
}

export interface BindingPreflightInfo {
  status: "ok" | "ambiguous" | "unrecoverable";
  reason: string;
  network_signature: string;
  route_resolution_source: string;
  route_resolution_target_ip: string | null;
  resolved_if_index: number | null;
  recommended_guid: string | null;
  cached_override_used: boolean;
  binding_stage: string | null;
  candidates: BindingCandidateInfo[];
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
  relay_available: boolean;
  relay_port: number | null;
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
  roblox_foreground: boolean;
  process_id: number | null;
}

export interface CursorPosResponse {
  x: number;
  y: number;
  left_down: boolean;
}

export interface SystemInfoResponse {
  is_admin: boolean;
  os_version: string;
  cpu_count: number;
}

export interface SystemMemorySnapshot {
  total_mb: number;
  used_mb: number;
  available_mb: number;
  load_pct: number;
  standby_mb: number | null;
  modified_mb: number | null;
}

export interface StandbyPurgeResult {
  attempted: boolean;
  success: boolean;
  skipped_reason: string | null;
}

export interface ModifiedFlushResult {
  attempted: boolean;
  success: boolean;
  skipped_reason: string | null;
}

export interface RamCleanResultResponse {
  before: SystemMemorySnapshot;
  after: SystemMemorySnapshot;
  trimmed_count: number;
  standby_purge: StandbyPurgeResult;
  modified_flush: ModifiedFlushResult;
  freed_mb: number;
  standby_freed_mb: number | null;
  modified_freed_mb: number | null;
  duration_ms: number;
  warnings: string[];
}

export interface BoostUpdateResult {
  warnings: string[];
  applied_config: Config;
}

export type OptimizationProfile = "LowEnd" | "Balanced" | "HighEnd" | "Custom";
export type PowerPlan =
  | "Balanced"
  | "HighPerformance"
  | "Ultimate"
  | "SwiftTunnel";
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
  previous_power_plan: PowerPlan | null;
  timer_resolution_1ms: boolean;
  mmcss_gaming_profile: boolean;
  game_mode_enabled: boolean;
  auto_ram_clean: boolean;
}

export interface RobloxSettingsConfig {
  graphics_quality: GraphicsQuality;
  unlock_fps: boolean;
  target_fps: number;
  window_width: number;
  window_height: number;
  window_fullscreen: boolean;
  ultraboost: boolean;
  custom_fflags_enabled: boolean;
  custom_fflags_json: string;
}

export interface NetworkConfig {
  enable_network_boost: boolean;
  disable_nagle: boolean;
  disable_network_throttling: boolean;
  firewall_fix: boolean;
}

export type OverlayMetric =
  | "fps"
  | "time"
  | "playtime"
  | "ping"
  | "battery"
  | "upload"
  | "download"
  | "cpu"
  | "cpu_temp"
  | "gpu"
  | "gpu_temp"
  | "ram"
  | "disk";

export type OverlaySize = "small" | "medium" | "large";
export type OverlayStyle = "straight" | "layered";
export type OverlayPosition =
  | "top-left"
  | "top-center"
  | "top-right"
  | "center-left"
  | "center"
  | "center-right"
  | "bottom-left"
  | "bottom-center"
  | "bottom-right";

export interface OverlayConfig {
  enabled: boolean;
  metrics: OverlayMetric[];
  size: OverlaySize;
  style: OverlayStyle;
  color: string;
  position: OverlayPosition;
  custom_x: number | null;
  custom_y: number | null;
  hotkey: string;
  monitor_fps_chart: boolean;
  show_max_fps_message: boolean;
}

export interface Config {
  profile: OptimizationProfile;
  system_optimization: SystemOptimizationConfig;
  roblox_settings: RobloxSettingsConfig;
  network_settings: NetworkConfig;
  auto_start_with_roblox: boolean;
  show_overlay: boolean;
  overlay: OverlayConfig;
}

// ── Network Tests ──

export interface PingSample {
  elapsed_secs: number;
  latency_ms: number | null;
}

export interface StabilityResultResponse {
  avg_ping: number;
  min_ping: number;
  max_ping: number;
  jitter: number;
  packet_loss: number;
  ping_spread: number;
  quality: string;
  sample_count: number;
  ping_samples: PingSample[];
}

export interface SpeedResultResponse {
  download_mbps: number;
  upload_mbps: number;
  server: string;
}

export interface PersistedStabilityResult {
  avg_ping: number;
  min_ping: number;
  max_ping: number;
  jitter: number;
  packet_loss: number;
  ping_spread: number;
  quality: string;
  sample_count: number;
  ping_samples: PingSample[];
  timestamp: string;
}

export interface PersistedSpeedResult {
  download_mbps: number;
  upload_mbps: number;
  server: string;
  timestamp: string;
}

export interface NetworkTestResultsCache {
  last_stability: PersistedStabilityResult | null;
  last_speed: PersistedSpeedResult | null;
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

export interface GameProcessPerformanceSettings {
  high_performance_gpu_binding: boolean;
  prefer_performance_cores: boolean;
  unbind_cpu0: boolean;
}

export interface NetworkDiagnosticsBundleResponse {
  file_path: string;
  folder_path: string;
}

export interface UpdaterCheckResponse {
  current_version: string;
  available_version: string | null;
  release_tag: string | null;
  release_notes: string | null;
  channel: UpdateChannel;
}

export interface UpdaterInstallResponse {
  installed_version: string;
  release_tag: string;
}

export interface AppSettings {
  theme: string;
  config: Config;
  window_state: WindowState;
  selected_region: string;
  selected_server: string;
  current_tab: string;
  update_settings: UpdateSettings;
  update_channel: UpdateChannel;
  minimize_to_tray: boolean;
  run_on_startup: boolean;
  auto_reconnect: boolean;
  resume_vpn_on_startup: boolean;
  last_connected_region: string | null;
  expanded_boost_info: string[];
  selected_game_presets: string[];
  network_test_results: NetworkTestResultsCache;
  forced_servers: Record<string, string>;
  artificial_latency_ms: number;
  experimental_mode: boolean;
  custom_relay_server: string;
  enable_discord_rpc: boolean;
  auto_routing_enabled: boolean;
  whitelisted_regions: string[];
  preferred_physical_adapter_guid: string | null;
  network_binding_overrides: Record<string, string>;
  adapter_binding_mode: "smart_auto" | "manual";
  game_process_performance: GameProcessPerformanceSettings;
  enable_api_tunneling: boolean;
  enable_country_ban: boolean;
  enable_partial_country_ban: boolean;
}

// ── System ──

export interface AdminCheckResponse {
  is_admin: boolean;
}

export interface DriverCheckResponse {
  installed: boolean;
  version: string | null;
  ready: boolean;
  status: string;
  message: string;
  reboot_required: boolean;
  recommended_action:
    | "none"
    | "install"
    | "reset_service"
    | "reinstall"
    | "reboot"
    | string;
}

export interface WindowsFirewallServiceStatus {
  name: string;
  display_name: string;
  state: string;
  start_attempted: boolean;
  start_succeeded: boolean;
  message: string;
}

export interface WindowsFirewallRepairResponse {
  supported: boolean;
  is_admin: boolean;
  before_available: boolean;
  after_available: boolean;
  reset_attempted: boolean;
  reset_succeeded: boolean;
  reboot_recommended: boolean;
  backup_path: string | null;
  message: string;
  probe_before: string;
  probe_after: string;
  reset_output: string | null;
  services: WindowsFirewallServiceStatus[];
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
  is_tester?: boolean;
  is_banned?: boolean;
  banned_reason?: string | null;
  banned_at?: string | null;
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

export interface RamCleanProgressEvent {
  stage: string;
  total_mb: number;
  used_mb: number;
  available_mb: number;
  load_pct: number;
  standby_mb: number | null;
  modified_mb: number | null;
  trimmed_count: number;
  current_process: string | null;
  warning: string | null;
}

export interface UpdaterProgressEvent {
  downloaded: number;
  total: number | null;
}

// ── Tabs ──

export type TabId =
  | "connect"
  | "optimization"
  | "games"
  | "ingame"
  | "network"
  | "repair"
  | "settings";
