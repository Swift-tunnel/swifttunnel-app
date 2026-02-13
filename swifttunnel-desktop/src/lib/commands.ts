import { invoke } from "@tauri-apps/api/core";
import type {
  AuthStateResponse,
  OAuthPollResult,
  VpnStateResponse,
  ThroughputResponse,
  DiagnosticsResponse,
  ServerListResponse,
  LatencyEntry,
  PerformanceMetricsResponse,
  SystemInfoResponse,
  StabilityResultResponse,
  SpeedResultResponse,
  BufferbloatResultResponse,
  AdminCheckResponse,
  DriverCheckResponse,
  UpdaterCheckResponse,
  UpdaterInstallResponse,
  UpdateChannel,
} from "./types";

// ── Auth ──

export const authGetState = () =>
  invoke<AuthStateResponse>("auth_get_state");

export const authStartOAuth = () =>
  invoke<string>("auth_start_oauth");

export const authPollOAuth = () =>
  invoke<OAuthPollResult>("auth_poll_oauth");

export const authCancelOAuth = () =>
  invoke<void>("auth_cancel_oauth");

export const authCompleteOAuth = (token: string, callbackState: string) =>
  invoke<void>("auth_complete_oauth", { token, callbackState });

export const authLogout = () =>
  invoke<void>("auth_logout");

export const authRefreshProfile = () =>
  invoke<void>("auth_refresh_profile");

// ── VPN ──

export const vpnGetState = () =>
  invoke<VpnStateResponse>("vpn_get_state");

export const vpnConnect = (region: string, gamePresets: string[]) =>
  invoke<void>("vpn_connect", { region, gamePresets });

export const vpnDisconnect = () =>
  invoke<void>("vpn_disconnect");

export const vpnGetThroughput = () =>
  invoke<ThroughputResponse | null>("vpn_get_throughput");

export const vpnGetDiagnostics = () =>
  invoke<DiagnosticsResponse | null>("vpn_get_diagnostics");

// ── Servers ──

export const serverGetList = () =>
  invoke<ServerListResponse>("server_get_list");

export const serverGetLatencies = () =>
  invoke<LatencyEntry[]>("server_get_latencies");

export const serverRefresh = () =>
  invoke<string>("server_refresh");

export const serverSmartSelect = (regionId: string) =>
  invoke<string | null>("server_smart_select", { regionId });

// ── Boost / Optimizer ──

export const boostGetMetrics = () =>
  invoke<PerformanceMetricsResponse>("boost_get_metrics");

export const boostToggle = (enable: boolean) =>
  invoke<void>("boost_toggle", { enable });

export const boostUpdateConfig = (configJson: string) =>
  invoke<void>("boost_update_config", { configJson });

export const boostGetSystemInfo = () =>
  invoke<SystemInfoResponse>("boost_get_system_info");

export const boostRestartRoblox = () =>
  invoke<void>("boost_restart_roblox");

// ── Network Tests ──

export const networkStartStabilityTest = (durationSecs: number) =>
  invoke<StabilityResultResponse>("network_start_stability_test", {
    durationSecs,
  });

export const networkStartSpeedTest = () =>
  invoke<SpeedResultResponse>("network_start_speed_test");

export const networkStartBufferbloatTest = () =>
  invoke<BufferbloatResultResponse>("network_start_bufferbloat_test");

// ── Settings ──

export const settingsLoad = () =>
  invoke<{ json: string }>("settings_load");

export const settingsSave = (settingsJson: string) =>
  invoke<void>("settings_save", { settingsJson });

// ── Updater ──

export const updaterCheckChannel = (channel: UpdateChannel) =>
  invoke<UpdaterCheckResponse>("updater_check_channel", { channel });

export const updaterInstallChannel = (
  channel: UpdateChannel,
  expectedVersion: string,
) =>
  invoke<UpdaterInstallResponse>("updater_install_channel", {
    channel,
    expectedVersion,
  });

// ── System ──

export const systemIsAdmin = () =>
  invoke<AdminCheckResponse>("system_is_admin");

export const systemCheckDriver = () =>
  invoke<DriverCheckResponse>("system_check_driver");

export const systemInstallDriver = () =>
  invoke<void>("system_install_driver");

export const systemOpenUrl = (url: string) =>
  invoke<void>("system_open_url", { url });
