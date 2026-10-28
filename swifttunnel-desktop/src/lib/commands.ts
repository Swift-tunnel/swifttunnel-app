import { invoke as nativeInvoke } from "@tauri-apps/api/core";
const invoke = <T,>(command: string, args?: Record<string, unknown>): Promise<T> => {
  if (import.meta.env.DEV && typeof window !== "undefined" && new URLSearchParams(window.location.search).has("game-preview")) {
    return import("./gamePreviewApi").then(module => module.previewInvoke<T>(command, args));
  }
  return args === undefined ? nativeInvoke<T>(command) : nativeInvoke<T>(command, args);
};
import type {
  AppSettings,
  AuthStateResponse,
  OAuthPollResult,
  VpnStateResponse,
  ThroughputResponse,
  DiagnosticsResponse,
  BindingPreflightInfo,
  NetworkAdapterInfo,
  ServerListResponse,
  LatencyEntry,
  PerformanceMetricsResponse,
  CursorPosResponse,
  SystemInfoResponse,
  SystemMemorySnapshot,
  RamCleanResultResponse,
  RobloxResetReportResponse,
  StabilityResultResponse,
  SpeedResultResponse,
  BufferbloatResultResponse,
  AdminCheckResponse,
  DriverCheckResponse,
  WindowsFirewallRepairResponse,
  BoostUpdateResult,
  NetworkDiagnosticsBundleResponse,
  UpdaterCheckResponse,
  UpdaterInstallResponse,
  UpdateChannel,
  RobloxClient,
  RobloxLibrarySnapshot,
  RobloxImportPreview,
  RobloxDatacenter,
  RobloxServerPage,
  GamePreferences,
  GameLaunchPlan,
  FlagCleanupReport,
  NvidiaDriverProfile,
  NvidiaDriverSetting,
  LauncherConfig,
  GameDisplay,
} from "./types";

let pendingGamePreferencesSave: Promise<void> | null = null;
async function waitForGamePreferencesSave() {
  while (pendingGamePreferencesSave) await pendingGamePreferencesSave;
}
export const gamesGetLibrary = async () => {
  // A save can outlive the Games page. Reads may recover from its failure,
  // but must not publish the old preferences while a save is still pending.
  await waitForGamePreferencesSave().catch(() => {});
  return invoke<RobloxLibrarySnapshot>("games_get_library");
};
let pendingOverlayWindow: Promise<void> | null = null;
export const ensureOverlayWindow = (): Promise<void> => {
  // A settings change can restart the driver while native creation is still
  // running. Share that work without permanently caching the window's existence.
  pendingOverlayWindow ??= invoke<void>("ensure_overlay_window", { label: "overlay-stats" })
    .finally(() => { pendingOverlayWindow = null; });
  return pendingOverlayWindow;
};
let pendingLauncherSave: Promise<void> | null = null;
async function waitForLauncherSave() {
  while (pendingLauncherSave) await pendingLauncherSave;
}
export const gamesLauncherConfig = async () => {
  // Reopening Matchmaker must read after its previous page's save, including
  // when that save failed and the old on-disk preferences are still valid.
  await waitForLauncherSave().catch(() => {});
  return invoke<LauncherConfig>("games_launcher_config");
};
export const gamesSaveLauncherConfig = (config: LauncherConfig): Promise<void> => {
  if (pendingLauncherSave) return Promise.reject(new Error("Matchmaker settings are still being saved. Wait a moment, then retry Save."));
  const saving = invoke<void>("games_save_launcher_config", { config }).finally(() => {
    if (pendingLauncherSave === saving) pendingLauncherSave = null;
  });
  pendingLauncherSave = saving;
  return saving;
};
let pendingDisplays: Promise<GameDisplay[]> | null = null;
export const gamesDisplays = (): Promise<GameDisplay[]> => {
  pendingDisplays ??= invoke<GameDisplay[]>("games_displays")
    .finally(() => { pendingDisplays = null; });
  return pendingDisplays;
};
export const gamesCreateShortcut = (placeId: string, name: string) => invoke<string>("games_create_shortcut", { placeId, name });
export const gamesStartupTarget = () => invoke<string | null>("games_startup_target");
export const gamesDismissRecovery = () => invoke<void>("games_dismiss_recovery");
export const gamesSuggestServer = async () => {
  await Promise.all([waitForLauncherSave(), waitForGamePreferencesSave()]);
  return invoke<GameLaunchPlan | null>("games_suggest_server");
};
export const gamesSetFavourite = (placeId: string, client: RobloxClient, favourite: boolean) =>
  invoke<void>("games_set_favourite", { placeId, client, favourite });
export const gamesAddFavourite = (placeId: string, client: RobloxClient = "standard") => invoke<void>("games_add_favourite", { placeId, client });
export const gamesForget = async (placeId: string, client: RobloxClient) => {
  await waitForGamePreferencesSave().catch(() => {});
  return invoke<void>("games_forget", { placeId, client });
};
export const gamesSetNotifications = (enabled: boolean) => invoke<void>("games_set_notifications", { enabled });
export const gamesScanImports = () => invoke<RobloxImportPreview>("games_scan_imports");
export const gamesDatacenters = () => invoke<RobloxDatacenter[]>("games_datacenters");
const pendingServerSearches = new Map<string, Promise<RobloxServerPage>>();
export const gamesSearchServers = (placeId: string, datacenterId: number, cursor: number | null = null): Promise<RobloxServerPage> => {
  const key = JSON.stringify([placeId, datacenterId, cursor]);
  const pending = pendingServerSearches.get(key);
  if (pending) return pending;
  // Share in-flight work, including through a dialog remount. Completed
  // searches are never cached here; a later Refresh checks availability again.
  const search = invoke<RobloxServerPage>("games_search_servers", { placeId, datacenterId, cursor })
    .finally(() => { pendingServerSearches.delete(key); });
  pendingServerSearches.set(key, search);
  return search;
};
export const gamesSetPreferences = (placeId: string, client: RobloxClient, preferences: GamePreferences): Promise<void> => {
  if (pendingGamePreferencesSave) return Promise.reject(new Error("Game settings are still being saved. Wait a moment, then retry Save."));
  const saving = invoke<void>("games_set_preferences", { placeId, client, preferences }).finally(() => {
    if (pendingGamePreferencesSave === saving) pendingGamePreferencesSave = null;
  });
  pendingGamePreferencesSave = saving;
  return saving;
};
export const gamesLaunchPlan = async (placeId: string, client: RobloxClient, jobId: string | null = null, datacenterId: number | null = null, usePreferredRegion = true) => {
  // Observe both writes immediately. Awaiting one first could lose a failure
  // from the other if it finishes while this request is still waiting.
  await Promise.all([waitForLauncherSave(), waitForGamePreferencesSave()]);
  return invoke<GameLaunchPlan>("games_launch_plan", { placeId, client, jobId, datacenterId, usePreferredRegion });
};
export const gamesLaunch = async (placeId: string, client: RobloxClient, jobId: string | null, datacenterId: number | null, allowUnverified: boolean, safeLaunch = false) => {
  await waitForGamePreferencesSave();
  return invoke<void>("games_launch", { placeId, client, jobId, datacenterId, allowUnverified, safeLaunch });
};
export const gamesFlags = (action: "preview" | "clean" | "undo") => invoke<FlagCleanupReport>("games_flags", { action });
export const gamesSaveFlags = (enabled: boolean, json: string, expected: { custom_fflags_json: string; custom_fflags_enabled: boolean; ultraboost: boolean }) => invoke<BoostUpdateResult>("games_save_flags", { enabled, json, expectedJson: expected.custom_fflags_json, expectedEnabled: expected.custom_fflags_enabled, expectedUltraboost: expected.ultraboost });
let pendingNvidiaProfile: Promise<NvidiaDriverProfile> | null = null;
let pendingNvidiaWrite: Promise<NvidiaDriverProfile> | null = null;
export const gamesNvidiaProfile = (): Promise<NvidiaDriverProfile> => {
  if (pendingNvidiaWrite) {
    // Reopening during Apply must not adopt a pre-write driver snapshot.
    // Even a failed write is followed by a fresh read for review/retry.
    return pendingNvidiaWrite.then(gamesNvidiaProfile, gamesNvidiaProfile);
  }
  // Tab remounts share native work that is already running, without caching its result.
  pendingNvidiaProfile ??= invoke<NvidiaDriverProfile>("games_nvidia_profile")
    .finally(() => { pendingNvidiaProfile = null; });
  return pendingNvidiaProfile;
};
export const gamesSaveNvidia = (changes: { id: number; value: number | null }[], expected: NvidiaDriverSetting[]): Promise<NvidiaDriverProfile> => {
  if (pendingNvidiaWrite) return Promise.reject(new Error("NVIDIA settings are still being applied. Wait a moment, then retry Apply."));
  const writing = Promise.resolve(pendingNvidiaProfile).catch(() => {}).then(() =>
    invoke<NvidiaDriverProfile>("games_save_nvidia", { changes, expected }))
    .finally(() => { if (pendingNvidiaWrite === writing) pendingNvidiaWrite = null; });
  pendingNvidiaWrite = writing;
  return writing;
};
export const gamesRefreshMetadata = () => invoke<void>("games_refresh_metadata");
export const vpnConnectGame = (region: string, gamePresets: string[]) => invoke<void>("vpn_connect", { region, gamePresets, gameRegion: true });

// ── Auth ──

export const authGetState = () => invoke<AuthStateResponse>("auth_get_state");

export const authLogin = (email: string, password: string) =>
  invoke<void>("auth_login", { email, password });

export const authStartOAuth = () => invoke<string>("auth_start_oauth");

export const authPollOAuth = () => invoke<OAuthPollResult>("auth_poll_oauth");

export const authCancelOAuth = () => invoke<void>("auth_cancel_oauth");

export const authCompleteOAuth = (token: string, callbackState: string) =>
  invoke<void>("auth_complete_oauth", { token, callbackState });

export const authLogout = () => invoke<void>("auth_logout");

export const authRefreshProfile = () => invoke<void>("auth_refresh_profile");

// Forced-update gate: returns the server's "please update" message when this
// build has been locked out (old-build lockout), else null.
export const authUpdateRequired = () =>
  invoke<string | null>("auth_update_required");

// ── VPN ──

export const vpnGetState = () => invoke<VpnStateResponse>("vpn_get_state");

export const vpnPreflightBinding = (region: string, gamePresets: string[]) =>
  invoke<BindingPreflightInfo>("vpn_preflight_binding", {
    region,
    gamePresets,
  });

export const vpnConnect = (region: string, gamePresets: string[]) =>
  invoke<void>("vpn_connect", { region, gamePresets });

export const vpnDisconnect = () => invoke<void>("vpn_disconnect");

export const vpnGetThroughput = () =>
  invoke<ThroughputResponse | null>("vpn_get_throughput");

export const vpnGetPing = () => invoke<number | null>("vpn_get_ping");

export interface FreeTierQuota {
  /** Seconds of free relay time left, or null when no limit applies. */
  remaining_seconds: number | null;
  limit_seconds: number | null;
  /**
   * Seconds of grace left once the allowance is spent, null otherwise. The
   * backend keeps issuing leases through this window, so the session stays up
   * and the client only warns.
   */
  grace_seconds: number | null;
}

export const vpnGetFreeTier = () => invoke<FreeTierQuota>("vpn_get_free_tier");

export const vpnGetDiagnostics = () =>
  invoke<DiagnosticsResponse | null>("vpn_get_diagnostics");

export const vpnListNetworkAdapters = () =>
  invoke<NetworkAdapterInfo[]>("vpn_list_network_adapters");

// ── Servers ──

export const serverGetList = () =>
  invoke<ServerListResponse>("server_get_list");

export const serverGetLatencies = () =>
  invoke<LatencyEntry[]>("server_get_latencies");

export const serverRefresh = () => invoke<string>("server_refresh");

export const serverSmartSelect = (regionId: string) =>
  invoke<string | null>("server_smart_select", { regionId });

// ── Boost / Optimizer ──

export interface BoostMetricsOptions {
  overlayWantsFps?: boolean;
  overlayWantsPing?: boolean;
}

export const boostGetMetrics = (options: BoostMetricsOptions = {}) =>
  invoke<PerformanceMetricsResponse>("boost_get_metrics", {
    overlayWantsFps: options.overlayWantsFps ?? null,
    overlayWantsPing: options.overlayWantsPing ?? null,
  });

export const boostCursorPos = () =>
  invoke<CursorPosResponse>("boost_cursor_pos");

export const boostGetSystemMemory = () =>
  invoke<SystemMemorySnapshot>("boost_get_system_memory");

export const boostUpdateConfig = (configJson: string) =>
  invoke<BoostUpdateResult>("boost_update_config", { configJson });

export const boostSyncEffectiveConfig = () =>
  invoke<BoostUpdateResult>("boost_sync_effective_config");

export const boostCleanRam = () =>
  invoke<RamCleanResultResponse>("boost_clean_ram");

export const boostGetSystemInfo = () =>
  invoke<SystemInfoResponse>("boost_get_system_info");

export const boostRestartRoblox = () => invoke<void>("boost_restart_roblox");

export const boostCloseRoblox = () => invoke<void>("boost_close_roblox");

export const boostResetRobloxSettings = () =>
  invoke<AppSettings["config"]["roblox_settings"]>("boost_reset_roblox_settings");

/**
 * Delete every FFlag file on the machine, ours and any launcher's.
 *
 * Wider than boostResetRobloxSettings, which only removes SwiftTunnel's own
 * keys. Needs the user to have agreed to lose a bootstrapper's flag setup.
 */
export const boostResetRobloxClient = () =>
  invoke<RobloxResetReportResponse>("boost_reset_roblox_client");

// ── Network Tests ──

export const networkStartStabilityTest = (durationSecs: number, testId: string) =>
  invoke<StabilityResultResponse>("network_start_stability_test", {
    durationSecs,
    testId,
  });

export const networkStartSpeedTest = (testId: string) =>
  invoke<SpeedResultResponse>("network_start_speed_test", { testId });

export const networkStartBufferbloatTest = (testId: string) =>
  invoke<BufferbloatResultResponse>("network_start_bufferbloat_test", { testId });

export const networkCancelTest = (testId: string) =>
  invoke<void>("network_cancel_test", { testId });

// ── Settings ──

export const settingsLoad = () => invoke<AppSettings>("settings_load");

export interface SettingsSaveResult { warning: string | null; }
export const settingsSave = (settings: AppSettings) =>
  invoke<SettingsSaveResult>("settings_save", { settings });

let pendingDiagnosticExport: Promise<NetworkDiagnosticsBundleResponse> | null = null;
export const settingsGenerateNetworkDiagnosticsBundle = () => {
  if (!pendingDiagnosticExport) {
    pendingDiagnosticExport = invoke<NetworkDiagnosticsBundleResponse>(
      "settings_generate_network_diagnostics_bundle",
    ).finally(() => { pendingDiagnosticExport = null; });
  }
  return pendingDiagnosticExport;
};

export const presetSaveToDownloads = (fileName: string, contents: string) =>
  invoke<NetworkDiagnosticsBundleResponse>("preset_save_to_downloads", {
    fileName,
    contents,
  });

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

export const systemStartupRecoveryDone = () =>
  invoke<boolean>("system_startup_recovery_done");

export const systemCheckDriver = () =>
  invoke<DriverCheckResponse>("system_check_driver");

/**
 * Install the WinpkFilter driver.
 *
 * `force=true` re-runs msiexec even if `is_available()` reports success. A
 * corrupt install can pass the open-handle check but still fail IOCTLs, so the
 * force path is available for a future recovery flow (invoked after a mid-
 * session workers_panicked transition). No production caller currently passes
 * `true`; the default `force=false` path remains a no-op when the driver is
 * healthy.
 */
export const systemInstallDriver = (force = false) =>
  invoke<void>("system_install_driver", { force });

export const systemRepairDriver = () =>
  invoke<DriverCheckResponse>("system_repair_driver");

export const systemReinstallDriver = () =>
  invoke<DriverCheckResponse>("system_reinstall_driver");

export const systemRepairWindowsFirewall = () =>
  invoke<WindowsFirewallRepairResponse>("system_repair_windows_firewall");

export const systemCleanup = () => invoke<void>("system_cleanup");

export const systemCleanupTunnelState = () =>
  invoke<void>("system_cleanup_tunnel_state");

export interface NetworkRepairStep {
  id: string;
  label: string;
  status: "fixed" | "healthy" | "failed" | "skipped";
  detail: string;
}

export interface NetworkRepairResponse {
  supported: boolean;
  is_admin: boolean;
  overall: "fixed" | "healthy" | "partial" | "failed";
  steps: NetworkRepairStep[];
}

/**
 * "My internet is broken after SwiftTunnel" recovery. Resets stale WinpkFilter
 * adapter modes (the total-blackout leftover from a crashed session), removes
 * leftover IPv6 blocks / offload changes / WFP filters / hosts entries, and
 * flushes DNS. Runs unconditionally, the stuck-tunnel failure is invisible
 * to VPN state. The backend refuses while a session is active.
 */
export const systemRepairNetwork = () =>
  invoke<NetworkRepairResponse>("system_repair_network");

/**
 * Restart the NDISRD kernel service without reinstalling the driver.
 *
 * Intended as an escalation for the "wedged NDIS state" case, driver files
 * are in place, service reports running, but bind IOCTLs fail. Cheaper than
 * reinstall, and much cheaper than a full OS reboot. Runs a self-test after
 * restart so a failed reset still surfaces a useful error instead of the UI
 * claiming success.
 */
export const systemResetDriver = () => invoke<void>("system_reset_driver");

export interface StartupRegistrationSnapshot {
  exists: boolean;
  value: string | null;
}

export const systemGetStartupRegistration = () =>
  invoke<StartupRegistrationSnapshot>("system_get_startup_registration");

export const systemRepairStartupRegistration = (enabled: boolean) =>
  invoke<StartupRegistrationSnapshot>("system_repair_startup_registration", {
    enabled,
  });

export const systemRestoreStartupRegistration = (
  snapshot: StartupRegistrationSnapshot,
) =>
  invoke<StartupRegistrationSnapshot>("system_restore_startup_registration", {
    snapshot,
  });

export const systemLaunchedFromStartup = () =>
  invoke<boolean>("system_launched_from_startup");

export const systemOpenUrl = (url: string) =>
  invoke<void>("system_open_url", { url });

export const systemRestartAsAdmin = () =>
  invoke<void>("system_restart_as_admin");

export const systemUninstall = () => invoke<void>("system_uninstall");

export interface CopyLogFileResponse {
  file_path: string;
}

let pendingLogCopy: Promise<CopyLogFileResponse> | null = null;
export const systemCopyLogToClipboard = () => {
  if (!pendingLogCopy) {
    pendingLogCopy = invoke<CopyLogFileResponse>("system_copy_log_to_clipboard")
      .finally(() => { pendingLogCopy = null; });
  }
  return pendingLogCopy;
};

// ── Optimization tab ──

export interface OptimizationApplyResponse {
  requires_reboot: boolean;
}

export const optimizationApply = (id: string) =>
  invoke<OptimizationApplyResponse>("optimization_apply", { id });

export const optimizationRevert = (id: string) =>
  invoke<OptimizationApplyResponse>("optimization_revert", { id });

export const optimizationGetActive = () =>
  invoke<string[]>("optimization_get_active");
