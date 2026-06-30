import { create } from "zustand";
import type {
  VpnState,
  VpnStateEvent,
  ThroughputEvent,
  DiagnosticsResponse,
  BindingPreflightInfo,
  DriverCheckResponse,
} from "../lib/types";
import {
  vpnGetState,
  vpnPreflightBinding,
  vpnConnect,
  vpnDisconnect,
  vpnGetThroughput,
  vpnGetPing,
  vpnGetDiagnostics,
  systemCheckDriver,
  systemRepairDriver,
  systemRepairWindowsFirewall,
  systemResetDriver,
  boostGetMetrics,
} from "../lib/commands";
import { reportError } from "../lib/errors";
import { notify } from "../lib/notifications";
import { useSettingsStore } from "./settingsStore";
import { useServerStore } from "./serverStore";

type DriverSetupState =
  | "idle"
  | "checking"
  | "installing"
  | "repairing"
  | "installed"
  | "error";

function getErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return String(error);
}

const FULL_COUNTRY_BAN_ROBLOX_RUNNING_MESSAGE =
  "Close Roblox before connecting with Full Country Ban. Then connect SwiftTunnel and reopen Roblox so login and game traffic use the bypass.";

const WINDOWS_DRIVER_INSTALLER_FAILURE_MESSAGE =
  "Windows could not install SwiftTunnel's split-tunnel driver because Windows networking/driver services are not responding cleanly. Restart Windows once, then open SwiftTunnel and try again. If it still fails, contact support with the log file.";

function isWindowsDriverInstallerFailureMessage(message: string): boolean {
  const haystack = message.toLowerCase();
  return (
    (haystack.includes("netcfg failed with code 1753") ||
      haystack.includes("0x800106d9") ||
      haystack.includes("msiexec code 1603") ||
      haystack.includes("there are no more endpoints available from the endpoint mapper") ||
      haystack.includes("driver file not found, cannot create ndisrd service")) &&
    (haystack.includes("winpkfilter") ||
      haystack.includes("windows packet filter") ||
      haystack.includes("nt_ndisrd") ||
      haystack.includes("ndisrd"))
  );
}

function cleanDriverSetupMessage(message: string): string {
  if (isWindowsDriverInstallerFailureMessage(message)) {
    return WINDOWS_DRIVER_INSTALLER_FAILURE_MESSAGE;
  }
  return message;
}

function isRebootRequiredMessage(
  vpnError: string | null,
  driverSetupError: string | null,
): boolean {
  const haystack = `${vpnError ?? ""}\n${driverSetupError ?? ""}`.toLowerCase();
  return haystack.includes("reboot required to finish driver installation");
}

function driverStatusMessage(status: DriverCheckResponse): string {
  return cleanDriverSetupMessage(
    status.message || "Split tunnel driver is not ready.",
  );
}

function isPendingDriverInstallReboot(status: DriverCheckResponse): boolean {
  if (!status.reboot_required && status.recommended_action !== "reboot") {
    return false;
  }

  const message = driverStatusMessage(status).toLowerCase();
  return (
    message.includes("reboot required to finish driver installation") ||
    message.includes("reboot required to finish winpkfilter") ||
    message.includes("marked for deletion")
  );
}

function isRepairableBindingPreflight(preflight: BindingPreflightInfo): boolean {
  const haystack = `${preflight.reason}\n${preflight.binding_stage ?? ""}`.toLowerCase();
  return (
    preflight.status === "unrecoverable" &&
    (haystack.includes("winpkfilter_binding_missing") ||
      haystack.includes("winpkfilter binding is missing") ||
      haystack.includes("nt_ndisrd is not bound") ||
      haystack.includes("nt_ndisrd is not installed on adapter") ||
      haystack.includes("binding nt_ndisrd is not installed") ||
      haystack.includes("winpkfilter-bound network adapters") ||
      haystack.includes("repair the split tunnel driver"))
  );
}

function isBindingMissingMessage(message: string): boolean {
  const haystack = message.toLowerCase();
  return (
    haystack.includes("winpkfilter_binding_missing") ||
    haystack.includes("split tunnel driver binding is missing") ||
    haystack.includes("failed to ensure winpkfilter binding") ||
    haystack.includes("winpkfilter binding validation failed") ||
    (haystack.includes("nt_ndisrd") &&
      (haystack.includes("not bound") ||
        haystack.includes("not installed on adapter") ||
        haystack.includes("binding is missing")))
  );
}

function isPermissionMessage(message: string): boolean {
  const haystack = message.toLowerCase();
  return (
    haystack.includes("administrator privileges required") ||
    haystack.includes("run swifttunnel as administrator") ||
    haystack.includes("access is denied") ||
    haystack.includes("access denied") ||
    haystack.includes("process is not elevated")
  );
}

function isDriverRebootMessage(message: string): boolean {
  const haystack = message.toLowerCase();
  return (
    isRebootRequiredMessage(message, null) ||
    haystack.includes("marked for deletion") ||
    (haystack.includes("reboot") && haystack.includes("driver"))
  );
}

function isRepairableDriverConnectMessage(message: string): boolean {
  const haystack = message.toLowerCase();
  if (haystack.includes("windows blocked swifttunnel's split-tunnel driver access")) {
    return true;
  }
  if (isPermissionMessage(message)) {
    return false;
  }

  return (
    isBindingMissingMessage(message) ||
    (haystack.includes("split tunnel driver not available") &&
      haystack.includes("windows packet filter driver")) ||
    (haystack.includes("failed to open") && haystack.includes("ndisrd")) ||
    haystack.includes("no tcp/ip-bound network adapters") ||
    haystack.includes("version query failed") ||
    haystack.includes("installed but ioctl failed") ||
    haystack.includes("get_tcpip_bound_adapters_info") ||
    haystack.includes("windows packet filter driver did not become available") ||
    haystack.includes("could not attach its network filter") ||
    haystack.includes("windows packet filter driver for your active network adapter") ||
    (haystack.includes("driver service") && haystack.includes("reset"))
  );
}

function isRepairableWindowsFirewallMessage(message: string): boolean {
  const haystack = message.toLowerCase();
  if (isPermissionMessage(message)) {
    return false;
  }

  return (
    haystack.includes("advfirewall") ||
    haystack.includes("windows firewall") ||
    haystack.includes("base filtering engine") ||
    haystack.includes("mpssvc") ||
    haystack.includes("ipv6 block firewall rule")
  );
}

function isAlreadyConnectedMessage(message: string): boolean {
  return message.trim().toLowerCase().replace(/\.+$/, "") === "already connected";
}

const VPN_CONNECT_TIMEOUT_MS = 90_000;
// Adapter preflight can wait on slow Windows networking APIs. Keep its UI
// timeout aligned with the real connect budget so we do not fail at 20s while
// the backend is still making progress.
const VPN_PREFLIGHT_TIMEOUT_MS = VPN_CONNECT_TIMEOUT_MS;
const VPN_CONNECT_CLEANUP_TIMEOUT_MS = 15_000;

function formatTimeout(timeoutMs: number): string {
  const seconds = timeoutMs / 1000;
  return Number.isInteger(seconds) ? `${seconds}s` : `${timeoutMs}ms`;
}

function withTimeout<T>(
  promise: Promise<T>,
  label: string,
  timeoutMs: number,
): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(
        new Error(
          `${label} timed out after ${formatTimeout(timeoutMs)}. SwiftTunnel stopped this connect attempt so you can retry.`,
        ),
      );
    }, timeoutMs);
  });

  return Promise.race([promise, timeout]).finally(() => {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
  });
}

async function cleanupFailedConnectAttempt(): Promise<string | null> {
  try {
    await withTimeout(
      vpnDisconnect(),
      "VPN cleanup",
      VPN_CONNECT_CLEANUP_TIMEOUT_MS,
    );
    return null;
  } catch (error) {
    const message = getErrorMessage(error);
    reportError("Failed to clean up VPN after connect failure", error, {
      dedupeKey: "vpn-connect-cleanup",
    });
    return message;
  }
}

let connectAttemptSeq = 0;
const autoRepairedBindingSignatures = new Set<string>();
const autoRepairedFirewallSignatures = new Set<string>();
let relayFailoverInFlight = false;
let lastRelayFailoverAt = 0;

function nextConnectAttempt(): number {
  connectAttemptSeq += 1;
  return connectAttemptSeq;
}

function isCurrentConnectAttempt(attempt: number): boolean {
  return attempt === connectAttemptSeq;
}

function isRelayStoppedReturningTrafficMessage(message: string | null): boolean {
  const haystack = (message ?? "").toLowerCase();
  return (
    haystack.includes("relay connection failed") &&
    haystack.includes("relay stopped returning traffic")
  );
}

function sameRegionKey(value: string): string {
  return value.trim().toLowerCase().replace(/[\s_]+/g, "-");
}

function resolveFailoverRegionId(
  eventRegion: string | null,
  selectedRegion: string,
): string | null {
  const regions = useServerStore.getState().regions;
  const candidates = [eventRegion, selectedRegion].filter(
    (value): value is string => Boolean(value && value.trim()),
  );

  for (const candidate of candidates) {
    const normalized = sameRegionKey(candidate);
    const region = regions.find(
      (r) =>
        sameRegionKey(r.id) === normalized ||
        sameRegionKey(r.name) === normalized,
    );
    if (region) return region.id;
  }

  return null;
}

function chooseNextRelayForRegion(
  regionId: string,
  currentForcedServer: string | undefined,
): string | null {
  const region = useServerStore
    .getState()
    .regions.find((candidate) => candidate.id === regionId);
  const relays = region?.servers.filter(Boolean) ?? [];
  if (relays.length < 2) return null;

  if (currentForcedServer) {
    const currentIndex = relays.indexOf(currentForcedServer);
    if (currentIndex >= 0) {
      return relays[(currentIndex + 1) % relays.length] ?? null;
    }
  }

  return relays[1] ?? null;
}

async function failoverRelayAfterDeadSession(
  event: VpnStateEvent,
  connect: (region: string, gamePresets: string[]) => Promise<void>,
): Promise<void> {
  if (relayFailoverInFlight) return;

  const now = Date.now();
  if (now - lastRelayFailoverAt < 5_000) return;

  const settingsStore = useSettingsStore.getState();
  const settings = settingsStore.settings;
  if (useServerStore.getState().regions.length === 0) {
    await useServerStore.getState().fetchList();
  }
  const regionId = resolveFailoverRegionId(event.region, settings.selected_region);
  if (!regionId) return;

  const nextRelay = chooseNextRelayForRegion(
    regionId,
    settings.forced_servers[regionId],
  );
  if (!nextRelay) return;

  relayFailoverInFlight = true;
  lastRelayFailoverAt = now;
  try {
    settingsStore.update({
      selected_region: regionId,
      auto_routing_enabled: false,
      forced_servers: {
        ...settings.forced_servers,
        [regionId]: nextRelay,
      },
    });
    await settingsStore.save();
    await notify(
      "SwiftTunnel",
      `Relay stopped responding. Switching ${regionId} to ${nextRelay} and reconnecting.`,
    );
    await connect(regionId, settings.selected_game_presets);
  } catch (error) {
    reportError("Failed to fail over after relay stopped returning traffic", error, {
      dedupeKey: "vpn-relay-failover",
    });
  } finally {
    relayFailoverInFlight = false;
  }
}

function bindingRepairFailedStatus(reason: string): DriverCheckResponse {
  const message = isWindowsDriverInstallerFailureMessage(reason)
    ? WINDOWS_DRIVER_INSTALLER_FAILURE_MESSAGE
    : "SwiftTunnel repaired the split-tunnel driver, but Windows still has not attached the network filter to the active adapter. Restart Windows once, then connect again. If it still fails after restarting, contact support with this result.\n\nDetails: " +
      reason;

  return {
    installed: true,
    version: null,
    ready: false,
    status: "reboot_required",
    message,
    reboot_required: true,
    recommended_action: "reboot",
  };
}

function driverRebootRequiredStatus(reason: string): DriverCheckResponse {
  const message = isWindowsDriverInstallerFailureMessage(reason)
    ? WINDOWS_DRIVER_INSTALLER_FAILURE_MESSAGE
    : "Restart Windows once to finish setting up SwiftTunnel's network driver, then connect again. If it still fails after restarting, contact support with this result.\n\nDetails: " +
      reason;

  return {
    installed: true,
    version: null,
    ready: false,
    status: "reboot_required",
    message,
    reboot_required: true,
    recommended_action: "reboot",
  };
}

interface VpnStore {
  state: VpnState;
  region: string | null;
  serverEndpoint: string | null;
  assignedIp: string | null;
  splitTunnelActive: boolean;
  tunneledProcesses: string[];
  error: string | null;
  driverSetupState: DriverSetupState;
  driverSetupError: string | null;
  driverStatus: DriverCheckResponse | null;
  /**
   * Set to true once the user has clicked "Reset driver service" at least
   * once during the current error lifecycle. Prevents the UI from
   * offering the same button forever when the actual problem can't be
   * fixed by a service restart (e.g. another VPN product's older
   * WinpkFilter is installed). Cleared on a successful connect or
   * disconnect so the next incident gets a fresh reset attempt.
   */
  driverResetAttempted: boolean;

  // Throughput
  bytesUp: number;
  bytesDown: number;
  packetsTunneled: number;
  packetsBypassed: number;

  // Ping (real-time ICMP to relay)
  ping: number | null;

  // Session timer
  connectedAt: number | null;

  // Diagnostics
  diagnostics: DiagnosticsResponse | null;
  bindingPreflight: BindingPreflightInfo | null;
  pendingConnectIntent: { region: string; gamePresets: string[] } | null;
  connectAttemptInFlight: boolean;

  // Actions
  fetchState: () => Promise<void>;
  ensureDriverReady: () => Promise<void>;
  repairDriver: () => Promise<void>;
  installDriver: () => Promise<void>;
  resetDriver: () => Promise<void>;
  connect: (region: string, gamePresets: string[]) => Promise<void>;
  resumeConnectWithAdapter: (guid: string) => Promise<void>;
  dismissBindingChooser: () => void;
  disconnect: () => Promise<void>;
  fetchThroughput: () => Promise<void>;
  fetchPing: () => Promise<void>;
  fetchDiagnostics: () => Promise<void>;
  handleStateEvent: (event: VpnStateEvent) => void;
  handleThroughputEvent: (event: ThroughputEvent) => void;
}

export const useVpnStore = create<VpnStore>((set, get) => ({
  state: "disconnected",
  region: null,
  serverEndpoint: null,
  assignedIp: null,
  splitTunnelActive: false,
  tunneledProcesses: [],
  error: null,
  driverSetupState: "idle",
  driverSetupError: null,
  driverStatus: null,
  driverResetAttempted: false,
  bytesUp: 0,
  bytesDown: 0,
  packetsTunneled: 0,
  packetsBypassed: 0,
  ping: null,
  connectedAt: null,
  diagnostics: null,
  bindingPreflight: null,
  pendingConnectIntent: null,
  connectAttemptInFlight: false,

  fetchState: async () => {
    try {
      const resp = await vpnGetState();
      set((current) => {
        const staleReadyPoll =
          resp.state === "disconnected" &&
          resp.error === null &&
          current.state !== "disconnecting" &&
          (current.connectAttemptInFlight ||
            (current.state === "error" && current.error !== null));

        if (staleReadyPoll) {
          return {};
        }

        return {
          state: resp.state,
          region: resp.region,
          serverEndpoint: resp.server_endpoint,
          assignedIp: resp.assigned_ip,
          splitTunnelActive: resp.split_tunnel_active,
          tunneledProcesses: resp.tunneled_processes,
          error: resp.error,
        };
      });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  ensureDriverReady: async () => {
    try {
      set({ driverSetupState: "checking", driverSetupError: null });
      const check = await systemCheckDriver();
      set({ driverStatus: check });
      if (check.ready) {
        set({ driverSetupState: "idle", driverSetupError: null });
        return;
      }
      if (isPendingDriverInstallReboot(check)) {
        const message = driverStatusMessage(check);
        set({
          driverSetupState: "error",
          driverSetupError: message,
          driverResetAttempted: true,
        });
        throw new Error(message);
      }

      const repairState: DriverSetupState =
        check.recommended_action === "install" ||
        check.recommended_action === "reinstall"
          ? "installing"
          : "repairing";
      set({ driverSetupState: repairState, driverSetupError: null });
      const repaired = await systemRepairDriver();
      set({ driverStatus: repaired });
      if (!repaired.ready) {
        set({ driverResetAttempted: true });
        throw new Error(driverStatusMessage(repaired));
      }
      set({ driverSetupState: "idle", driverSetupError: null });
    } catch (e) {
      const message = cleanDriverSetupMessage(getErrorMessage(e));
      set({ driverSetupState: "error", driverSetupError: message });
      throw new Error(message);
    }
  },

  repairDriver: async () => {
    try {
      set({ driverSetupState: "repairing", driverSetupError: null });
      const repaired = await systemRepairDriver();
      set({ driverStatus: repaired });
      if (!repaired.ready) {
        const message = driverStatusMessage(repaired);
        set({
          state: "error",
          error: message,
          driverSetupState: "error",
          driverSetupError: message,
          driverResetAttempted: true,
        });
        throw new Error(message);
      }
      set({
        error: null,
        driverSetupState: "installed",
        driverSetupError: null,
        driverResetAttempted: false,
      });
    } catch (e) {
      const raw = cleanDriverSetupMessage(getErrorMessage(e));
      set({
        state: "error",
        error: raw,
        driverSetupState: "error",
        driverSetupError: raw,
        driverResetAttempted: true,
      });
      throw new Error(raw);
    }
  },

  installDriver: async () => {
    await get().repairDriver();
  },

  resetDriver: async () => {
    // Invoked from the UI when resolveConnectStatus returns
    // `kind: "driver_outdated"` — clears the "wedged NDIS state" that a full
    // reinstall won't fix (prior-generation WinpkFilter from another VPN
    // product being earlier in the service path, in-kernel filter state
    // left behind by a previous session, etc.). Much cheaper than asking
    // the user to reboot, which was the only workaround in 1.25.2.
    //
    // `driverResetAttempted` is flipped to true in the failure branch so
    // the UI can stop offering the same button after a reset that didn't
    // work — it's the UX guardrail against the exact 1.25.2 loop (user
    // clicks "fix it" → backend says ok → user tries again → same error)
    // that this PR is trying to close. Cleared on successful connect or
    // disconnect to give the next incident a fresh attempt.
    try {
      set({ driverSetupState: "repairing", driverSetupError: null });
      await systemResetDriver();
      set({
        error: null,
        driverSetupState: "installed",
        driverSetupError: null,
        driverResetAttempted: false,
      });
    } catch (e) {
      const raw = cleanDriverSetupMessage(getErrorMessage(e));
      set((current) => {
        const priorRebootRequired = isRebootRequiredMessage(
          current.error,
          current.driverSetupError,
        );
        const priorMessage = current.driverSetupError || current.error;
        const message =
          priorRebootRequired && priorMessage
            ? `${priorMessage}\n\nReset driver service failed: ${raw}`
            : raw;
        return {
          state: "error",
          error: message,
          driverSetupState: "error",
          driverSetupError: message,
          driverResetAttempted: true,
        };
      });
      throw new Error(raw);
    }
  },

  connect: async (region, gamePresets) => {
    const attempt = nextConnectAttempt();
    const fullCountryBanEnabled =
      useSettingsStore.getState().settings.enable_country_ban;
    try {
      if (fullCountryBanEnabled) {
        try {
          const robloxRunning = (await boostGetMetrics()).roblox_running;
          if (robloxRunning) {
            set({
              state: "error",
              error: FULL_COUNTRY_BAN_ROBLOX_RUNNING_MESSAGE,
              driverSetupError: null,
              bindingPreflight: null,
              pendingConnectIntent: null,
              connectAttemptInFlight: false,
            });
            await notify(
              "SwiftTunnel",
              "Close Roblox first, then connect Full Country Ban.",
            );
            return;
          }
        } catch (e) {
          reportError("Failed to check Roblox before Full Country Ban connect", e, {
            dedupeKey: "full-country-ban-roblox-running-check",
          });
        }
      }
      set({
        state: "fetching_config",
        error: null,
        driverSetupError: null,
        bindingPreflight: null,
        pendingConnectIntent: null,
        connectAttemptInFlight: true,
      });
      await get().ensureDriverReady();
      if (!isCurrentConnectAttempt(attempt)) return;
      set({
        state: "fetching_config",
        error: null,
        driverSetupState: "idle",
        driverSetupError: null,
      });
      let preflight = await withTimeout(
        vpnPreflightBinding(region, gamePresets),
        "Split tunnel preflight",
        VPN_PREFLIGHT_TIMEOUT_MS,
      );
      if (!isCurrentConnectAttempt(attempt)) return;
      if (
        isRepairableBindingPreflight(preflight) &&
        !autoRepairedBindingSignatures.has(preflight.network_signature)
      ) {
        autoRepairedBindingSignatures.add(preflight.network_signature);
        set({
          state: "configuring_split_tunnel",
          error: null,
          driverSetupState: "repairing",
          driverSetupError: null,
          bindingPreflight: null,
          pendingConnectIntent: null,
        });
        const repaired = await systemRepairDriver();
        set({ driverStatus: repaired });
        if (!repaired.ready) {
          const message = driverStatusMessage(repaired);
          set({
            state: "error",
            error: message,
            driverSetupState: "error",
            driverSetupError: message,
            driverResetAttempted: repaired.reboot_required,
            connectAttemptInFlight: false,
          });
          return;
        }
        if (!isCurrentConnectAttempt(attempt)) return;
        await get().connect(region, gamePresets);
        return;
      }
      if (isRepairableBindingPreflight(preflight)) {
        const status = bindingRepairFailedStatus(preflight.reason);
        set({
          state: "error",
          error: status.message,
          driverSetupState: "error",
          driverSetupError: status.message,
          driverStatus: status,
          bindingPreflight: null,
          pendingConnectIntent: null,
          connectAttemptInFlight: false,
        });
        return;
      }
      if (preflight.status === "ambiguous") {
        set({
          state: "disconnected",
          error: preflight.reason,
          bindingPreflight: preflight,
          pendingConnectIntent: { region, gamePresets },
          connectAttemptInFlight: false,
        });
        return;
      }
      if (preflight.status === "unrecoverable") {
        if (isRepairableBindingPreflight(preflight)) {
          const status = bindingRepairFailedStatus(preflight.reason);
          set({
            state: "error",
            error: status.message,
            driverSetupState: "error",
            driverSetupError: status.message,
            driverStatus: status,
            bindingPreflight: null,
            pendingConnectIntent: null,
            connectAttemptInFlight: false,
          });
          return;
        }
        set({
          state: "error",
          error: preflight.reason,
          bindingPreflight: null,
          pendingConnectIntent: null,
          connectAttemptInFlight: false,
        });
        return;
      }
      try {
        await withTimeout(
          vpnConnect(region, gamePresets),
          "VPN connection",
          VPN_CONNECT_TIMEOUT_MS,
        );
      } catch (e) {
        const message = getErrorMessage(e);
        if (isDriverRebootMessage(message)) {
          const status = driverRebootRequiredStatus(message);
          set({
            state: "error",
            error: status.message,
            driverSetupState: "error",
            driverSetupError: status.message,
            driverStatus: status,
            bindingPreflight: null,
            pendingConnectIntent: null,
            connectAttemptInFlight: false,
          });
          return;
        }
        if (isRepairableDriverConnectMessage(message)) {
          const repairAlreadyTried = autoRepairedBindingSignatures.has(
            preflight.network_signature,
          );
          const cleanupError = await cleanupFailedConnectAttempt();
          if (!isCurrentConnectAttempt(attempt)) return;
          if (cleanupError) {
            throw new Error(
              `${message}\n\nCleanup after failed connect also failed: ${cleanupError}`,
            );
          }
          if (!repairAlreadyTried) {
            autoRepairedBindingSignatures.add(preflight.network_signature);
            set({
              state: "configuring_split_tunnel",
              error: null,
              driverSetupState: "repairing",
              driverSetupError: null,
            });
            const repaired = await systemRepairDriver();
            set({ driverStatus: repaired });
            if (!repaired.ready) {
              throw new Error(driverStatusMessage(repaired));
            }
            if (!isCurrentConnectAttempt(attempt)) return;
            await get().connect(region, gamePresets);
            return;
          }
          const status = bindingRepairFailedStatus(message);
          set({
            state: "error",
            error: status.message,
            driverSetupState: "error",
            driverSetupError: status.message,
            driverStatus: status,
            bindingPreflight: null,
            pendingConnectIntent: null,
            connectAttemptInFlight: false,
          });
          return;
        }
        if (isRepairableWindowsFirewallMessage(message)) {
          const repairAlreadyTried = autoRepairedFirewallSignatures.has(
            preflight.network_signature,
          );
          const cleanupError = await cleanupFailedConnectAttempt();
          if (!isCurrentConnectAttempt(attempt)) return;
          if (cleanupError) {
            throw new Error(
              `${message}\n\nCleanup after failed connect also failed: ${cleanupError}`,
            );
          }
          if (!repairAlreadyTried) {
            autoRepairedFirewallSignatures.add(preflight.network_signature);
            set({
              state: "configuring_split_tunnel",
              error: null,
              driverSetupState: "repairing",
              driverSetupError: null,
            });
            const repaired = await systemRepairWindowsFirewall();
            if (!repaired.after_available) {
              throw new Error(repaired.message || message);
            }
            if (!isCurrentConnectAttempt(attempt)) return;
            await get().connect(region, gamePresets);
            return;
          }
          throw new Error(
            "Windows Firewall repair did not finish SwiftTunnel setup. Restart Windows once, then connect again. If it still fails, contact support and include this result.\n\nDetails: " +
              message,
          );
        }
        if (!isAlreadyConnectedMessage(message)) {
          const cleanupError = await cleanupFailedConnectAttempt();
          if (!isCurrentConnectAttempt(attempt)) return;
          if (cleanupError) {
            throw new Error(
              `${message}\n\nCleanup after failed connect also failed: ${cleanupError}`,
            );
          }
          throw new Error(message);
        }
      }
      if (!isCurrentConnectAttempt(attempt)) return;
      await get().fetchState();
      if (!isCurrentConnectAttempt(attempt)) return;
      await get().fetchDiagnostics();
      if (!isCurrentConnectAttempt(attempt)) return;
      if (get().state === "connected") {
        set({ connectedAt: Date.now() });
        await notify(
          "SwiftTunnel",
          fullCountryBanEnabled
            ? "Connected. Open Roblox now so Full Country Ban uses the tunnel."
            : `Connected to ${get().region ?? region}`,
        );
      }
      // Successful connect clears the reset-attempted one-shot so a future
      // unrelated incident gets a fresh "Reset driver service" offer.
      set({
        driverSetupState: "idle",
        driverSetupError: null,
        driverStatus: null,
        driverResetAttempted: false,
        connectAttemptInFlight: false,
      });
      autoRepairedBindingSignatures.clear();
      autoRepairedFirewallSignatures.clear();
    } catch (e) {
      if (!isCurrentConnectAttempt(attempt)) return;
      const message = cleanDriverSetupMessage(getErrorMessage(e));
      set((current) => ({
        state: "error",
        error: message,
        connectAttemptInFlight: false,
        driverSetupState:
          current.driverSetupState === "error" ? "error" : "idle",
        driverSetupError:
          current.driverSetupState === "error"
            ? current.driverSetupError
            : null,
      }));
    }
  },

  resumeConnectWithAdapter: async (guid) => {
    const preflight = get().bindingPreflight;
    const pending = get().pendingConnectIntent;
    if (!preflight || !pending) {
      return;
    }

    const settingsStore = useSettingsStore.getState();
    settingsStore.update({
      network_binding_overrides: {
        ...settingsStore.settings.network_binding_overrides,
        [preflight.network_signature]: guid,
      },
    });
    await settingsStore.save();

    set({
      bindingPreflight: null,
      pendingConnectIntent: null,
      error: null,
    });

    await get().connect(pending.region, pending.gamePresets);
  },

  dismissBindingChooser: () => {
    set({
      bindingPreflight: null,
      pendingConnectIntent: null,
    });
  },

  disconnect: async () => {
    nextConnectAttempt();
    try {
      set({ state: "disconnecting" });
      await vpnDisconnect();
      await get().fetchState();
      set({
        region: null,
        serverEndpoint: null,
        assignedIp: null,
        splitTunnelActive: false,
        tunneledProcesses: [],
        bytesUp: 0,
        bytesDown: 0,
        packetsTunneled: 0,
        packetsBypassed: 0,
        ping: null,
        connectedAt: null,
        diagnostics: null,
        bindingPreflight: null,
        pendingConnectIntent: null,
        connectAttemptInFlight: false,
        driverSetupState: "idle",
        driverSetupError: null,
        driverStatus: null,
        driverResetAttempted: false,
      });
      autoRepairedBindingSignatures.clear();
      autoRepairedFirewallSignatures.clear();
      await notify("SwiftTunnel", "VPN disconnected.");
    } catch (e) {
      set({ state: "error", error: String(e) });
    }
  },

  fetchThroughput: async () => {
    try {
      const stats = await vpnGetThroughput();
      if (stats) {
        set({
          bytesUp: stats.bytes_up,
          bytesDown: stats.bytes_down,
          packetsTunneled: stats.packets_tunneled,
          packetsBypassed: stats.packets_bypassed,
        });
      }
    } catch (error) {
      reportError("Failed to fetch VPN throughput", error, {
        dedupeKey: "vpn-fetch-throughput",
      });
    }
  },

  fetchPing: async () => {
    try {
      const ms = await vpnGetPing();
      set({ ping: ms });
    } catch (error) {
      reportError("Failed to fetch VPN ping", error, {
        dedupeKey: "vpn-fetch-ping",
      });
    }
  },

  fetchDiagnostics: async () => {
    try {
      const diag = await vpnGetDiagnostics();
      set({ diagnostics: diag });
    } catch (error) {
      reportError("Failed to fetch VPN diagnostics", error, {
        dedupeKey: "vpn-fetch-diagnostics",
      });
    }
  },

  handleStateEvent: (event) => {
    const shouldFailoverRelay =
      event.state === "error" &&
      isRelayStoppedReturningTrafficMessage(event.error);

    set((current) => {
      const staleReadyEvent =
        event.state === "disconnected" &&
        event.error === null &&
        current.state !== "disconnecting" &&
        (current.connectAttemptInFlight ||
          (current.state === "error" && current.error !== null));

      if (staleReadyEvent) {
        return {};
      }

      const staleTransitionAfterError =
        current.state === "error" &&
        current.error !== null &&
        !current.connectAttemptInFlight &&
        event.error === null &&
        event.state !== "connected" &&
        event.state !== "error" &&
        event.state !== "disconnected";

      if (staleTransitionAfterError) {
        return {};
      }

      return {
        state: event.state,
        region: event.region,
        serverEndpoint: event.server_endpoint,
        assignedIp: event.assigned_ip,
        error: event.error,
        connectAttemptInFlight:
          event.state === "connected" || event.state === "error"
            ? false
            : current.connectAttemptInFlight,
      };
    });

    if (shouldFailoverRelay) {
      void failoverRelayAfterDeadSession(event, get().connect);
    }
  },

  handleThroughputEvent: (event) => {
    set({
      bytesUp: event.bytes_up,
      bytesDown: event.bytes_down,
      packetsTunneled: event.packets_tunneled,
      packetsBypassed: event.packets_bypassed,
    });
  },
}));
