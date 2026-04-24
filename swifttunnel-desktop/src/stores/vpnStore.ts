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
  systemResetDriver,
} from "../lib/commands";
import { reportError } from "../lib/errors";
import { notify } from "../lib/notifications";
import { useSettingsStore } from "./settingsStore";

type DriverSetupState =
  | "idle"
  | "checking"
  | "installing"
  | "installed"
  | "error";

function getErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return String(error);
}

function isRebootRequiredMessage(
  vpnError: string | null,
  driverSetupError: string | null,
): boolean {
  const haystack = `${vpnError ?? ""}\n${driverSetupError ?? ""}`.toLowerCase();
  return haystack.includes("reboot required to finish driver installation");
}

function driverStatusMessage(status: DriverCheckResponse): string {
  return status.message || "Split tunnel driver is not ready.";
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
      set({
        state: resp.state,
        region: resp.region,
        serverEndpoint: resp.server_endpoint,
        assignedIp: resp.assigned_ip,
        splitTunnelActive: resp.split_tunnel_active,
        tunneledProcesses: resp.tunneled_processes,
        error: resp.error,
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
      if (check.reboot_required || check.recommended_action === "reboot") {
        const message = driverStatusMessage(check);
        set({
          driverSetupState: "error",
          driverSetupError: message,
          driverResetAttempted: true,
        });
        throw new Error(message);
      }

      set({ driverSetupState: "installing", driverSetupError: null });
      const repaired = await systemRepairDriver();
      set({ driverStatus: repaired });
      if (!repaired.ready) {
        set({ driverResetAttempted: true });
        throw new Error(driverStatusMessage(repaired));
      }
      set({ driverSetupState: "idle", driverSetupError: null });
    } catch (e) {
      const message = getErrorMessage(e);
      set({ driverSetupState: "error", driverSetupError: message });
      throw new Error(message);
    }
  },

  repairDriver: async () => {
    try {
      set({ driverSetupState: "installing", driverSetupError: null });
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
      const raw = getErrorMessage(e);
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
      set({ driverSetupState: "installing", driverSetupError: null });
      await systemResetDriver();
      set({
        error: null,
        driverSetupState: "installed",
        driverSetupError: null,
        driverResetAttempted: false,
      });
    } catch (e) {
      const raw = getErrorMessage(e);
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
    try {
      set({
        state: "fetching_config",
        error: null,
        driverSetupError: null,
        bindingPreflight: null,
        pendingConnectIntent: null,
        connectAttemptInFlight: true,
      });
      await get().ensureDriverReady();
      set({
        state: "fetching_config",
        error: null,
        driverSetupState: "idle",
        driverSetupError: null,
      });
      const preflight = await vpnPreflightBinding(region, gamePresets);
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
        set({
          state: "error",
          error: preflight.reason,
          bindingPreflight: null,
          pendingConnectIntent: null,
          connectAttemptInFlight: false,
        });
        return;
      }
      await vpnConnect(region, gamePresets);
      await get().fetchState();
      await get().fetchDiagnostics();
      if (get().state === "connected") {
        set({ connectedAt: Date.now() });
        await notify("SwiftTunnel", `Connected to ${get().region ?? region}`);
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
    } catch (e) {
      const message = getErrorMessage(e);
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
