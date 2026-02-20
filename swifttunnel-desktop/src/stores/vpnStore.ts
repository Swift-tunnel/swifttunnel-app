import { create } from "zustand";
import type {
  VpnState,
  VpnStateEvent,
  ThroughputEvent,
  DiagnosticsResponse,
} from "../lib/types";
import {
  vpnGetState,
  vpnConnect,
  vpnDisconnect,
  vpnGetThroughput,
  vpnGetPing,
  vpnGetDiagnostics,
  systemCheckDriver,
  systemInstallDriver,
} from "../lib/commands";
import { notify } from "../lib/notifications";

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

function formatDriverSetupError(error: unknown): string {
  const detail = getErrorMessage(error);
  return [
    "Split tunnel driver not available (Windows Packet Filter driver).",
    "Automatic installation failed.",
    "",
    detail,
  ].join("\n");
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

  // Throughput
  bytesUp: number;
  bytesDown: number;
  packetsTunneled: number;
  packetsBypassed: number;

  // Ping (real-time ICMP to relay)
  ping: number | null;

  // Diagnostics
  diagnostics: DiagnosticsResponse | null;

  // Actions
  fetchState: () => Promise<void>;
  ensureDriverReady: () => Promise<void>;
  installDriver: () => Promise<void>;
  connect: (region: string, gamePresets: string[]) => Promise<void>;
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
  bytesUp: 0,
  bytesDown: 0,
  packetsTunneled: 0,
  packetsBypassed: 0,
  ping: null,
  diagnostics: null,

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
      if (check.installed) {
        set({ driverSetupState: "idle", driverSetupError: null });
        return;
      }

      set({ driverSetupState: "installing", driverSetupError: null });
      await systemInstallDriver();
      const postInstall = await systemCheckDriver();
      if (!postInstall.installed) {
        throw new Error(
          "Driver installation completed, but Windows Packet Filter driver is still not detected. Please restart your computer and try again.",
        );
      }
      set({ driverSetupState: "idle", driverSetupError: null });
    } catch (e) {
      const message = formatDriverSetupError(e);
      set({ driverSetupState: "error", driverSetupError: message });
      throw new Error(message);
    }
  },

  installDriver: async () => {
    try {
      set({ driverSetupState: "installing", driverSetupError: null });
      await systemInstallDriver();
      const check = await systemCheckDriver();
      if (!check.installed) {
        throw new Error(
          "Driver installation completed, but Windows Packet Filter driver is still not detected. Please restart your computer and try again.",
        );
      }
      set({
        error: null,
        driverSetupState: "installed",
        driverSetupError: null,
      });
    } catch (e) {
      const message = formatDriverSetupError(e);
      set({
        state: "error",
        error: message,
        driverSetupState: "error",
        driverSetupError: message,
      });
      throw new Error(message);
    }
  },

  connect: async (region, gamePresets) => {
    try {
      set({
        state: "fetching_config",
        error: null,
        driverSetupError: null,
      });
      await get().ensureDriverReady();
      set({
        state: "fetching_config",
        error: null,
        driverSetupState: "idle",
        driverSetupError: null,
      });
      await vpnConnect(region, gamePresets);
      await get().fetchState();
      await get().fetchDiagnostics();
      if (get().state === "connected") {
        await notify("SwiftTunnel", `Connected to ${get().region ?? region}`);
      }
      set({ driverSetupState: "idle", driverSetupError: null });
    } catch (e) {
      const message = getErrorMessage(e);
      set((current) => ({
        state: "error",
        error: message,
        driverSetupState:
          current.driverSetupState === "error" ? "error" : "idle",
        driverSetupError:
          current.driverSetupState === "error"
            ? current.driverSetupError
            : null,
      }));
    }
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
        diagnostics: null,
        driverSetupState: "idle",
        driverSetupError: null,
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
    } catch {
      // Silently ignore throughput fetch errors
    }
  },

  fetchPing: async () => {
    try {
      const ms = await vpnGetPing();
      set({ ping: ms });
    } catch {
      // Silently ignore ping errors
    }
  },

  fetchDiagnostics: async () => {
    try {
      const diag = await vpnGetDiagnostics();
      set({ diagnostics: diag });
    } catch {
      // Silently ignore
    }
  },

  handleStateEvent: (event) => {
    set({
      state: event.state,
      region: event.region,
      serverEndpoint: event.server_endpoint,
      assignedIp: event.assigned_ip,
      error: event.error,
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
