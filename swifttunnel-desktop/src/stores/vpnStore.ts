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
} from "../lib/commands";
import { notify } from "../lib/notifications";

interface VpnStore {
  state: VpnState;
  region: string | null;
  serverEndpoint: string | null;
  assignedIp: string | null;
  splitTunnelActive: boolean;
  tunneledProcesses: string[];
  error: string | null;

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

  connect: async (region, gamePresets) => {
    try {
      set({ state: "fetching_config", error: null });
      await vpnConnect(region, gamePresets);
      await get().fetchState();
      await get().fetchDiagnostics();
      if (get().state === "connected") {
        await notify("SwiftTunnel", `Connected to ${get().region ?? region}`);
      }
    } catch (e) {
      set({ state: "error", error: String(e) });
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
