import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  VpnStateEvent,
  AuthStateEvent,
  ThroughputEvent,
  PerformanceMetricsEvent,
} from "./types";
import { useVpnStore } from "../stores/vpnStore";
import { useAuthStore } from "../stores/authStore";
import { useBoostStore } from "../stores/boostStore";
import { useServerStore } from "../stores/serverStore";

const EVENT_VPN_STATE_CHANGED = "vpn-state-changed";
const EVENT_AUTH_STATE_CHANGED = "auth-state-changed";
const EVENT_THROUGHPUT_UPDATE = "throughput-update";
const EVENT_PERFORMANCE_METRICS_UPDATE = "performance-metrics-update";
const EVENT_SERVER_LIST_UPDATED = "server-list-updated";

let unlisteners: UnlistenFn[] = [];

export async function initEventListeners() {
  // Clean up any existing listeners
  await cleanupEventListeners();

  unlisteners.push(
    await listen<VpnStateEvent>(EVENT_VPN_STATE_CHANGED, (event) => {
      useVpnStore.getState().handleStateEvent(event.payload);
    }),
  );

  unlisteners.push(
    await listen<AuthStateEvent>(EVENT_AUTH_STATE_CHANGED, (event) => {
      useAuthStore.getState().handleStateEvent(event.payload);
    }),
  );

  unlisteners.push(
    await listen<ThroughputEvent>(EVENT_THROUGHPUT_UPDATE, (event) => {
      useVpnStore.getState().handleThroughputEvent(event.payload);
    }),
  );

  unlisteners.push(
    await listen<PerformanceMetricsEvent>(
      EVENT_PERFORMANCE_METRICS_UPDATE,
      (event) => {
        useBoostStore.getState().handleMetricsEvent(event.payload);
      },
    ),
  );

  unlisteners.push(
    await listen<string>(EVENT_SERVER_LIST_UPDATED, () => {
      void useServerStore.getState().fetchList();
    }),
  );
}

export async function cleanupEventListeners() {
  for (const unlisten of unlisteners) {
    unlisten();
  }
  unlisteners = [];
}
