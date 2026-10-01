import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  VpnStateEvent,
  AuthStateEvent,
  ThroughputEvent,
  PerformanceMetricsEvent,
  RamCleanProgressEvent,
  UpdaterProgressEvent,
} from "./types";
import { useVpnStore } from "../stores/vpnStore";
import { useSettingsStore } from "../stores/settingsStore";
import { useAuthStore } from "../stores/authStore";
import { useBoostStore } from "../stores/boostStore";
import { useServerStore } from "../stores/serverStore";
import { useUpdaterStore } from "../stores/updaterStore";
import { useToastStore } from "../stores/toastStore";
import { reportError } from "./errors";

const EVENT_VPN_STATE_CHANGED = "vpn-state-changed";
const EVENT_AUTH_STATE_CHANGED = "auth-state-changed";
const EVENT_THROUGHPUT_UPDATE = "throughput-update";
const EVENT_PERFORMANCE_METRICS_UPDATE = "performance-metrics-update";
const EVENT_RAM_CLEAN_PROGRESS = "ram-clean-progress";
const EVENT_SERVER_LIST_UPDATED = "server-list-updated";
const EVENT_UPDATER_PROGRESS = "updater://progress";
const EVENT_UPDATER_DONE = "updater://done";
const EVENT_COUNTRY_BAN_BYPASS_UNAVAILABLE = "country-ban-bypass-unavailable";

let unlisteners: UnlistenFn[] = [];
let listenerGeneration = 0;

function clearRegisteredListeners() {
  const previous = unlisteners;
  unlisteners = [];
  for (const unlisten of previous) {
    try {
      unlisten();
    } catch (error) {
      reportError("Failed to remove native event listener", error, {
        dedupeKey: "event-listener-cleanup",
      });
    }
  }
}

export async function initEventListeners() {
  // Claim this generation synchronously, before any registration can yield.
  const generation = ++listenerGeneration;
  clearRegisteredListeners();

  async function register<T>(name: string, handler: (event: { payload: T }) => void) {
    if (generation !== listenerGeneration) return;
    const stop = await listen<T>(name, (event) => {
      if (generation === listenerGeneration) handler(event);
    });
    if (generation !== listenerGeneration) stop();
    else unlisteners.push(stop);
  }

  try {
    await register<void>("license-access-required", () => {
      useSettingsStore.getState().setTab("license");
    });
    await register<VpnStateEvent>(EVENT_VPN_STATE_CHANGED, (event) => {
      useVpnStore.getState().handleStateEvent(event.payload);
    });

    await register<AuthStateEvent>(EVENT_AUTH_STATE_CHANGED, (event) => {
      useAuthStore.getState().handleStateEvent(event.payload);
    });

    await register<ThroughputEvent>(EVENT_THROUGHPUT_UPDATE, (event) => {
      useVpnStore.getState().handleThroughputEvent(event.payload);
    });

    await register<PerformanceMetricsEvent>(
      EVENT_PERFORMANCE_METRICS_UPDATE,
      (event) => {
        useBoostStore.getState().handleMetricsEvent(event.payload);
      },
    );

    await register<RamCleanProgressEvent>(EVENT_RAM_CLEAN_PROGRESS, (event) => {
      useBoostStore.getState().handleRamCleanProgress(event.payload);
    });

    await register<string>(EVENT_SERVER_LIST_UPDATED, () => {
      void useServerStore.getState().fetchList();
    });

    await register<UpdaterProgressEvent>(EVENT_UPDATER_PROGRESS, (event) => {
      useUpdaterStore.getState().handleUpdaterProgress(event.payload);
    });

    await register<void>(EVENT_UPDATER_DONE, () => {
      useUpdaterStore.getState().handleUpdaterDone();
    });

    await register<void>(EVENT_COUNTRY_BAN_BYPASS_UNAVAILABLE, () => {
      useToastStore.getState().addToast({
        type: "warning",
        message: "Country ban bypass unavailable on this network",
      });
    });
  } catch (error) {
    // A stale registration failure must not remove a newer run's listeners.
    if (generation === listenerGeneration) await cleanupEventListeners();
    throw error;
  }
}

export async function cleanupEventListeners() {
  ++listenerGeneration;
  clearRegisteredListeners();
}
