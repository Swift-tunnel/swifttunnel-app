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
import { useAuthStore } from "../stores/authStore";
import { useBoostStore } from "../stores/boostStore";
import { useServerStore } from "../stores/serverStore";
import { useUpdaterStore } from "../stores/updaterStore";

const EVENT_VPN_STATE_CHANGED = "vpn-state-changed";
const EVENT_AUTH_STATE_CHANGED = "auth-state-changed";
const EVENT_THROUGHPUT_UPDATE = "throughput-update";
const EVENT_PERFORMANCE_METRICS_UPDATE = "performance-metrics-update";
const EVENT_RAM_CLEAN_PROGRESS = "ram-clean-progress";
const EVENT_SERVER_LIST_UPDATED = "server-list-updated";
const EVENT_UPDATER_PROGRESS = "updater://progress";
const EVENT_UPDATER_DONE = "updater://done";

let unlisteners: UnlistenFn[] = [];
let listenerGeneration = 0;

type EventRegistration = () => Promise<UnlistenFn>;

const eventRegistrations: EventRegistration[] = [
  () =>
    listen<VpnStateEvent>(EVENT_VPN_STATE_CHANGED, (event) => {
      useVpnStore.getState().handleStateEvent(event.payload);
    }),
  () =>
    listen<AuthStateEvent>(EVENT_AUTH_STATE_CHANGED, (event) => {
      useAuthStore.getState().handleStateEvent(event.payload);
    }),
  () =>
    listen<ThroughputEvent>(EVENT_THROUGHPUT_UPDATE, (event) => {
      useVpnStore.getState().handleThroughputEvent(event.payload);
    }),
  () =>
    listen<PerformanceMetricsEvent>(
      EVENT_PERFORMANCE_METRICS_UPDATE,
      (event) => {
        useBoostStore.getState().handleMetricsEvent(event.payload);
      },
    ),
  () =>
    listen<RamCleanProgressEvent>(EVENT_RAM_CLEAN_PROGRESS, (event) => {
      useBoostStore.getState().handleRamCleanProgress(event.payload);
    }),
  () =>
    listen<string>(EVENT_SERVER_LIST_UPDATED, () => {
      void useServerStore.getState().fetchList();
    }),
  () =>
    listen<UpdaterProgressEvent>(EVENT_UPDATER_PROGRESS, (event) => {
      useUpdaterStore.getState().handleUpdaterProgress(event.payload);
    }),
  () =>
    listen<void>(EVENT_UPDATER_DONE, () => {
      useUpdaterStore.getState().handleUpdaterDone();
    }),
];

function cleanupRegisteredListeners() {
  for (const unlisten of unlisteners) {
    unlisten();
  }
  unlisteners = [];
}

async function registerListener(
  generation: number,
  registration: EventRegistration,
) {
  const unlisten = await registration();

  if (generation !== listenerGeneration) {
    unlisten();
    return false;
  }

  unlisteners.push(unlisten);
  return true;
}

export async function initEventListeners() {
  const generation = ++listenerGeneration;
  cleanupRegisteredListeners();

  try {
    for (const registration of eventRegistrations) {
      const isCurrent = await registerListener(generation, registration);
      if (!isCurrent) return;
    }
  } catch (error) {
    if (generation === listenerGeneration) {
      listenerGeneration++;
      cleanupRegisteredListeners();
    }
    throw error;
  }
}

export async function cleanupEventListeners() {
  listenerGeneration++;
  cleanupRegisteredListeners();
}
