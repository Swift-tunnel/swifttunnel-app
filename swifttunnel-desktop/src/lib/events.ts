import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  VpnStateEvent,
  AuthStateEvent,
  RamCleanProgressEvent,
  UpdaterProgressEvent,
} from "./types";
import { useVpnStore } from "../stores/vpnStore";
import { useAuthStore } from "../stores/authStore";
import { useBoostStore } from "../stores/boostStore";
import { useServerStore } from "../stores/serverStore";
import { useUpdaterStore } from "../stores/updaterStore";
import { useToastStore } from "../stores/toastStore";
import { reportError } from "./errors";

const EVENT_VPN_STATE_CHANGED = "vpn-state-changed";
const EVENT_AUTH_STATE_CHANGED = "auth-state-changed";
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
    try {
      const stop = await listen<T>(name, (event) => {
        if (generation === listenerGeneration) handler(event);
      });
      if (generation !== listenerGeneration) stop();
      else unlisteners.push(stop);
    } catch (error) {
      if (generation === listenerGeneration) {
        reportError(`Failed to listen for ${name}`, error, { dedupeKey: `event-listener-${name}` });
      }
    }
  }

  // Bootstrap reads these states once their listeners are ready. The other
  // listeners can land independently, without holding up those first reads.
  const vpn = register<VpnStateEvent>(EVENT_VPN_STATE_CHANGED, (event) => {
    useVpnStore.getState().handleStateEvent(event.payload);
  });
  const auth = register<AuthStateEvent>(EVENT_AUTH_STATE_CHANGED, (event) => {
    useAuthStore.getState().handleStateEvent(event.payload);
  });
  void register<RamCleanProgressEvent>(EVENT_RAM_CLEAN_PROGRESS, (event) => {
    useBoostStore.getState().handleRamCleanProgress(event.payload);
  });
  void register<string>(EVENT_SERVER_LIST_UPDATED, () => {
    void useServerStore.getState().fetchList();
  });
  void register<UpdaterProgressEvent>(EVENT_UPDATER_PROGRESS, (event) => {
    useUpdaterStore.getState().handleUpdaterProgress(event.payload);
  });
  void register<void>(EVENT_UPDATER_DONE, () => {
    useUpdaterStore.getState().handleUpdaterDone();
  });
  void register<void>(EVENT_COUNTRY_BAN_BYPASS_UNAVAILABLE, () => {
    useToastStore.getState().addToast({
      type: "warning",
      message: "Country ban bypass could not be set up. Check Diagnostics.",
    });
  });
  await Promise.all([vpn, auth]);
}

export async function cleanupEventListeners() {
  ++listenerGeneration;
  clearRegisteredListeners();
}
