import type { AppSettings, AuthState, VpnState } from "./types";
import { shouldAutoReconnectOnLaunch } from "./startup";
import { reportError } from "./errors";

type AppBootstrapDeps = {
  initEventListeners: () => Promise<void>;
  fetchAuth: () => Promise<void>;
  loadSettings: () => Promise<void>;
  fetchServers: () => Promise<void>;
  fetchSystemInfo: () => Promise<void>;
  fetchVpnState: () => Promise<void>;
  refreshAuthProfile: () => Promise<void>;
  getSettings: () => AppSettings;
  getAuthState: () => AuthState;
  getVpnState: () => VpnState;
  connectVpn: (region: string, gamePresets: string[]) => Promise<void>;
  checkForUpdates: (
    showNoUpdatesMessage: boolean,
    autoInstall?: boolean,
  ) => Promise<void>;
};

async function safeAwait(label: string, task: () => Promise<void>) {
  try {
    await task();
  } catch (error) {
    reportError(`Bootstrap step failed: ${label}`, error, {
      dedupeKey: `bootstrap-${label}`,
    });
  }
}

export async function runAppBootstrap(deps: AppBootstrapDeps) {
  // Event listeners must not block fetchers — a failed listen() registration
  // cannot be allowed to keep the spinner stuck forever.
  await safeAwait("initEventListeners", deps.initEventListeners);

  // allSettled so one failing IPC call cannot abort the others. fetchAuth in
  // particular MUST run to completion so isLoading flips to false.
  await Promise.allSettled([
    deps.fetchAuth(),
    deps.loadSettings(),
    deps.fetchServers(),
    deps.fetchSystemInfo(),
    deps.fetchVpnState(),
  ]);

  const authState = deps.getAuthState();
  if (authState === "logged_in") {
    await safeAwait("refreshAuthProfile", deps.refreshAuthProfile);
    await Promise.allSettled([deps.fetchAuth(), deps.fetchVpnState()]);
  }

  const loadedSettings = deps.getSettings();
  if (
    shouldAutoReconnectOnLaunch(
      deps.getAuthState(),
      deps.getVpnState(),
      loadedSettings,
    )
  ) {
    void deps.connectVpn(loadedSettings.selected_region, ["roblox"]);
  }

  if (loadedSettings.update_settings.auto_check) {
    void deps.checkForUpdates(false, true);
  }
}
