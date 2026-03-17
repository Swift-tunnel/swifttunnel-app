import type { AppSettings, AuthState, VpnState } from "./types";
import { shouldAutoReconnectOnLaunch } from "./startup";

type AppBootstrapDeps = {
  initEventListeners: () => Promise<void>;
  fetchAuth: () => Promise<void>;
  loadSettings: () => Promise<void>;
  fetchServers: () => Promise<void>;
  fetchSystemInfo: () => Promise<void>;
  fetchVpnState: () => Promise<void>;
  getSettings: () => AppSettings;
  getAuthState: () => AuthState;
  getVpnState: () => VpnState;
  connectVpn: (region: string, gamePresets: string[]) => Promise<void>;
  checkForUpdates: (showNoUpdatesMessage: boolean, autoInstall?: boolean) => Promise<void>;
};

export async function runAppBootstrap(deps: AppBootstrapDeps) {
  await deps.initEventListeners();
  await Promise.all([
    deps.fetchAuth(),
    deps.loadSettings(),
    deps.fetchServers(),
    deps.fetchSystemInfo(),
    deps.fetchVpnState(),
  ]);

  const loadedSettings = deps.getSettings();
  if (
    shouldAutoReconnectOnLaunch(
      deps.getAuthState(),
      deps.getVpnState(),
      loadedSettings,
    )
  ) {
    void deps.connectVpn(
      loadedSettings.selected_region,
      loadedSettings.selected_game_presets,
    );
  }

  if (loadedSettings.update_settings.auto_check) {
    void deps.checkForUpdates(false, true);
  }
}
