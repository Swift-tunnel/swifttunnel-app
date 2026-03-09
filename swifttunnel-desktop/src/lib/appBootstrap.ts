import type { AppSettings, AuthState, Config, VpnState } from "./types";
import { shouldAutoReconnectOnLaunch } from "./startup";
import { reportError } from "./errors";

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
  applyBoostConfig: (config: Config) => Promise<void>;
  connectVpn: (region: string, gamePresets: string[]) => Promise<void>;
  checkForUpdates: (showNoUpdatesMessage: boolean) => Promise<void>;
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

  try {
    await deps.applyBoostConfig(loadedSettings.config);
  } catch (error) {
    reportError("Failed to apply boost config on startup", error);
  }

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
    void deps.checkForUpdates(false);
  }
}
