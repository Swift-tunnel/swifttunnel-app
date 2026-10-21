import App from "./App";
import { AppMotion } from "./components/common/AppMotion";
import { installAnimationIdle } from "./lib/animationIdle";
import { useSettingsStore } from "./stores/settingsStore";
import { trackTunnelSessions } from "./stores/sessionStatsStore";

export function prepareMainWindow() {
  installAnimationIdle({
    isIdleEnabled: () => useSettingsStore.getState().settings.idle_when_unfocused,
  });
  trackTunnelSessions();
}

export function MainWindow() {
  return <AppMotion><App /></AppMotion>;
}
