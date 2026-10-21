import App from "./App";
import { MotionConfig } from "framer-motion";
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
  return <MotionConfig reducedMotion="user"><App /></MotionConfig>;
}
