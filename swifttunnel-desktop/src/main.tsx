import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { RamOverlay } from "./components/overlay/RamOverlay";
import { OverlayStatsBar } from "./components/ingame/OverlayStatsBar";
import { installWebviewLockdown, shouldLockDown } from "./lib/webviewLockdown";
import { installAnimationIdle } from "./lib/animationIdle";
import { MotionConfig } from "framer-motion";
import { useSettingsStore } from "./stores/settingsStore";
import "./styles/globals.css";

// Right-click and F12 otherwise expose the page context menu and developer
// tools, which is how a shipped app gives away that it is a webview. Applied
// to every window, overlays included, and only in release builds.
if (shouldLockDown(import.meta.env.DEV)) {
  installWebviewLockdown();
}

// The same bundle serves the main window plus two always-on-top overlay windows
// (see tauri.conf.json): "overlay" = the RAM-freed toast, "overlay-stats" = the
// in-game stats bar. Branch on the window label.
let label = "main";
try {
  label = getCurrentWindow().label;
} catch {
  label = "main";
}
const isOverlay = label === "overlay";
const isStatsOverlay = label === "overlay-stats";

if (isOverlay || isStatsOverlay) {
  // Let the game show through: no opaque page background behind the overlay.
  document.documentElement.style.background = "transparent";
  document.body.style.background = "transparent";
  const root = document.getElementById("root");
  if (root) root.style.background = "transparent";
} else {
  // Main window only. The overlays are never focused by design, so pausing
  // their motion on blur would freeze the one surface meant to animate while
  // you are looking at the game.
  installAnimationIdle({
    isIdleEnabled: () =>
      useSettingsStore.getState().settings.idle_when_unfocused,
  });
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MotionConfig reducedMotion="user">
    {isOverlay ? (
      <RamOverlay />
    ) : isStatsOverlay ? (
      <OverlayStatsBar />
    ) : (
      <App />
    )}
    </MotionConfig>
  </React.StrictMode>,
);
