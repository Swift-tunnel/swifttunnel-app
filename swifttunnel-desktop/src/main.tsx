import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { OverlayStatsBar } from "./components/ingame/OverlayStatsBar";
import { installWebviewLockdown, shouldLockDown } from "./lib/webviewLockdown";
import { installAnimationIdle } from "./lib/animationIdle";
import { MotionConfig } from "framer-motion";
import { useSettingsStore } from "./stores/settingsStore";
import { trackTunnelSessions } from "./stores/sessionStatsStore";
import "./styles/globals.css";

// Right-click and F12 otherwise expose the page context menu and developer
// tools, which is how a shipped app gives away that it is a webview. Applied
// to every window, overlays included, and only in release builds.
if (shouldLockDown(import.meta.env.DEV)) {
  installWebviewLockdown();
}

// The entry serves the main window and the in-game stats bar.
let label = "main";
try {
  label = getCurrentWindow().label;
} catch {
  label = "main";
}
const isStatsOverlay = label === "overlay-stats";

if (isStatsOverlay) {
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
  // Session ping stats for the Connect tab, counted whichever tab is open.
  trackTunnelSessions();
}

if (import.meta.env.DEV && new URLSearchParams(window.location.search).has("game-preview")) {
  void import("./lib/GamePreview").then(({ GamePreview }) => ReactDOM.createRoot(document.getElementById("root")!).render(<GamePreview />));
} else {
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MotionConfig reducedMotion="user">
    {isStatsOverlay ? (
      <OverlayStatsBar />
    ) : (
      <App />
    )}
    </MotionConfig>
  </React.StrictMode>,
);

}
