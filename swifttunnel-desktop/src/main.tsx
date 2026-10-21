import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { installWebviewLockdown, shouldLockDown } from "./lib/webviewLockdown";
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
}

const root = ReactDOM.createRoot(document.getElementById("root")!);

async function mountWindow() {
  if (import.meta.env.DEV && new URLSearchParams(window.location.search).has("game-preview")) {
    const { GamePreview } = await import("./lib/GamePreview");
    root.render(<GamePreview />);
  } else if (isStatsOverlay) {
    // Do not parse the full shell, auth/VPN stores, repair or launcher pages
    // in a second renderer just to display a small bar of supplied values.
    const { OverlayStatsBar } = await import("./components/ingame/OverlayStatsBar");
    root.render(<React.StrictMode><OverlayStatsBar /></React.StrictMode>);
  } else {
    const { MainWindow, prepareMainWindow } = await import("./MainWindow");
    prepareMainWindow();
    root.render(<React.StrictMode><MainWindow /></React.StrictMode>);
  }
}

void mountWindow().catch(error => {
  console.error("SwiftTunnel window could not load", error);
  if (isStatsOverlay) {
    void getCurrentWindow().hide().catch(() => {});
  } else {
    root.render(<p role="alert" className="p-6 text-text-primary">
      SwiftTunnel could not open. Close the app and try again.
    </p>);
  }
});
