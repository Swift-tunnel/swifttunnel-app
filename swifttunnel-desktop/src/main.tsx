import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { RamOverlay } from "./components/overlay/RamOverlay";
import { OverlayStatsBar } from "./components/ingame/OverlayStatsBar";
import "./styles/globals.css";

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
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    {isOverlay ? (
      <RamOverlay />
    ) : isStatsOverlay ? (
      <OverlayStatsBar />
    ) : (
      <App />
    )}
  </React.StrictMode>,
);
