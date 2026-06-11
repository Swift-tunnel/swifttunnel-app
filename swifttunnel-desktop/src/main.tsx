import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { RamOverlay } from "./components/overlay/RamOverlay";
import "./styles/globals.css";

// The same bundle serves both the main window and the always-on-top "overlay"
// window (see tauri.conf.json). Branch on the window label so the overlay
// renders only the lightweight, transparent toast.
let isOverlay = false;
try {
  isOverlay = getCurrentWindow().label === "overlay";
} catch {
  isOverlay = false;
}

if (isOverlay) {
  // Let the game show through: no opaque page background behind the toast.
  document.documentElement.style.background = "transparent";
  document.body.style.background = "transparent";
  const root = document.getElementById("root");
  if (root) root.style.background = "transparent";
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>{isOverlay ? <RamOverlay /> : <App />}</React.StrictMode>,
);
