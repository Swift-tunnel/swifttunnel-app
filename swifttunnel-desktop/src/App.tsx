import { useEffect } from "react";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import {
  availableMonitors,
  getCurrentWindow,
  primaryMonitor,
} from "@tauri-apps/api/window";
import { AppShell } from "./components/shell/AppShell";
import { LoginScreen } from "./components/auth/LoginScreen";
import { BannedScreen } from "./components/auth/BannedScreen";
import { ConnectTab } from "./components/connect/ConnectTab";
import { OptimizationTab } from "./components/optimization/OptimizationTab";
import { GamesTab } from "./components/games/GamesTab";
import { InGameTab } from "./components/ingame/InGameTab";
import { NetworkTab } from "./components/network/NetworkTab";
import { RepairTab } from "./components/repair/RepairTab";
import { SettingsTab } from "./components/settings/SettingsTab";
import { useAuthStore } from "./stores/authStore";
import { useSettingsStore } from "./stores/settingsStore";
import { useServerStore } from "./stores/serverStore";
import { useBoostStore } from "./stores/boostStore";
import { useVpnStore } from "./stores/vpnStore";
import { useUpdaterStore } from "./stores/updaterStore";
import { cleanupEventListeners, initEventListeners } from "./lib/events";
import { createCloseToTrayHandler } from "./lib/closeToTray";
import { runAppBootstrap } from "./lib/appBootstrap";
import { useAutoRamClean } from "./lib/useAutoRamClean";
import { reportError } from "./lib/errors";
import { systemLaunchedFromStartup } from "./lib/commands";
import {
  ensureWindowStateVisible,
  isPersistableWindowSize,
  normalizeWindowState,
} from "./lib/windowState";
import type { TabId } from "./lib/types";

function tabComponent(tab: TabId) {
  switch (tab) {
    case "connect":
      return <ConnectTab />;
    case "optimization":
      return <OptimizationTab />;
    case "games":
      return <GamesTab />;
    case "ingame":
      return <InGameTab />;
    case "network":
      return <NetworkTab />;
    case "repair":
      return <RepairTab />;
    case "settings":
      return <SettingsTab />;
    default:
      return <ConnectTab />;
  }
}

function App() {
  const authState = useAuthStore((s) => s.state);
  const isLoading = useAuthStore((s) => s.isLoading);
  const fetchAuth = useAuthStore((s) => s.fetchState);
  const refreshAuthProfile = useAuthStore((s) => s.refreshProfile);
  const isSettingsLoaded = useSettingsStore((s) => s.isLoaded);
  const setTab = useSettingsStore((s) => s.setTab);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const loadSettings = useSettingsStore((s) => s.load);
  const fetchServers = useServerStore((s) => s.fetchList);
  const fetchSystemInfo = useBoostStore((s) => s.fetchSystemInfo);
  const fetchVpnState = useVpnStore((s) => s.fetchState);
  const connectVpn = useVpnStore((s) => s.connect);
  const checkForUpdates = useUpdaterStore((s) => s.checkForUpdates);

  // Auto-clean RAM on game launch + show the in-game overlay (opt-in).
  useAutoRamClean();

  useEffect(() => {
    let disposed = false;

    // Show the window ASAP, independent of bootstrap. Bootstrap does several
    // network calls (auth, servers, profile); waiting for it to finish before
    // showing made a slow first launch look like nothing happened, so the user
    // had to launch a second time (single-instance then revealed the already-
    // running window). Showing early shows the loading spinner immediately.
    const showWindowEarly = async () => {
      try {
        const fromStartup = await systemLaunchedFromStartup();
        if (!fromStartup && !disposed) {
          await getCurrentWindow().show();
        }
      } catch {
        if (!disposed) {
          try {
            await getCurrentWindow().show();
          } catch {}
        }
      }
    };

    // Safety net: if the auth fetch never clears the spinner (wedged IPC), drop
    // out of the loading screen after 8s so the window isn't a black void.
    const spinnerSafetyTimer = window.setTimeout(() => {
      if (disposed) return;
      if (useAuthStore.getState().isLoading) {
        useAuthStore.setState({
          isLoading: false,
          error:
            "Could not reach the SwiftTunnel backend. Try restarting the app or running Repair.",
        });
      }
    }, 8000);

    const init = async () => {
      void showWindowEarly();

      try {
        await runAppBootstrap({
          initEventListeners,
          fetchAuth,
          loadSettings,
          fetchServers,
          fetchSystemInfo,
          fetchVpnState,
          refreshAuthProfile,
          getSettings: () => useSettingsStore.getState().settings,
          getAuthState: () => useAuthStore.getState().state,
          getVpnState: () => useVpnStore.getState().state,
          connectVpn,
          checkForUpdates,
        });
      } catch (error) {
        reportError("App bootstrap threw", error, {
          dedupeKey: "app-bootstrap-init",
        });
        if (!disposed && useAuthStore.getState().isLoading) {
          try {
            await fetchAuth();
          } catch {
            useAuthStore.setState({ isLoading: false });
          }
        }
      } finally {
        window.clearTimeout(spinnerSafetyTimer);
      }

      if (disposed) {
        void cleanupEventListeners();
      }
    };

    void init();

    return () => {
      disposed = true;
      window.clearTimeout(spinnerSafetyTimer);
      void cleanupEventListeners();
    };
  }, [
    fetchAuth,
    loadSettings,
    fetchServers,
    fetchSystemInfo,
    fetchVpnState,
    refreshAuthProfile,
    connectVpn,
    checkForUpdates,
  ]);

  useEffect(() => {
    if (!isSettingsLoaded) return;

    const appWindow = getCurrentWindow();
    let disposed = false;
    let saveTimer: number | null = null;
    const unlisteners: Array<() => void> = [];

    const addUnlistener = (unlisten: () => void) => {
      if (disposed) {
        unlisten();
        return;
      }
      unlisteners.push(unlisten);
    };

    const persistWindowState = async () => {
      if (disposed) return;

      try {
        const [pos, size, maximized, minimized] = await Promise.all([
          appWindow.outerPosition(),
          appWindow.outerSize(),
          appWindow.isMaximized(),
          appWindow.isMinimized(),
        ]);
        if (disposed) return;
        if (minimized) return;
        if (!isPersistableWindowSize(size.width, size.height)) return;

        const nextWindowState = normalizeWindowState({
          x: pos.x,
          y: pos.y,
          width: size.width,
          height: size.height,
          maximized,
        });

        updateSettings({
          window_state: nextWindowState,
        });
        await saveSettings();
      } catch (error) {
        reportError("Failed to persist window state", error, {
          dedupeKey: "app-window-persist",
        });
      }
    };

    const schedulePersist = () => {
      if (disposed) return;

      if (saveTimer !== null) {
        window.clearTimeout(saveTimer);
      }
      saveTimer = window.setTimeout(() => {
        void persistWindowState();
      }, 300);
    };

    const initWindowState = async () => {
      let ws = normalizeWindowState(
        useSettingsStore.getState().settings.window_state,
      );
      try {
        if (disposed) return;

        try {
          const [monitors, primary] = await Promise.all([
            availableMonitors(),
            primaryMonitor(),
          ]);

          const workAreas = monitors.map((monitor) => ({
            x: monitor.workArea.position.x,
            y: monitor.workArea.position.y,
            width: monitor.workArea.size.width,
            height: monitor.workArea.size.height,
          }));

          const primaryWorkArea = primary
            ? {
                x: primary.workArea.position.x,
                y: primary.workArea.position.y,
                width: primary.workArea.size.width,
                height: primary.workArea.size.height,
              }
            : undefined;

          const next = ensureWindowStateVisible(ws, workAreas, {
            primaryMonitor: primaryWorkArea,
          });

          if (next.x !== ws.x || next.y !== ws.y) {
            ws = next;
            updateSettings({ window_state: ws });
            await saveSettings();
          } else {
            ws = next;
          }
        } catch (error) {
          reportError("Failed to inspect monitor work areas", error, {
            dedupeKey: "app-window-monitors",
          });
        }

        if (ws.width > 0 && ws.height > 0) {
          await appWindow.setSize(
            new PhysicalSize(Math.round(ws.width), Math.round(ws.height)),
          );
        }
        if (ws.x !== null && ws.y !== null) {
          await appWindow.setPosition(
            new PhysicalPosition(Math.round(ws.x), Math.round(ws.y)),
          );
        }
        if (ws.maximized) {
          await appWindow.maximize();
        }
      } catch (error) {
        reportError("Failed to restore window state", error, {
          dedupeKey: "app-window-restore",
        });
      }

      if (disposed) return;

      addUnlistener(await appWindow.onMoved(() => schedulePersist()));
      addUnlistener(await appWindow.onResized(() => schedulePersist()));
      addUnlistener(
        await appWindow.onCloseRequested(
          createCloseToTrayHandler({
            persistWindowState,
            hide: () => appWindow.hide(),
            close: () => appWindow.close(),
            shouldMinimizeToTray: () =>
              useSettingsStore.getState().settings.minimize_to_tray,
            isDisposed: () => disposed,
          }),
        ),
      );
    };

    void initWindowState();

    return () => {
      disposed = true;
      if (saveTimer !== null) {
        window.clearTimeout(saveTimer);
      }
      for (const unlisten of unlisteners) {
        unlisten();
      }
    };
  }, [isSettingsLoaded, saveSettings, updateSettings]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey) {
        return;
      }

      const target = event.target as HTMLElement | null;
      if (
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target?.isContentEditable
      ) {
        return;
      }

      const map: Record<string, TabId> = {
        "1": "connect",
        "2": "optimization",
        "3": "games",
        "4": "network",
        "5": "repair",
        "6": "settings",
        "7": "ingame",
      };
      const tab = map[event.key];
      if (!tab) return;

      event.preventDefault();
      setTab(tab);
      void saveSettings();
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [setTab, saveSettings]);

  if (isLoading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-bg-base">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent-primary border-t-transparent" />
      </div>
    );
  }

  if (authState === "banned") {
    return <BannedScreen />;
  }

  if (authState !== "logged_in") {
    return <LoginScreen />;
  }

  return <AppShell>{(tab) => tabComponent(tab as TabId)}</AppShell>;
}

export default App;
