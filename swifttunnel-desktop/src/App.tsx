import { useEffect } from "react";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import {
  availableMonitors,
  getCurrentWindow,
  primaryMonitor,
} from "@tauri-apps/api/window";
import { AppShell } from "./components/shell/AppShell";
import { LoginScreen } from "./components/auth/LoginScreen";
import { ConnectTab } from "./components/connect/ConnectTab";
import { BoostTab } from "./components/boost/BoostTab";
import { NetworkTab } from "./components/network/NetworkTab";
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
import { reportError } from "./lib/errors";
import {
  installRendererActivityListeners,
  useRendererActivityStore,
} from "./lib/rendererActivity";
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
    case "boost":
      return <BoostTab />;
    case "network":
      return <NetworkTab />;
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
  const rendererActive = useRendererActivityStore((s) => s.isActive);
  const setWindowVisible = useRendererActivityStore((s) => s.setWindowVisible);

  useEffect(() => installRendererActivityListeners(), []);

  useEffect(() => {
    document.documentElement.dataset.rendererActive = rendererActive
      ? "true"
      : "false";
  }, [rendererActive]);

  useEffect(() => {
    let disposed = false;

    const init = async () => {
      await runAppBootstrap({
        initEventListeners,
        fetchAuth,
        loadSettings,
        fetchServers,
        fetchSystemInfo,
        fetchVpnState,
        getSettings: () => useSettingsStore.getState().settings,
        getAuthState: () => useAuthStore.getState().state,
        getVpnState: () => useVpnStore.getState().state,
        connectVpn,
        checkForUpdates,
      });

      if (!disposed) {
        try {
          const fromStartup = await systemLaunchedFromStartup();
          if (!fromStartup && !disposed) {
            await getCurrentWindow().show();
            setWindowVisible(true);
          }
        } catch {
          if (!disposed) {
            await getCurrentWindow().show();
            setWindowVisible(true);
          }
        }
      }

      if (disposed) {
        void cleanupEventListeners();
      }
    };

    void init();

    return () => {
      disposed = true;
      void cleanupEventListeners();
    };
  }, [
    fetchAuth,
    loadSettings,
    fetchServers,
    fetchSystemInfo,
    fetchVpnState,
    connectVpn,
    checkForUpdates,
    setWindowVisible,
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
            onHiddenToTray: () => setWindowVisible(false),
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
        "2": "boost",
        "3": "network",
        "4": "settings",
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

  if (authState !== "logged_in") {
    return <LoginScreen />;
  }

  return <AppShell>{(tab) => tabComponent(tab as TabId)}</AppShell>;
}

export default App;
