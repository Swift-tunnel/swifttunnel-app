import { useEffect } from "react";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Sidebar } from "./components/common/Sidebar";
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

function TabContent() {
  const activeTab = useSettingsStore((s) => s.activeTab);

  switch (activeTab) {
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

function AppShell() {
  return (
    <div className="flex h-screen w-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-[var(--spacing-content)]">
        <TabContent />
      </main>
    </div>
  );
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
  const syncActiveFromSettings = useBoostStore((s) => s.syncActiveFromSettings);
  const fetchVpnState = useVpnStore((s) => s.fetchState);
  const checkForUpdates = useUpdaterStore((s) => s.checkForUpdates);

  useEffect(() => {
    let disposed = false;

    const init = async () => {
      await initEventListeners();
      await Promise.all([
        fetchAuth(),
        loadSettings(),
        fetchServers(),
        fetchSystemInfo(),
        fetchVpnState(),
      ]);

      if (!disposed) {
        const loadedSettings = useSettingsStore.getState().settings;
        syncActiveFromSettings(loadedSettings.optimizations_active);
        if (loadedSettings.update_settings.auto_check) {
          void checkForUpdates(false);
        }
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
    syncActiveFromSettings,
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
        const [pos, size, maximized] = await Promise.all([
          appWindow.outerPosition(),
          appWindow.outerSize(),
          appWindow.isMaximized(),
        ]);
        if (disposed) return;

        updateSettings({
          window_state: {
            x: pos.x,
            y: pos.y,
            width: size.width,
            height: size.height,
            maximized,
          },
        });
        await saveSettings();
      } catch {
        // ignore transient window state errors
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
      const ws = useSettingsStore.getState().settings.window_state;
      try {
        if (disposed) return;

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
      } catch {
        // ignore restore errors for invalid/off-screen saved state
      }

      if (disposed) return;

      addUnlistener(await appWindow.onMoved(() => schedulePersist()));
      addUnlistener(await appWindow.onResized(() => schedulePersist()));
      addUnlistener(
        await appWindow.onCloseRequested(async (event) => {
          if (disposed) return;
          const current = useSettingsStore.getState().settings;
          if (!current.minimize_to_tray) return;
          event.preventDefault();
          await persistWindowState();
          await appWindow.hide();
        }),
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

      const map: Record<string, "connect" | "boost" | "network" | "settings"> =
        {
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

  return <AppShell />;
}

export default App;
