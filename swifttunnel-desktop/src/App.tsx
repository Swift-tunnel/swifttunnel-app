import { useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import {
  availableMonitors,
  getCurrentWindow,
  primaryMonitor,
} from "@tauri-apps/api/window";
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
import { createCloseToTrayHandler } from "./lib/closeToTray";
import { runAppBootstrap } from "./lib/appBootstrap";
import { reportError } from "./lib/errors";
import { ToastContainer } from "./components/common/Toast";
import {
  ensureWindowStateVisible,
  isPersistableWindowSize,
  normalizeWindowState,
} from "./lib/windowState";
import type { BindingCandidateInfo, TabId } from "./lib/types";

function BindingCandidateCard({
  candidate,
  recommended,
  onChoose,
}: {
  candidate: BindingCandidateInfo;
  recommended: boolean;
  onChoose: (guid: string) => void;
}) {
  const label =
    candidate.friendly_name || candidate.description || candidate.guid;
  const tags = [
    candidate.kind,
    candidate.is_up ? "up" : "down",
    candidate.is_default_route ? "default" : null,
    recommended ? "recommended" : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <button
      type="button"
      onClick={() => onChoose(candidate.guid)}
      className="w-full rounded-xl border border-border-subtle bg-bg-card px-4 py-3 text-left transition-colors hover:bg-bg-hover"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-medium text-text-primary">
            {label}
          </div>
          <div className="mt-1 text-xs text-text-muted">{tags}</div>
          <div className="mt-1 text-[11px] text-text-dimmed">
            {candidate.stage.replace(/_/g, " ")} · {candidate.reason}
          </div>
        </div>
        <span className="shrink-0 text-xs text-accent-secondary">Use</span>
      </div>
    </button>
  );
}

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

function TabContent() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, 0);
  }, [activeTab]);

  return (
    <div
      ref={scrollRef}
      className="flex-1 overflow-y-auto p-[var(--spacing-content)]"
    >
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
        >
          {tabComponent(activeTab)}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

function AppShell() {
  const bindingPreflight = useVpnStore((s) => s.bindingPreflight);
  const resumeConnectWithAdapter = useVpnStore(
    (s) => s.resumeConnectWithAdapter,
  );
  const dismissBindingChooser = useVpnStore((s) => s.dismissBindingChooser);

  return (
    <>
      <div className="flex h-screen w-screen overflow-hidden">
        <Sidebar />
        <TabContent />
      </div>
      <ToastContainer />
      {bindingPreflight && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(6,10,18,0.76)] p-4 backdrop-blur-sm">
          <div className="w-full max-w-xl rounded-2xl border border-border-subtle bg-bg-base p-5 shadow-2xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-lg font-semibold text-text-primary">
                  Choose Network Adapter
                </div>
                <div className="mt-1 text-sm text-text-muted">
                  SwiftTunnel needs a one-time split tunnel choice for this
                  network.
                </div>
              </div>
              <button
                type="button"
                onClick={dismissBindingChooser}
                className="text-sm text-text-muted transition-opacity hover:opacity-80"
              >
                Close
              </button>
            </div>

            <div className="mt-4 rounded-xl border border-border-subtle bg-bg-card px-4 py-3 text-sm text-text-secondary">
              <div>{bindingPreflight.reason}</div>
              <div className="mt-2 text-xs text-text-dimmed">
                Route source: {bindingPreflight.route_resolution_source}
                {bindingPreflight.route_resolution_target_ip
                  ? ` (${bindingPreflight.route_resolution_target_ip})`
                  : ""}
                {" · "}
                ifIndex: {bindingPreflight.resolved_if_index ?? "n/a"}
              </div>
            </div>

            <div className="mt-4 space-y-3">
              {bindingPreflight.candidates.map((candidate) => (
                <BindingCandidateCard
                  key={
                    candidate.guid ||
                    `${candidate.friendly_name}-${candidate.if_index ?? "na"}`
                  }
                  candidate={candidate}
                  recommended={
                    candidate.guid === bindingPreflight.recommended_guid
                  }
                  onChoose={(guid) => void resumeConnectWithAdapter(guid)}
                />
              ))}
            </div>
          </div>
        </div>
      )}
    </>
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
  const fetchVpnState = useVpnStore((s) => s.fetchState);
  const connectVpn = useVpnStore((s) => s.connect);
  const checkForUpdates = useUpdaterStore((s) => s.checkForUpdates);

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
