import { useEffect, useState, type ReactNode } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useBoostStore } from "../../stores/boostStore";
import { useAuthStore } from "../../stores/authStore";
import { getLatencyColor } from "../../lib/utils";
import { StatusChip } from "./StatusChip";
import { LanguageSelector } from "./LanguageSelector";
import { navItemFor } from "./nav";

export function TopBar() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const setTab = useSettingsStore((s) => s.setTab);
  const vpnState = useVpnStore((s) => s.state);
  const ping = useVpnStore((s) => s.ping);
  const robloxRunning = useBoostStore((s) => s.robloxRunning);
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const email = useAuthStore((s) => s.email);

  const item = navItemFor(activeTab);
  const isConnected = vpnState === "connected";
  const initial = email?.[0]?.toUpperCase() || "?";
  const [isMaximized, setIsMaximized] = useState(false);

  // Keep the game-status indicator live on every tab (metrics is a cheap local
  // call). 4s is plenty for a "is Roblox open yet" signal.
  useEffect(() => {
    void fetchMetrics();
    const id = window.setInterval(() => void fetchMetrics(), 4000);
    return () => window.clearInterval(id);
  }, [fetchMetrics]);

  useEffect(() => {
    const appWindow = getCurrentWindow();
    let unlisten: (() => void) | undefined;

    const syncMaximizedState = () => {
      void appWindow
        .isMaximized()
        .then(setIsMaximized)
        .catch(() => undefined);
    };

    syncMaximizedState();
    void appWindow.onResized(syncMaximizedState).then((stopListening) => {
      unlisten = stopListening;
    });

    return () => unlisten?.();
  }, []);

  const minimizeWindow = async () => {
    // Just minimize. The previous version called center() first, which forces
    // the window to show/position itself and races the minimize, so it never
    // fully dropped to the taskbar. Windows already remembers a maximized
    // window's state across a minimize, so no unmaximize dance is needed.
    await getCurrentWindow().minimize();
  };

  const toggleMaximize = async () => {
    const appWindow = getCurrentWindow();
    if (await appWindow.isMaximized()) {
      await appWindow.unmaximize();
      await appWindow.center();
      setIsMaximized(false);
      return;
    }

    await appWindow.maximize();
    setIsMaximized(true);
  };

  return (
    <header
      data-tauri-drag-region
      className="flex shrink-0 items-center justify-between gap-4 px-5"
      style={{
        height: "var(--spacing-topbar)",
        backgroundColor: "var(--color-bg-sidebar)",
      }}
    >
      <div data-tauri-drag-region className="flex min-w-0 items-center gap-3.5">
        <div className="min-w-0">
          <h1
            className="truncate text-[13.5px] font-semibold leading-none text-text-primary"
            style={{ letterSpacing: "-0.01em" }}
          >
            {item.label}
          </h1>
          <p className="mt-1.5 truncate text-[10.5px] leading-none text-text-muted">
            {item.description}
          </p>
        </div>

        {/* Game-status chip — Medal's "Waiting For Game": solid gamepad, no
            border, subtle inset pill. */}
        <div
          className="hidden items-center gap-2 rounded-[9px] px-3 py-1.5 sm:flex"
          style={{ backgroundColor: "var(--color-bg-base)" }}
        >
          <svg
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill={
              robloxRunning
                ? "var(--color-text-secondary)"
                : "var(--color-text-muted)"
            }
            aria-hidden
          >
            <path d="M15 5H9a7 7 0 0 0-7 7 4 4 0 0 0 7.24 2.35A2 2 0 0 1 10.83 15h2.34a2 2 0 0 1 1.59.79A4 4 0 1 0 22 12a7 7 0 0 0-7-7ZM9 12H8v1a1 1 0 1 1-2 0v-1H5a1 1 0 1 1 0-2h1V9a1 1 0 1 1 2 0v1h1a1 1 0 1 1 0 2Zm6.5.5a1.25 1.25 0 1 1 1.25-1.25A1.25 1.25 0 0 1 15.5 12.5Zm2.5-3a1.25 1.25 0 1 1 1.25-1.25A1.25 1.25 0 0 1 18 9.5Z" />
          </svg>
          <span
            className="text-[11px] font-medium leading-none"
            style={{
              color: robloxRunning
                ? "var(--color-text-secondary)"
                : "var(--color-text-muted)",
            }}
          >
            {robloxRunning ? "Roblox running" : "Waiting for Roblox"}
          </span>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {/* Search — opens the command palette (same Ctrl+K target). */}
        <button
          title="Search (Ctrl+K)"
          aria-label="Search"
          onClick={() =>
            window.dispatchEvent(new Event("toggle-command-palette"))
          }
          className="flex h-9 w-9 items-center justify-center rounded-full transition-[background-color] duration-150 hover:bg-[color:var(--color-bg-hover)]"
          style={{ color: "var(--color-text-muted)" }}
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="11" cy="11" r="7" />
            <path d="m21 21-4.3-4.3" />
          </svg>
        </button>

        {isConnected && ping !== null && (
          <div
            className="flex items-center gap-1.5 rounded-[5px] px-2.5 py-1.5"
            style={{
              backgroundColor: "var(--color-bg-base)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            <span
              className="lcd-readout text-[11px] font-medium leading-none"
              style={{ color: getLatencyColor(ping) }}
            >
              {ping}
            </span>
            <span className="text-[9.5px] leading-none text-text-dimmed">
              ms
            </span>
          </div>
        )}
        <StatusChip state={vpnState} />

        {/* Language — translate the whole UI to any language (Medal-style). */}
        <LanguageSelector />

        {/* Profile avatar — moved from the sidebar to the top-right (Medal). */}
        <button
          onClick={() => setTab("settings")}
          title={email ?? "Account"}
          aria-label="Account settings"
          className="neon-edge ml-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-[12px] font-semibold transition-[filter] duration-150 hover:brightness-110"
          style={{
            background:
              "linear-gradient(135deg, var(--color-bg-elevated), var(--color-bg-active))",
            color: "var(--color-text-primary)",
            border: "1px solid var(--color-border-default)",
          }}
        >
          {initial}
        </button>

        {/* Window controls — custom titlebar (window is frameless, Medal-style). */}
        <div
          className="-mr-5 ml-1 flex items-stretch"
          style={{ height: "var(--spacing-topbar)" }}
        >
          <span
            className="mx-1.5 self-center"
            style={{
              width: 1,
              height: 18,
              backgroundColor: "var(--color-border-strong)",
            }}
          />
          <WindowButton
            label="Minimize"
            onClick={() => void minimizeWindow()}
          >
            <svg
              width="11"
              height="11"
              viewBox="0 0 12 12"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.1"
              strokeLinecap="round"
            >
              <path d="M2 6h8" />
            </svg>
          </WindowButton>
          <WindowButton
            label={isMaximized ? "Restore" : "Maximize"}
            onClick={() => void toggleMaximize()}
          >
            {isMaximized ? (
              <svg
                width="11"
                height="11"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.05"
              >
                <rect x="2.5" y="3.5" width="6" height="6" rx="0.5" />
                <path d="M4 3.5V2.5h5.5V8H8.5" />
              </svg>
            ) : (
              <svg
                width="11"
                height="11"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.05"
              >
                <rect x="2.25" y="2.25" width="7.5" height="7.5" rx="0.6" />
              </svg>
            )}
          </WindowButton>
          <WindowButton
            label="Close"
            danger
            onClick={() => void getCurrentWindow().close()}
          >
            <svg
              width="11"
              height="11"
              viewBox="0 0 12 12"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.15"
              strokeLinecap="round"
            >
              <path d="M2.5 2.5l7 7M9.5 2.5l-7 7" />
            </svg>
          </WindowButton>
        </div>
      </div>
    </header>
  );
}

function WindowButton({
  children,
  onClick,
  label,
  danger,
}: {
  children: ReactNode;
  onClick: () => void;
  label: string;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={label}
      aria-label={label}
      className={`flex h-full w-[44px] items-center justify-center transition-colors duration-100 ${
        danger
          ? "hover:bg-[#e5484d] hover:text-white"
          : "hover:bg-[color:var(--color-bg-hover)]"
      }`}
      style={{ color: "var(--color-text-muted)" }}
    >
      {children}
    </button>
  );
}
