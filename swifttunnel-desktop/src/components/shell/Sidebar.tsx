import { useEffect, useState } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import type { TabId, VpnState } from "../../lib/types";
import { StatusChip } from "./StatusChip";
import { Tooltip } from "../ui/Tooltip";
import swiftLogo from "../../assets/swift.png";

declare const __APP_VERSION__: string;

const SIDEBAR_COLLAPSED_KEY = "swifttunnel:sidebar-collapsed";
const WIDTH_EXPANDED = "188px";
const WIDTH_COLLAPSED = "56px";

const TABS: { id: TabId; label: string; shortcut: string; icon: string }[] = [
  {
    id: "connect",
    label: "Connect",
    shortcut: "1",
    icon: "M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0 M12 20h.01",
  },
  {
    id: "boost",
    label: "Boost",
    shortcut: "2",
    icon: "M13 2L3 14h9l-1 8 10-12h-9l1-8z",
  },
  {
    id: "network",
    label: "Diagnostics",
    shortcut: "3",
    icon: "M22 12h-4l-3 9L9 3l-3 9H2",
  },
  {
    id: "settings",
    label: "Settings",
    shortcut: "4",
    icon: "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z",
  },
];

function resolveDotColor(state: VpnState): string {
  if (state === "connected") return "var(--color-status-connected)";
  if (state === "error") return "var(--color-status-error)";
  if (state === "disconnected") return "var(--color-status-inactive)";
  return "var(--color-status-warning)";
}

function useCollapsed(): [boolean, (v: boolean) => void] {
  const [collapsed, setCollapsedState] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "1";
  });

  useEffect(() => {
    document.documentElement.style.setProperty(
      "--spacing-sidebar",
      collapsed ? WIDTH_COLLAPSED : WIDTH_EXPANDED,
    );
  }, [collapsed]);

  const setCollapsed = (v: boolean) => {
    setCollapsedState(v);
    try {
      localStorage.setItem(SIDEBAR_COLLAPSED_KEY, v ? "1" : "0");
    } catch {
      // ignore
    }
  };

  return [collapsed, setCollapsed];
}

export function Sidebar() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const setTab = useSettingsStore((s) => s.setTab);
  const vpnState = useVpnStore((s) => s.state);
  const email = useAuthStore((s) => s.email);
  const isTester = useAuthStore((s) => s.isTester);
  const [collapsed, setCollapsed] = useCollapsed();

  const initial = email?.[0]?.toUpperCase() || "?";
  const userLabel = email ? email.split("@")[0] : "Not signed in";
  const dotColor = resolveDotColor(vpnState);
  const isConnected = vpnState === "connected";
  const isTransitioning =
    vpnState !== "connected" &&
    vpnState !== "disconnected" &&
    vpnState !== "error";

  return (
    <nav
      data-tauri-drag-region
      className="relative flex h-full shrink-0 flex-col overflow-hidden border-r"
      style={{
        width: "var(--spacing-sidebar)",
        backgroundColor: "var(--color-bg-sidebar)",
        borderColor: "var(--color-border-subtle)",
        transition: "width 0.18s cubic-bezier(0.4, 0, 0.2, 1)",
      }}
    >
      {/* Brand */}
      <div
        data-tauri-drag-region
        className={`flex items-center ${collapsed ? "justify-center px-2" : "gap-2.5 px-3"} pt-4 pb-3`}
      >
        <img
          src={swiftLogo}
          alt="SwiftTunnel"
          width={28}
          height={28}
          className="shrink-0"
          style={{ objectFit: "contain" }}
        />
        {!collapsed && (
          <div className="min-w-0 flex-1">
            <div className="text-[12.5px] font-semibold leading-none tracking-[-0.01em] text-text-primary">
              SwiftTunnel
            </div>
            <div className="mt-1 font-mono text-[9.5px] leading-none text-text-dimmed">
              v{__APP_VERSION__}
            </div>
          </div>
        )}
        {!collapsed && (
          <CollapseButton collapsed={false} onClick={() => setCollapsed(true)} />
        )}
      </div>

      {/* Status */}
      <div
        className={
          collapsed
            ? "flex justify-center px-2 pb-3"
            : "px-3 pb-3"
        }
      >
        {collapsed ? (
          <Tooltip
            content={
              vpnState === "connected"
                ? "Tunnel active"
                : vpnState === "error"
                  ? "Error"
                  : vpnState === "disconnected"
                    ? "Disconnected"
                    : "Connecting"
            }
            side="right"
            delay={200}
          >
            <div
              className="flex h-7 w-7 items-center justify-center rounded-[5px]"
              style={{
                backgroundColor: "var(--color-bg-base)",
                border: "1px solid var(--color-border-subtle)",
              }}
            >
              <span className="relative flex h-1.5 w-1.5">
                {isConnected && (
                  <span
                    className="absolute inset-0 animate-ping rounded-full opacity-60"
                    style={{ backgroundColor: dotColor }}
                  />
                )}
                <span
                  className="relative h-1.5 w-1.5 rounded-full"
                  style={{
                    backgroundColor: dotColor,
                    boxShadow: isConnected
                      ? "0 0 6px var(--color-status-connected-glow)"
                      : "none",
                    animation: isTransitioning
                      ? "pulse-opacity 1.2s ease-in-out infinite"
                      : "none",
                  }}
                />
              </span>
            </div>
          </Tooltip>
        ) : (
          <StatusChip state={vpnState} full />
        )}
      </div>

      {/* Divider */}
      <div
        className={collapsed ? "mx-2 h-px" : "mx-3 h-px"}
        style={{ backgroundColor: "var(--color-border-subtle)" }}
      />

      {/* Nav */}
      <div
        className={`mt-3 flex flex-1 flex-col gap-0.5 ${collapsed ? "px-2" : "px-2"}`}
      >
        {!collapsed && (
          <div className="mb-1 px-2 text-[9.5px] font-semibold uppercase tracking-[0.12em] text-text-dimmed">
            Menu
          </div>
        )}
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;

          const buttonInner = (
            <>
              {isActive && (
                <span
                  className={
                    collapsed
                      ? "absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2 rounded-r"
                      : "absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-r"
                  }
                  style={{ backgroundColor: "var(--color-accent-primary)" }}
                />
              )}
              <svg
                width="15"
                height="15"
                viewBox="0 0 24 24"
                fill="none"
                stroke={
                  isActive
                    ? "var(--color-accent-secondary)"
                    : "var(--color-text-muted)"
                }
                strokeWidth="1.9"
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{ transition: "stroke 0.1s ease" }}
              >
                <path d={tab.icon} />
              </svg>
              {!collapsed && (
                <>
                  <span
                    className="flex-1 text-[12.5px] font-medium"
                    style={{
                      color: isActive
                        ? "var(--color-text-primary)"
                        : "var(--color-text-secondary)",
                      letterSpacing: "-0.01em",
                      transition: "color 0.1s ease",
                    }}
                  >
                    {tab.label}
                  </span>
                  <span
                    className="rounded-[3px] px-1 py-0.5 font-mono text-[9px] font-medium opacity-0 transition-opacity group-hover:opacity-100"
                    style={{
                      backgroundColor: "var(--color-bg-elevated)",
                      color: "var(--color-text-muted)",
                      letterSpacing: "0.05em",
                    }}
                  >
                    ⌃{tab.shortcut}
                  </span>
                </>
              )}
            </>
          );

          const button = (
            <button
              key={tab.id}
              onClick={() => setTab(tab.id)}
              className={`group relative flex items-center ${collapsed ? "h-9 justify-center" : "gap-2.5 px-2.5 py-1.5"} rounded-[5px] text-left transition-colors duration-100`}
              style={{
                backgroundColor: isActive
                  ? "var(--color-accent-primary-soft-12)"
                  : "transparent",
              }}
              onMouseEnter={(e) => {
                if (!isActive)
                  e.currentTarget.style.backgroundColor =
                    "var(--color-bg-hover)";
              }}
              onMouseLeave={(e) => {
                if (!isActive)
                  e.currentTarget.style.backgroundColor = "transparent";
              }}
              title={collapsed ? undefined : `${tab.label} (Ctrl+${tab.shortcut})`}
              aria-label={tab.label}
              aria-current={isActive ? "page" : undefined}
            >
              {buttonInner}
            </button>
          );

          return collapsed ? (
            <Tooltip
              key={tab.id}
              content={`${tab.label}  ·  ⌃${tab.shortcut}`}
              side="right"
              delay={200}
            >
              {button}
            </Tooltip>
          ) : (
            button
          );
        })}
      </div>

      {/* Collapse toggle (collapsed state) */}
      {collapsed && (
        <div className="flex justify-center px-2 pb-1">
          <CollapseButton collapsed={true} onClick={() => setCollapsed(false)} />
        </div>
      )}

      {/* Account footer */}
      <div className={collapsed ? "p-2" : "p-2"}>
        {collapsed ? (
          <Tooltip
            content={email || "Not signed in"}
            side="right"
            delay={200}
          >
            <div
              className="mx-auto flex h-8 w-8 items-center justify-center rounded-full text-[10.5px] font-semibold"
              style={{
                background:
                  "linear-gradient(135deg, var(--color-accent-primary-soft-20), rgba(90,159,255,0.15))",
                color: "var(--color-accent-secondary)",
                border: "1px solid var(--color-border-subtle)",
              }}
            >
              {initial}
            </div>
          </Tooltip>
        ) : (
          <div
            className="flex items-center gap-2.5 rounded-[5px] px-2.5 py-2"
            style={{
              backgroundColor: "var(--color-bg-base)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            <div
              className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold"
              style={{
                background:
                  "linear-gradient(135deg, var(--color-accent-primary-soft-20), rgba(90,159,255,0.15))",
                color: "var(--color-accent-secondary)",
                border: "1px solid var(--color-border-subtle)",
              }}
            >
              {initial}
            </div>
            <div className="min-w-0 flex-1 leading-none">
              <div className="flex items-center gap-1.5">
                <span className="truncate text-[11px] font-medium text-text-primary">
                  {userLabel}
                </span>
                {isTester && (
                  <span
                    className="shrink-0 rounded-[2px] px-1 py-px text-[8.5px] font-bold uppercase tracking-[0.1em]"
                    style={{
                      backgroundColor: "rgba(150, 100, 255, 0.15)",
                      color: "var(--color-accent-purple)",
                    }}
                  >
                    T
                  </span>
                )}
              </div>
              <div className="mt-1 text-[9.5px] font-medium uppercase tracking-[0.1em] text-text-dimmed">
                {email ? "Signed in" : "Not signed in"}
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
}

function CollapseButton({
  collapsed,
  onClick,
}: {
  collapsed: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[5px] transition-colors duration-100"
      style={{
        color: "var(--color-text-muted)",
        backgroundColor: "transparent",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = "var(--color-bg-hover)";
        e.currentTarget.style.color = "var(--color-text-primary)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = "transparent";
        e.currentTarget.style.color = "var(--color-text-muted)";
      }}
      title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
    >
      <svg
        width="13"
        height="13"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
        style={{
          transition: "transform 0.18s ease",
          transform: collapsed ? "rotate(180deg)" : "rotate(0)",
        }}
      >
        <path d="M15 18l-6-6 6-6" />
      </svg>
    </button>
  );
}
