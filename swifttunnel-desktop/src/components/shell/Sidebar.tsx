import { useState } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import type { TabId, VpnState } from "../../lib/types";
import { Tooltip } from "../ui/Tooltip";
import swiftLogo from "../../assets/swift.png";

declare const __APP_VERSION__: string;

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

function dotColor(state: VpnState): string {
  if (state === "connected") return "var(--color-status-connected)";
  if (state === "error") return "var(--color-status-error)";
  if (state === "disconnected") return "var(--color-status-inactive)";
  return "var(--color-status-warning)";
}

export function Sidebar() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const setTab = useSettingsStore((s) => s.setTab);
  const vpnState = useVpnStore((s) => s.state);
  const email = useAuthStore((s) => s.email);
  const [expanded, setExpanded] = useState(false);

  const initial = email?.[0]?.toUpperCase() || "?";
  const userLabel = email ? email.split("@")[0] : "Not signed in";
  const isConnected = vpnState === "connected";
  const isTransitioning =
    vpnState !== "connected" &&
    vpnState !== "disconnected" &&
    vpnState !== "error";

  return (
    <nav
      data-tauri-drag-region
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
      className="relative flex h-full shrink-0 flex-col overflow-hidden border-r"
      style={{
        width: expanded
          ? "var(--spacing-sidebar-expanded)"
          : "var(--spacing-sidebar)",
        backgroundColor: "var(--color-bg-sidebar)",
        borderColor: "var(--color-border-subtle)",
        transition: "width 0.15s cubic-bezier(0.4, 0, 0.2, 1)",
      }}
    >
      {/* Brand */}
      <div
        data-tauri-drag-region
        className="flex items-center gap-2.5 px-2.5 pt-3.5 pb-4"
      >
        <img
          src={swiftLogo}
          alt="SwiftTunnel"
          width={28}
          height={28}
          className="shrink-0"
          style={{ objectFit: "contain" }}
        />
        {expanded && (
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold leading-none tracking-[-0.01em] text-text-primary">
              SwiftTunnel
            </div>
            <div className="mt-1 font-mono text-[10px] leading-none text-text-dimmed">
              v{__APP_VERSION__}
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="mt-1 flex flex-1 flex-col gap-0.5 px-1.5">
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          const button = (
            <button
              key={tab.id}
              onClick={() => setTab(tab.id)}
              className="group relative flex h-9 items-center gap-3 rounded-[5px] px-2 text-left transition-colors duration-100"
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
              aria-label={tab.label}
              aria-current={isActive ? "page" : undefined}
            >
              {isActive && (
                <span
                  className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2"
                  style={{ backgroundColor: "#ffffff" }}
                />
              )}
              <svg
                width="17"
                height="17"
                viewBox="0 0 24 24"
                fill="none"
                stroke={
                  isActive
                    ? "var(--color-text-primary)"
                    : "var(--color-text-muted)"
                }
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{ flexShrink: 0, marginLeft: 2 }}
              >
                <path d={tab.icon} />
              </svg>
              {expanded && (
                <>
                  <span
                    className="flex-1 text-[13px] font-medium"
                    style={{
                      color: isActive
                        ? "var(--color-text-primary)"
                        : "var(--color-text-secondary)",
                      letterSpacing: "-0.005em",
                    }}
                  >
                    {tab.label}
                  </span>
                  <span
                    className="font-mono text-[10px]"
                    style={{ color: "var(--color-text-dimmed)" }}
                  >
                    ⌃{tab.shortcut}
                  </span>
                </>
              )}
            </button>
          );

          return expanded ? (
            button
          ) : (
            <Tooltip
              key={tab.id}
              content={`${tab.label}  ·  ⌃${tab.shortcut}`}
              side="right"
              delay={200}
            >
              {button}
            </Tooltip>
          );
        })}
      </div>

      {/* User tile */}
      <div className="p-1.5">
        <div className="flex h-10 items-center gap-2.5 rounded-[5px] px-1.5">
          <div className="relative shrink-0">
            <div
              className="flex h-7 w-7 items-center justify-center rounded-full text-[11px] font-semibold"
              style={{
                backgroundColor: "var(--color-bg-hover)",
                color: "var(--color-text-primary)",
                border: "1px solid var(--color-border-default)",
              }}
            >
              {initial}
            </div>
            <span
              className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full"
              style={{
                backgroundColor: dotColor(vpnState),
                border: "2px solid var(--color-bg-sidebar)",
                boxShadow: isConnected
                  ? "0 0 6px var(--color-status-connected-glow)"
                  : "none",
                animation: isTransitioning
                  ? "pulse-opacity 1.2s ease-in-out infinite"
                  : "none",
              }}
              aria-label={`VPN ${vpnState}`}
            />
          </div>
          {expanded && (
            <div className="min-w-0 flex-1 leading-none">
              <div className="truncate text-[12px] font-medium text-text-primary">
                {userLabel}
              </div>
              <div
                className="mt-1 text-[10px] font-medium uppercase tracking-[0.08em]"
                style={{ color: "var(--color-text-muted)" }}
              >
                {vpnState === "connected" ? "Tunneled" : "Idle"}
              </div>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
