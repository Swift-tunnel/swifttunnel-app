import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import type { TabId } from "../../lib/types";

declare const __APP_VERSION__: string;

const tabs: { id: TabId; label: string; shortcut: string; icon: string }[] = [
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
    label: "Network",
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

function SidebarIcon({ path, isActive }: { path: string; isActive: boolean }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke={
        isActive ? "var(--color-text-primary)" : "var(--color-text-muted)"
      }
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ transition: "stroke 0.15s ease" }}
    >
      <path d={path} />
    </svg>
  );
}

export function Sidebar() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const setTab = useSettingsStore((s) => s.setTab);
  const vpnState = useVpnStore((s) => s.state);
  const isConnected = vpnState === "connected";
  const isTransitioning =
    vpnState !== "connected" &&
    vpnState !== "disconnected" &&
    vpnState !== "error";
  const email = useAuthStore((s) => s.email);
  const initial = email?.[0]?.toUpperCase() || "?";
  const userLabel = email ? email.split("@")[0] : "Not signed in";

  const statusText = isConnected
    ? "Connected"
    : isTransitioning
      ? "Connecting…"
      : "Disconnected";

  const statusColor = isConnected
    ? "var(--color-status-connected)"
    : isTransitioning
      ? "var(--color-status-warning)"
      : "var(--color-status-inactive)";

  return (
    <nav
      data-tauri-drag-region
      className="relative flex h-screen flex-col overflow-hidden border-r border-border-subtle bg-bg-sidebar"
      style={{ width: "var(--spacing-sidebar)" }}
    >
      {/* Header */}
      <div
        data-tauri-drag-region
        className="flex items-center gap-2.5 px-4 pt-4 pb-3"
      >
        <div
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px]"
          style={{
            background:
              "linear-gradient(135deg, var(--color-accent-primary), var(--color-accent-secondary))",
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#fff"
            strokeWidth="2.25"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
          </svg>
        </div>
        <div className="min-w-0 leading-none">
          <div className="text-[13px] font-semibold text-text-primary tracking-[-0.01em]">
            SwiftTunnel
          </div>
          <div className="mt-1 text-[10px] font-medium text-text-dimmed tracking-wide">
            v{__APP_VERSION__}
          </div>
        </div>
      </div>

      {/* Status chip */}
      <div className="px-3 pb-3">
        <div
          className="flex items-center gap-2 rounded-[6px] border border-border-subtle px-2.5 py-1.5"
          style={{ backgroundColor: "var(--color-bg-base)" }}
        >
          <span
            className="inline-block h-1.5 w-1.5 shrink-0 rounded-full transition-colors"
            style={{
              backgroundColor: statusColor,
              boxShadow: isConnected
                ? "0 0 6px var(--color-status-connected-glow)"
                : "none",
            }}
          />
          <span
            className="text-[11px] font-medium text-text-secondary"
            style={{ transition: "color 0.15s ease" }}
          >
            {statusText}
          </span>
        </div>
      </div>

      {/* Nav */}
      <div className="flex flex-1 flex-col gap-0.5 px-2">
        <div className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-text-dimmed">
          Menu
        </div>
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setTab(tab.id)}
              className="group relative flex items-center gap-2.5 rounded-[6px] px-2.5 py-2 text-left transition-colors duration-100"
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
              title={`${tab.label} (Ctrl+${tab.shortcut})`}
              aria-label={tab.label}
              aria-current={isActive ? "page" : undefined}
            >
              <SidebarIcon path={tab.icon} isActive={isActive} />
              <span
                className="flex-1 text-[13px] font-medium"
                style={{
                  color: isActive
                    ? "var(--color-text-primary)"
                    : "var(--color-text-secondary)",
                  letterSpacing: "-0.01em",
                  transition: "color 0.15s ease",
                }}
              >
                {tab.label}
              </span>
              <span
                className="rounded-[3px] px-1.5 py-0.5 text-[9px] font-semibold opacity-0 transition-opacity group-hover:opacity-100"
                style={{
                  backgroundColor: "var(--color-bg-elevated)",
                  color: "var(--color-text-muted)",
                  letterSpacing: "0.02em",
                }}
              >
                Ctrl {tab.shortcut}
              </span>
            </button>
          );
        })}
      </div>

      {/* Account footer */}
      <div
        className="m-2 flex items-center gap-2.5 rounded-[6px] border border-border-subtle px-2.5 py-2"
        style={{ backgroundColor: "var(--color-bg-base)" }}
      >
        <div
          className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold"
          style={{
            backgroundColor: "var(--color-accent-primary-soft-20)",
            color: "var(--color-accent-secondary)",
          }}
        >
          {initial}
        </div>
        <div className="min-w-0 flex-1 leading-none">
          <div className="truncate text-[11px] font-medium text-text-primary">
            {userLabel}
          </div>
          <div className="mt-1 text-[9px] font-medium text-text-dimmed">
            {email ? "Signed in" : "Not signed in"}
          </div>
        </div>
      </div>
    </nav>
  );
}
