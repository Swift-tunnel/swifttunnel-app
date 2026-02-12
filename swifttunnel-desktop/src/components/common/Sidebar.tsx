import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import type { TabId } from "../../lib/types";

const tabs: { id: TabId; label: string; icon: string }[] = [
  { id: "connect", label: "Connect", icon: "M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0 M12 20h.01" },
  { id: "boost", label: "Boost", icon: "M13 2L3 14h9l-1 8 10-12h-9l1-8z" },
  { id: "network", label: "Network", icon: "M22 12h-4l-3 9L9 3l-3 9H2" },
  { id: "settings", label: "Settings", icon: "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z" },
];

function SidebarIcon({ path, isActive }: { path: string; isActive: boolean }) {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke={isActive ? "var(--color-accent-primary)" : "var(--color-text-muted)"}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
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

  return (
    <nav className="flex h-screen w-[var(--spacing-sidebar)] flex-col items-center bg-bg-sidebar border-r border-border-subtle py-4">
      {/* Logo */}
      <div className="mb-6 flex h-8 w-8 items-center justify-center">
        <div
          className="h-3 w-3 rounded-full transition-colors duration-300"
          style={{
            backgroundColor: isConnected
              ? "var(--color-status-connected)"
              : "var(--color-status-inactive)",
            boxShadow: isConnected
              ? "0 0 8px var(--color-status-connected-glow)"
              : "none",
          }}
        />
      </div>

      {/* Tab buttons */}
      <div className="flex flex-1 flex-col gap-1">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setTab(tab.id)}
              className="group relative flex h-10 w-10 items-center justify-center rounded-[var(--radius-button)] transition-colors duration-150"
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
              title={tab.label}
              aria-label={tab.label}
              aria-current={isActive ? "page" : undefined}
            >
              <SidebarIcon path={tab.icon} isActive={isActive} />
              {isActive && (
                <div
                  className="absolute left-0 h-5 w-0.5 rounded-r"
                  style={{ backgroundColor: "var(--color-accent-primary)" }}
                />
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
