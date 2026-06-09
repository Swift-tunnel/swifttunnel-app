import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import { getLatencyColor } from "../../lib/utils";
import { StatusChip } from "./StatusChip";
import { navItemFor } from "./nav";

export function TopBar() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const vpnState = useVpnStore((s) => s.state);
  const ping = useVpnStore((s) => s.ping);

  const item = navItemFor(activeTab);
  const isConnected = vpnState === "connected";

  return (
    <header
      data-tauri-drag-region
      className="flex shrink-0 items-center justify-between gap-4 border-b px-5"
      style={{
        height: "var(--spacing-topbar)",
        backgroundColor: "var(--color-bg-sidebar)",
        borderColor: "var(--color-border-subtle)",
      }}
    >
      <div data-tauri-drag-region className="min-w-0">
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

      <div className="flex shrink-0 items-center gap-2">
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
      </div>
    </header>
  );
}
