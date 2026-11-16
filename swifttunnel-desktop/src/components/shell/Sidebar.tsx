import { useState } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useServerStore } from "../../stores/serverStore";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { NAV_SECTIONS, type NavItem } from "./nav";
import type { VpnState } from "../../lib/types";
import { SwiftLogo } from "../common/SwiftLogo";
import { Icon } from "../ui/Icon";
import { Flag } from "../ui/Flag";

declare const __APP_VERSION__: string;

const COLLAPSE_KEY = "st.sidebarCollapsed";

function loadCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

function persistCollapsed(value: boolean) {
  try {
    localStorage.setItem(COLLAPSE_KEY, value ? "1" : "0");
  } catch {
    // localStorage unavailable, collapse state just won't persist.
  }
}

function dotColor(state: VpnState): string {
  if (state === "connected") return "var(--color-status-connected)";
  if (state === "error") return "var(--color-status-error)";
  if (state === "disconnected") return "var(--color-status-inactive)";
  return "var(--color-status-warning)";
}

function stateLabel(state: VpnState): string {
  if (state === "connected") return "Tunnel active";
  if (state === "error") return "Error";
  if (state === "disconnected") return "Not connected";
  return "Working…";
}

function CollapseIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <Icon name={collapsed ? "panel-open" : "panel-close"} size={15} strokeWidth={1.85} />
  );
}

function NavButton({
  item,
  active,
  collapsed,
}: {
  item: NavItem;
  active: boolean;
  collapsed: boolean;
}) {
  const setTab = useSettingsStore((s) => s.setTab);

  return (
    <button
      onClick={() => setTab(item.id)}
      title={`${item.label}, Ctrl+${item.shortcut}`}
      className={`group relative flex w-full items-center rounded-[9px] text-left transition-colors duration-100 ${
        collapsed ? "justify-center px-0 py-[7px]" : "gap-2.5 px-2.5 py-[7px]"
      } ${active ? "" : "hover:bg-[color:var(--color-bg-hover)]"}`}
      style={{
        backgroundColor: active ? "var(--color-accent-primary-soft-8)" : undefined,
      }}
      aria-label={item.label}
      aria-current={active ? "page" : undefined}
    >
      {/* Marker bar at the sidebar's edge for the current tab, as in ExitLag. */}
      {active && (
        <span
          aria-hidden
          className="absolute -left-2 bottom-[7px] top-[7px] w-[3px] rounded-r-full"
          style={{ backgroundColor: "var(--color-text-primary)" }}
        />
      )}
      <Icon
        name={item.icon}
        size={19}
        active={active}
        className="shrink-0 transition-colors duration-100 group-hover:text-[color:var(--color-text-secondary)]"
        style={{
          color: active ? "var(--color-text-primary)" : "var(--color-text-muted)",
        }}
      />
      {!collapsed && (
        <>
          <span
            className="flex-1 truncate text-[12.5px] font-medium"
            style={{
              color: active
                ? "var(--color-text-primary)"
                : "var(--color-text-secondary)",
              letterSpacing: "-0.005em",
            }}
          >
            {item.label}
          </span>
          {/* Reveal on hover, not just on the active tab, you learn the key
              for where you're going, not for where you already are. */}
          <kbd
            className={`flex h-[16px] min-w-[16px] items-center justify-center rounded-[3px] px-1 font-mono text-[9px] font-medium leading-none transition-opacity duration-100 ${
              active ? "opacity-100" : "opacity-0 group-hover:opacity-70"
            }`}
            style={{
              color: "var(--color-text-dimmed)",
              border: "1px solid var(--color-border-subtle)",
              backgroundColor: "var(--color-bg-base)",
            }}
          >
            {item.shortcut}
          </kbd>
        </>
      )}
    </button>
  );
}

function ConnectionCard({ collapsed }: { collapsed: boolean }) {
  const vpnState = useVpnStore((s) => s.state);
  const vpnRegion = useVpnStore((s) => s.region);
  const ping = useVpnStore((s) => s.ping);
  const regions = useServerStore((s) => s.regions);
  const setTab = useSettingsStore((s) => s.setTab);

  const isConnected = vpnState === "connected";
  const isTransitioning =
    vpnState !== "connected" &&
    vpnState !== "disconnected" &&
    vpnState !== "error";
  const region = findRegionForVpnRegion(regions, vpnRegion);

  const dot = (
    <span className="relative flex h-1.5 w-1.5 shrink-0">
      <span
        className="relative h-1.5 w-1.5 rounded-full"
        style={{
          backgroundColor: dotColor(vpnState),
          animation: isTransitioning
            ? "pulse-opacity 1.2s ease-in-out infinite"
            : "none",
        }}
      />
    </span>
  );

  if (collapsed) {
    return (
      <button
        onClick={() => setTab("connect")}
        title={`${stateLabel(vpnState)}${isConnected && region ? ` · ${region.name}` : ""}`}
        className="flex h-9 w-full items-center justify-center rounded-[8px] transition-colors duration-100 hover:bg-bg-hover"
        style={{
          backgroundColor: "var(--color-bg-card)",
          border: "1px solid var(--color-border-subtle)",
        }}
        aria-label="Open Connect tab"
      >
        {dot}
      </button>
    );
  }

  return (
    <button
      onClick={() => setTab("connect")}
      className="group flex w-full flex-col gap-1.5 rounded-[8px] px-2.5 py-2.5 text-left transition-colors duration-100"
      style={{
        backgroundColor: "var(--color-bg-card)",
        border: "1px solid var(--color-border-subtle)",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.025)",
      }}
      aria-label="Open Connect tab"
    >
      <span className="flex items-center gap-2">
        {dot}
        <span
          className="flex-1 truncate text-[10px] font-semibold uppercase tracking-[0.06em]"
          style={{
            color: isConnected
              ? "var(--color-text-secondary)"
              : "var(--color-text-muted)",
          }}
        >
          {stateLabel(vpnState)}
        </span>
      </span>
      <span className="flex items-center gap-1.5 truncate text-[11.5px] font-medium text-text-primary">
        {isConnected && region ? (
          <>
            <Flag code={region.country_code} size={14} />
            <span className="min-w-0 flex-1 truncate">{region.name}</span>
            {ping !== null && (
              <span className="lcd-readout shrink-0 text-[10.5px] text-text-secondary">
                {ping} ms
              </span>
            )}
          </>
        ) : (
          <span className="truncate text-text-dimmed">
            {isTransitioning ? "Establishing session…" : "No active session"}
          </span>
        )}
      </span>
    </button>
  );
}

export function Sidebar() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const email = useAuthStore((s) => s.email);
  const [collapsed, setCollapsed] = useState(loadCollapsed);

  const initial = email?.[0]?.toUpperCase() || "?";
  const userLabel = email ? email.split("@")[0] : "Not signed in";

  function toggleCollapsed() {
    setCollapsed((prev) => {
      const next = !prev;
      persistCollapsed(next);
      return next;
    });
  }

  return (
    <nav
      data-tauri-drag-region
      className="flex h-full shrink-0 flex-col"
      style={{
        width: collapsed ? 56 : 176,
        backgroundColor: "var(--color-bg-sidebar)",
        transition: "width 0.18s cubic-bezier(0.4, 0, 0.2, 1)",
      }}
    >
      {/* Brand */}
      <div
        data-tauri-drag-region
        className="group/brand relative flex shrink-0 items-center"
        style={{ height: "var(--spacing-topbar)" }}
      >
        {collapsed ? (
          <div className="relative flex w-full items-center justify-center">
            {/* On hover the logo cross-fades to the expand toggle so nothing
                overlaps it; clicking anywhere in the corner expands. */}
            <span className="flex items-center justify-center transition-opacity duration-150 group-hover/brand:opacity-0">
              <SwiftLogo size={66} />
            </span>
            <button
              onClick={toggleCollapsed}
              title="Expand sidebar"
              aria-label="Expand sidebar"
              className="absolute inset-0 flex items-center justify-center opacity-0 transition-opacity duration-150 group-hover/brand:opacity-100"
              style={{ color: "var(--color-text-secondary)" }}
            >
              <CollapseIcon collapsed />
            </button>
          </div>
        ) : (
          <div className="flex w-full items-center justify-between pl-1 pr-2">
            <div className="flex min-w-0 items-center">
              <SwiftLogo size={56} className="-mr-1 shrink-0" />
              <span
                className="truncate text-[14px] font-semibold leading-none"
                style={{
                  color: "var(--color-text-primary)",
                  letterSpacing: "-0.015em",
                }}
              >
                SwiftTunnel
              </span>
            </div>
            <button
              onClick={toggleCollapsed}
              title="Collapse sidebar"
              aria-label="Collapse sidebar"
              className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[5px] opacity-60 transition-all duration-150 hover:bg-bg-hover hover:opacity-100"
              style={{ color: "var(--color-text-muted)" }}
            >
              <CollapseIcon collapsed={false} />
            </button>
          </div>
        )}
      </div>

      {/* Nav sections */}
      <div
        className={`flex flex-1 flex-col gap-4 overflow-y-auto pt-1 ${
          collapsed ? "px-2" : "px-2"
        }`}
      >
        {NAV_SECTIONS.map((section, idx) => (
          <div key={section.label} className="flex flex-col gap-0.5">
            {collapsed ? (
              idx > 0 && (
                <div
                  className="mx-2 mb-1.5 h-px"
                  style={{ backgroundColor: "var(--color-border-subtle)" }}
                />
              )
            ) : (
              <div
                className="px-2 pb-1.5 text-[9.5px] font-semibold uppercase tracking-[0.14em]"
                style={{ color: "var(--color-text-dimmed)" }}
              >
                {section.label}
              </div>
            )}
            {section.items.map((item) => (
              <NavButton
                key={item.id}
                item={item}
                active={activeTab === item.id}
                collapsed={collapsed}
              />
            ))}
          </div>
        ))}
      </div>

      {/* Connection status */}
      <div className="px-2.5 pb-2.5 pt-2">
        <ConnectionCard collapsed={collapsed} />
      </div>

      {/* User */}
      <div
        className={`flex items-center border-t py-3 ${
          collapsed ? "justify-center px-0" : "gap-2.5 px-4"
        }`}
        style={{ borderColor: "var(--color-border-subtle)" }}
      >
        <div
          title={collapsed ? `${userLabel} · v${__APP_VERSION__}` : undefined}
          className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[10.5px] font-semibold"
          style={{
            background:
              "linear-gradient(135deg, var(--color-bg-elevated), var(--color-bg-active))",
            color: "var(--color-text-primary)",
            border: "1px solid var(--color-border-default)",
          }}
        >
          {initial}
        </div>
        {!collapsed && (
          <>
            <span
              // The account name (email prefix) is an identifier, never
              // translate it. The "Not signed in" fallback still translates.
              data-no-translate={email ? "" : undefined}
              className="min-w-0 flex-1 truncate text-[11.5px] font-medium text-text-secondary"
              style={{ letterSpacing: "-0.005em" }}
            >
              {userLabel}
            </span>
            <span className="shrink-0 font-mono text-[9.5px] tracking-wide text-text-dimmed">
              v{__APP_VERSION__}
            </span>
          </>
        )}
      </div>
    </nav>
  );
}
