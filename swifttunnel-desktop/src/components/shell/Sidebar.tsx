import { useState } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useServerStore } from "../../stores/serverStore";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { countryFlag } from "../../lib/utils";
import { NAV_SECTIONS, type NavItem } from "./nav";
import type { VpnState } from "../../lib/types";
import { SwiftLogo } from "../common/SwiftLogo";

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
    // localStorage unavailable — collapse state just won't persist.
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
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.85"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <line x1="9" y1="4" x2="9" y2="20" />
      {collapsed ? (
        <path d="M14 9.5l2.5 2.5L14 14.5" />
      ) : (
        <path d="M16.5 9.5L14 12l2.5 2.5" />
      )}
    </svg>
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
      title={collapsed ? item.label : undefined}
      className={`group relative flex h-8 w-full items-center rounded-[6px] text-left transition-colors duration-100 ${
        collapsed ? "justify-center px-0" : "gap-2.5 px-2"
      }`}
      style={{
        backgroundColor: active
          ? "var(--color-accent-primary-soft-8)"
          : "transparent",
      }}
      onMouseEnter={(e) => {
        if (!active)
          e.currentTarget.style.backgroundColor = "var(--color-bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.backgroundColor = "transparent";
      }}
      aria-label={item.label}
      aria-current={active ? "page" : undefined}
    >
      {active && (
        <span
          className="absolute -left-2 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-r"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        />
      )}
      <svg
        width="15"
        height="15"
        viewBox="0 0 24 24"
        fill="none"
        stroke={
          active ? "var(--color-text-primary)" : "var(--color-text-muted)"
        }
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="shrink-0 transition-colors duration-100 group-hover:stroke-[color:var(--color-text-secondary)]"
        style={{ marginLeft: collapsed ? 0 : 2 }}
      >
        <path d={item.icon} />
      </svg>
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
          <kbd
            className="flex h-[16px] min-w-[16px] items-center justify-center rounded-[3px] px-1 font-mono text-[9px] font-medium leading-none transition-opacity duration-100"
            style={{
              color: "var(--color-text-dimmed)",
              border: "1px solid var(--color-border-subtle)",
              backgroundColor: "var(--color-bg-base)",
              opacity: active ? 1 : 0,
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
      {isConnected && (
        <span
          className="absolute inset-0 animate-ping rounded-full opacity-60"
          style={{ backgroundColor: dotColor(vpnState) }}
        />
      )}
      <span
        className="relative h-1.5 w-1.5 rounded-full"
        style={{
          backgroundColor: dotColor(vpnState),
          boxShadow: isConnected
            ? "0 0 6px var(--color-status-connected-glow)"
            : "none",
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
          border: `1px solid ${
            isConnected
              ? "var(--color-status-connected-soft-20)"
              : "var(--color-border-subtle)"
          }`,
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
        border: `1px solid ${
          isConnected
            ? "var(--color-status-connected-soft-20)"
            : "var(--color-border-subtle)"
        }`,
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.025)",
      }}
      aria-label="Open Connect tab"
    >
      <span className="flex items-center gap-2">
        {dot}
        <span
          className="flex-1 truncate text-[10.5px] font-semibold uppercase tracking-[0.08em]"
          style={{
            color: isConnected
              ? "var(--color-status-connected)"
              : "var(--color-text-muted)",
          }}
        >
          {stateLabel(vpnState)}
        </span>
        {isConnected && ping !== null && (
          <span className="lcd-readout text-[10.5px] text-text-secondary">
            {ping} ms
          </span>
        )}
      </span>
      <span className="flex items-center gap-1.5 truncate text-[11.5px] font-medium text-text-primary">
        {isConnected && region ? (
          <>
            <span className="text-[12px] leading-none">
              {countryFlag(region.country_code)}
            </span>
            <span className="truncate">{region.name}</span>
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
      className="flex h-full shrink-0 flex-col border-r"
      style={{
        width: collapsed ? 56 : 224,
        backgroundColor: "var(--color-bg-sidebar)",
        borderColor: "var(--color-border-subtle)",
        transition: "width 0.18s cubic-bezier(0.4, 0, 0.2, 1)",
      }}
    >
      {/* Brand */}
      <div
        data-tauri-drag-region
        className={`flex items-center pb-3 pt-[18px] ${
          collapsed ? "flex-col gap-2 px-0" : "gap-2.5 px-4"
        }`}
      >
        <SwiftLogo size={26} />
        {!collapsed && (
          <div
            className="min-w-0 flex-1 truncate text-[13px] font-semibold leading-none text-text-primary"
            style={{ letterSpacing: "-0.018em" }}
          >
            SwiftTunnel
          </div>
        )}
        <button
          onClick={toggleCollapsed}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[5px] transition-colors duration-100 hover:bg-bg-hover"
          style={{ color: "var(--color-text-muted)" }}
        >
          <CollapseIcon collapsed={collapsed} />
        </button>
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
