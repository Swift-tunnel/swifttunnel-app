import { useEffect, type ReactNode } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import type { TabId } from "../../lib/types";

/** `2h 14m` / `47m` / `<1m`. */
function formatFreeTier(seconds: number): string {
  if (seconds < 60) return "<1m";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

function freeTierColor(seconds: number): string {
  if (seconds <= 600) return "var(--color-status-error)";
  if (seconds <= 1800) return "var(--color-status-warning)";
  return "var(--color-text-dimmed)";
}

const TABS: { id: TabId; label: string }[] = [
  { id: "connect", label: "Connect" },
  { id: "games", label: "Roblox" },
  { id: "settings", label: "Settings" },
];

/**
 * The 30px title bar.
 *
 * The full app spends 52px here on a page title, a subtitle, a game-status
 * pill, a search button, a language picker and an avatar. In a 380px window
 * that is most of the screen spent saying where you already are. This keeps
 * the wordmark, the free-tier budget and two window buttons.
 */
export function LiteTitleBar() {
  const freeTierRemaining = useVpnStore((s) => s.freeTierRemaining);
  const freeTierGraceRemaining = useVpnStore((s) => s.freeTierGraceRemaining);
  const fetchFreeTier = useVpnStore((s) => s.fetchFreeTier);
  const tickFreeTier = useVpnStore((s) => s.tickFreeTier);

  // Same cadence as the full app: the authoritative number only moves when a
  // relay ticket refreshes, so resync slowly and count down locally between.
  useEffect(() => {
    void fetchFreeTier();
    const sync = window.setInterval(() => void fetchFreeTier(), 60_000);
    const tick = window.setInterval(() => tickFreeTier(), 1_000);
    return () => {
      window.clearInterval(sync);
      window.clearInterval(tick);
    };
  }, [fetchFreeTier, tickFreeTier]);

  const budget = freeTierGraceRemaining ?? freeTierRemaining;

  return (
    <header
      data-tauri-drag-region
      className="flex shrink-0 items-center justify-between"
      style={{
        height: 30,
        paddingLeft: 10,
        backgroundColor: "var(--color-bg-sidebar)",
      }}
    >
      <div data-tauri-drag-region className="flex items-center gap-1.5">
        <span
          className="text-[11.5px] font-semibold tracking-[-0.01em]"
          style={{ color: "var(--color-text-secondary)" }}
        >
          SwiftTunnel
        </span>
        <span
          className="rounded-[4px] px-1 text-[8.5px] font-bold uppercase tracking-[0.08em]"
          style={{
            backgroundColor: "var(--color-bg-active)",
            color: "var(--color-text-dimmed)",
            paddingTop: 1,
            paddingBottom: 1,
          }}
        >
          Lite
        </span>
      </div>

      <div className="flex items-stretch" style={{ height: 30 }}>
        {budget !== null && (
          <span
            className="self-center pr-2 text-[10px] font-medium tabular-nums"
            title={
              freeTierGraceRemaining !== null
                ? `Free time used up. SwiftTunnel disconnects in ${formatFreeTier(freeTierGraceRemaining)}.`
                : `${formatFreeTier(budget)} of free time left.`
            }
            style={{ color: freeTierColor(budget) }}
          >
            {formatFreeTier(budget)}
          </span>
        )}
        <WindowButton label="Minimize" onClick={() => void getCurrentWindow().minimize()}>
          <path d="M2 6h8" />
        </WindowButton>
        <WindowButton label="Close" danger onClick={() => void getCurrentWindow().close()}>
          <path d="M2.5 2.5l7 7M9.5 2.5l-7 7" />
        </WindowButton>
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
      className={`flex h-full items-center justify-center ${
        danger
          ? "hover:bg-[#e5484d] hover:text-white"
          : "hover:bg-[color:var(--color-bg-hover)]"
      }`}
      style={{ width: 34, color: "var(--color-text-muted)" }}
    >
      <svg
        width="10"
        height="10"
        viewBox="0 0 12 12"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.15"
        strokeLinecap="round"
      >
        {children}
      </svg>
    </button>
  );
}

/**
 * Three underlined tabs.
 *
 * Underlines rather than the sidebar's filled pills: a pill needs padding on
 * four sides to read as a pill, and there are 380 pixels to divide three ways.
 */
export function LiteNav() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const setTab = useSettingsStore((s) => s.setTab);

  return (
    <nav
      className="flex shrink-0"
      aria-label="Sections"
      style={{
        backgroundColor: "var(--color-bg-sidebar)",
        borderBottom: "1px solid var(--color-border-subtle)",
      }}
    >
      {TABS.map((tab) => {
        const selected = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => setTab(tab.id)}
            aria-current={selected ? "page" : undefined}
            className="relative flex-1 text-[11.5px] font-medium"
            style={{
              height: 30,
              color: selected
                ? "var(--color-text-primary)"
                : "var(--color-text-dimmed)",
            }}
          >
            {tab.label}
            <span
              className="absolute inset-x-3 bottom-0"
              style={{
                height: 1.5,
                backgroundColor: selected
                  ? "var(--color-text-primary)"
                  : "transparent",
              }}
            />
          </button>
        );
      })}
    </nav>
  );
}
