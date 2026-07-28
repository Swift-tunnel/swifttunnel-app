import type { ReactNode } from "react";
import { countryFlag, getLatencyColor } from "../../lib/utils";

/* ──────────────────────────────────────────────────────────────────────────
   Game route diagram, lives inside the connect deck, under the status row.

   Shows the path traffic actually takes: you → relay → game. Three nodes and
   one number, because that is all we genuinely measure. The relay is
   packet-NAT, so there are no intermediate hostnames to probe and no honest
   way to attribute latency to the relay→game leg; that leg draws dashed and
   says so rather than showing a plausible-looking number.
   ────────────────────────────────────────────────────────────────────────── */

interface RouteDiagramProps {
  regionName: string | null;
  countryCode: string | null;
  /** Measured RTT to the relay, in ms. */
  ping: number | null;
  connected: boolean;
  /** Specific relay node when resolved (e.g. "singapore-02"); falls back to the
   *  region name. Auto-fills once the server reports which node was picked. */
  relayName?: string | null;
  gameName?: string;
  onRefresh?: () => void;
}

export function RouteDiagram({
  regionName,
  countryCode,
  ping,
  connected,
  relayName,
  gameName = "Roblox",
  onRefresh,
}: RouteDiagramProps) {
  const tone = ping !== null ? getLatencyColor(ping) : "var(--color-text-muted)";

  return (
    /* Full width on purpose: the deck footer's stat strip spans the whole
       panel, so a capped diagram reads as misaligned against it. */
    <div className="relative px-6 pb-5">
      {/* No estimated-ping box here: the leg chip and the LATENCY stat in the
          deck footer already show this number. Three copies of one value is
          what left an orphaned box floating mid-panel. */}
      <div className="mb-4 flex items-center gap-2.5">
        <h3 className="text-[13.5px] font-semibold text-text-primary">
          Game route
        </h3>
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            aria-label="Refresh route"
            className="flex h-7 w-7 items-center justify-center rounded-[7px] transition-colors hover:bg-[color:var(--color-bg-hover)]"
            style={{
              border: "1px solid var(--color-border-subtle)",
              color: "var(--color-text-muted)",
            }}
          >
            <svg
              width="13"
              height="13"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M21 12a9 9 0 1 1-2.64-6.36" />
              <path d="M21 3v6h-6" />
            </svg>
          </button>
        )}
      </div>

      <div className="flex items-center overflow-x-auto pb-1">
        <Endpoint label="You" active={connected} icon={<UserIcon />} />

        <Leg value={ping !== null ? `${ping} ms` : null} tone={tone} />

        <NodeCard
          title={relayName || regionName || "No relay"}
          tag={countryCode ? countryCode.toUpperCase() : undefined}
          sub="IPv4 route"
          active={connected}
          badge={
            countryCode ? (
              <span className="text-[13px] leading-none">
                {countryFlag(countryCode)}
              </span>
            ) : undefined
          }
        />

        {/* Relay → game is not measured; the connector says so rather than
            inventing a number to fill the gap. */}
        <Leg value={null} tone={tone} dashed />

        <Endpoint label={gameName} icon={<RobloxIcon />} tile />
      </div>

      <p className="mt-3 text-[10.5px] leading-snug text-text-dimmed">
        The {ping !== null ? `${ping} ms` : "relay"} figure is your ping to the
        relay, not the final in-game ping, SwiftTunnel forwards packets without
        resolving intermediate hops.
      </p>
    </div>
  );
}

/** Round avatar (you) or squared app tile (destination). */
function Endpoint({
  label,
  icon,
  active,
  tile,
}: {
  label: string;
  icon: ReactNode;
  active?: boolean;
  tile?: boolean;
}) {
  return (
    <div className="flex shrink-0 flex-col items-center gap-1.5">
      <div
        className={`flex h-12 w-12 items-center justify-center ${
          tile ? "rounded-[11px] neon-edge" : "icon-orb"
        } ${active ? "neon-edge-live" : ""}`}
        style={{
          backgroundColor: tile ? "var(--color-bg-elevated)" : undefined,
          border: tile ? "1px solid var(--color-border-default)" : undefined,
          color: active
            ? "var(--color-status-connected)"
            : "var(--color-text-secondary)",
        }}
      >
        {icon}
      </div>
      <span className="max-w-[76px] truncate text-[10px] font-medium text-text-muted">
        {label}
      </span>
    </div>
  );
}

/** Two-row relay card: identity on top, transport underneath. */
function NodeCard({
  title,
  tag,
  sub,
  active,
  badge,
}: {
  title: string;
  tag?: string;
  sub: string;
  active?: boolean;
  badge?: ReactNode;
}) {
  return (
    <div
      className={`shrink-0 overflow-hidden rounded-[10px] ${
        active ? "neon-edge-live" : "neon-edge"
      }`}
      style={{
        minWidth: 158,
        backgroundColor: "var(--color-bg-elevated)",
        border: `1px solid ${
          active
            ? "var(--color-status-connected)"
            : "var(--color-border-default)"
        }`,
      }}
    >
      <div className="flex items-center justify-between gap-3 px-3 py-2">
        <span className="flex min-w-0 items-center gap-1.5">
          {badge}
          <span className="truncate text-[12px] font-semibold text-text-primary">
            {title}
          </span>
        </span>
        {tag && (
          <span className="shrink-0 text-[9px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
            {tag}
          </span>
        )}
      </div>
      <div
        className="flex items-center justify-between gap-3 px-3 py-1.5"
        style={{
          borderTop: "1px solid var(--color-border-subtle)",
          backgroundColor: "var(--color-bg-base)",
        }}
      >
        <span className="truncate font-mono text-[10px] text-text-muted">
          {sub}
        </span>
        <span
          style={{
            color: active
              ? "var(--color-status-connected)"
              : "var(--color-text-dimmed)",
          }}
        >
          <RouteIcon />
        </span>
      </div>
    </div>
  );
}

/** A leg of the route, with its latency chip sitting on the line. */
function Leg({
  value,
  tone,
  dashed,
}: {
  value: string | null;
  tone: string;
  dashed?: boolean;
}) {
  return (
    <div className="relative flex min-w-[84px] flex-1 items-center justify-center">
      <div
        className="absolute inset-x-0"
        style={
          dashed
            ? { borderTop: "1px dashed var(--color-border-default)" }
            : {
                height: 1,
                background:
                  "linear-gradient(90deg, transparent, var(--color-border-strong) 22%, var(--color-border-strong) 78%, transparent)",
              }
        }
      />
      <span
        className="lcd-readout relative rounded-[6px] px-2 py-1 text-[10px] font-semibold leading-none"
        style={{
          backgroundColor: "var(--color-bg-elevated)",
          border: "1px solid var(--color-border-subtle)",
          color: value ? tone : "var(--color-text-dimmed)",
        }}
      >
        {value ?? "not measured"}
      </span>
    </div>
  );
}

function UserIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
}

/** Roblox mark: a tilted square with a tilted square cut out of it.
 *  Drawn with fillRule="evenodd" so the inner square punches a hole rather
 *  than sitting on top, which keeps it correct on any background. Uses
 *  currentColor so it inherits the node's connected/idle tint. */
function RobloxIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M4.92 1.6 1.6 15.02 19.08 22.4 22.4 8.98 4.92 1.6Zm4.4 7.55 5.86 2.48-1.24 5.03-5.86-2.48 1.24-5.03Z"
      />
    </svg>
  );
}

function RouteIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="2" y="15" width="6" height="6" rx="1" />
      <rect x="16" y="3" width="6" height="6" rx="1" />
      <path d="M5 15V9a3 3 0 0 1 3-3h8" />
    </svg>
  );
}
