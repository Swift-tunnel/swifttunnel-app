import swiftLogoUrl from "../../assets/swift.png";
import type { VpnState } from "../../lib/types";

// swift.png is 256x170 with the round mark in a 118px square at (69.5, 23).
const LOGO = { w: 256, h: 170, x: 69.5, y: 23, side: 118 };

/** Connection state around the SwiftTunnel mark.
 *  idle: dashed hairline, dimmed mark · connecting: spinning arc ·
 *  connected: solid ring and a green dot · error: red ring and dot.
 *
 *  Only the connecting arc moves, and only while the state is changing. The
 *  connected state is shown for the whole session, often behind a game, so
 *  it is drawn once and then left alone. */
export function StatusRing({
  state,
  size = 84,
}: {
  state: VpnState;
  size?: number;
}) {
  const isConnected = state === "connected";
  const isError = state === "error";
  const isTransitioning = !isConnected && !isError && state !== "disconnected";

  const r = 40;
  const c = 2 * Math.PI * r;
  const disc = Math.round(size * 0.76);
  const mark = Math.round(disc * 0.7);
  const k = mark / LOGO.side;
  const dot = Math.max(10, Math.round(size * 0.15));

  return (
    <div
      className="relative shrink-0 select-none"
      style={{ width: size, height: size }}
      aria-hidden
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 84 84"
        className="absolute inset-0"
        style={{ width: size, height: size }}
      >
        {/* Track */}
        <circle
          cx="42"
          cy="42"
          r={r}
          fill="none"
          stroke="var(--color-border-strong)"
          strokeWidth="1.5"
          strokeDasharray={state === "disconnected" ? "3 5" : undefined}
        />

        {/* Connecting: spinning arc */}
        {isTransitioning && (
          <circle
            cx="42"
            cy="42"
            r={r}
            fill="none"
            stroke="var(--color-text-primary)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeDasharray={`${c * 0.22} ${c * 0.78}`}
            className="ring-spin"
          />
        )}

        {(isConnected || isError) && (
          <circle
            cx="42"
            cy="42"
            r={r}
            fill="none"
            stroke={
              isError ? "var(--color-status-error)" : "var(--color-text-secondary)"
            }
            strokeWidth="1.75"
          />
        )}
      </svg>

      {/* The mark on a flat disc, dimmed until the tunnel is up. */}
      <div
        className="absolute flex items-center justify-center rounded-full"
        style={{
          inset: (size - disc) / 2,
          backgroundColor: "var(--color-bg-elevated)",
        }}
      >
        <span
          style={{
            width: mark,
            height: mark,
            backgroundImage: `url("${swiftLogoUrl}")`,
            backgroundRepeat: "no-repeat",
            backgroundSize: `${LOGO.w * k}px ${LOGO.h * k}px`,
            backgroundPosition: `${-LOGO.x * k}px ${-LOGO.y * k}px`,
            opacity: isConnected ? 1 : isTransitioning ? 0.8 : 0.4,
            transition: "opacity 0.3s ease",
          }}
        />
      </div>

      {/* Status dot, cut out of the card behind it. */}
      {(isConnected || isError) && (
        <span
          className="absolute rounded-full"
          style={{
            width: dot,
            height: dot,
            right: size * 0.09,
            bottom: size * 0.09,
            backgroundColor: isError
              ? "var(--color-status-error)"
              : "var(--color-status-connected)",
            boxShadow: "0 0 0 3px var(--color-bg-card)",
          }}
        />
      )}
    </div>
  );
}
