import type { VpnState } from "../../lib/types";

/** Animated connection ring around a fluid orb.
 *  idle: dashed hairline, grey drifting blobs · connecting: spinning arc,
 *  brighter faster fluid · connected: glowing green ring + green fluid ·
 *  error: red ring, dim red fluid */
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

  const r = 39;
  const c = 2 * Math.PI * r;

  return (
    <div
      className="relative shrink-0 select-none"
      style={{ width: size, height: size }}
      aria-hidden
    >
      {/* Connected: expanding pulse halo behind the ring */}
      {isConnected && (
        <span
          className="ring-pulse absolute inset-0 rounded-full"
          style={{
            border: "1.5px solid var(--color-status-connected)",
          }}
        />
      )}

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
          stroke="var(--color-border-default)"
          strokeWidth="1.5"
          strokeDasharray={state === "disconnected" ? "3 5" : undefined}
          opacity={isConnected || isError ? 0.35 : 0.8}
        />

        {/* Connecting: spinning quarter arc */}
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

        {/* Connected: full glowing ring */}
        {isConnected && (
          <circle
            cx="42"
            cy="42"
            r={r}
            fill="none"
            stroke="var(--color-status-connected)"
            strokeWidth="2"
            style={{
              filter: "drop-shadow(0 0 5px var(--color-status-connected-glow))",
            }}
          />
        )}

        {/* Error: full red ring */}
        {isError && (
          <circle
            cx="42"
            cy="42"
            r={r}
            fill="none"
            stroke="var(--color-status-error)"
            strokeWidth="2"
            opacity="0.9"
          />
        )}
      </svg>

      {/* Plasma orb core */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div
          className="plasma-orb"
          style={
            {
              width: Math.round(size * 0.58),
              height: Math.round(size * 0.58),
              color: isConnected
                ? "var(--color-status-connected)"
                : isError
                  ? "var(--color-status-error)"
                  : isTransitioning
                    ? "#f2f2f2"
                    : "#b8b8b8",
              opacity: isConnected ? 1 : isError ? 0.8 : 0.95,
              "--orb-speed": isTransitioning
                ? "1.8s"
                : isConnected
                  ? "4.5s"
                  : "7s",
              transition: "color 0.4s ease, opacity 0.4s ease",
            } as React.CSSProperties
          }
        >
          <span className="band band-1" />
          <span className="band band-2" />
          <span className="core" />
        </div>
      </div>
    </div>
  );
}
