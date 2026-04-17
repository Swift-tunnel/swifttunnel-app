import type { VpnState } from "../../lib/types";

interface StatusChipProps {
  state: VpnState;
  full?: boolean;
}

function resolveState(state: VpnState) {
  const isConnected = state === "connected";
  const isError = state === "error";
  const isTransitioning = !isConnected && !isError && state !== "disconnected";

  const label = isConnected
    ? "Tunnel active"
    : isTransitioning
      ? "Connecting"
      : isError
        ? "Error"
        : "Disconnected";

  const color = isConnected
    ? "var(--color-status-connected)"
    : isTransitioning
      ? "var(--color-status-warning)"
      : isError
        ? "var(--color-status-error)"
        : "var(--color-status-inactive)";

  return { label, color, isConnected, isTransitioning };
}

export function StatusChip({ state, full }: StatusChipProps) {
  const { label, color, isConnected, isTransitioning } = resolveState(state);

  return (
    <div
      className={`flex items-center gap-2 rounded-[5px] px-2.5 py-1.5 ${full ? "w-full" : ""}`}
      style={{
        backgroundColor: "var(--color-bg-base)",
        border: "1px solid var(--color-border-subtle)",
      }}
    >
      <span className="relative flex h-1.5 w-1.5 shrink-0">
        {isConnected && (
          <span
            className="absolute inset-0 animate-ping rounded-full opacity-60"
            style={{ backgroundColor: color }}
          />
        )}
        <span
          className="relative h-1.5 w-1.5 rounded-full"
          style={{
            backgroundColor: color,
            boxShadow: isConnected
              ? "0 0 6px var(--color-status-connected-glow)"
              : "none",
            animation: isTransitioning
              ? "pulse-opacity 1.2s ease-in-out infinite"
              : "none",
          }}
        />
      </span>
      <span
        className="text-[10.5px] font-medium uppercase tracking-[0.1em]"
        style={{ color: "var(--color-text-secondary)" }}
      >
        {label}
      </span>
    </div>
  );
}
