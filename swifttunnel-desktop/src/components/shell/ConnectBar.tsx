import { useEffect, useState } from "react";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { countryFlag, getLatencyColor } from "../../lib/utils";
import { resolveConnectStatus } from "../connect/connectState";
import { Spinner } from "../ui/Spinner";

function formatElapsed(s: number): string {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h > 0
    ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
    : `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
}

export function ConnectBar() {
  const vpnState = useVpnStore((s) => s.state);
  const vpnRegion = useVpnStore((s) => s.region);
  const serverEndpoint = useVpnStore((s) => s.serverEndpoint);
  const ping = useVpnStore((s) => s.ping);
  const connectedAt = useVpnStore((s) => s.connectedAt);
  const driverSetupState = useVpnStore((s) => s.driverSetupState);
  const driverSetupError = useVpnStore((s) => s.driverSetupError);
  const vpnError = useVpnStore((s) => s.error);
  const connect = useVpnStore((s) => s.connect);
  const disconnect = useVpnStore((s) => s.disconnect);
  const installDriver = useVpnStore((s) => s.installDriver);

  const settings = useSettingsStore((s) => s.settings);
  const save = useSettingsStore((s) => s.save);
  const setTab = useSettingsStore((s) => s.setTab);

  const regions = useServerStore((s) => s.regions);
  const servers = useServerStore((s) => s.servers);
  const getLatency = useServerStore((s) => s.getLatency);

  const isConnected = vpnState === "connected";
  const isIdle = vpnState === "disconnected" || vpnState === "error";
  const isTransitioning = !isConnected && !isIdle;

  const connectStatus = resolveConnectStatus({
    driverSetupState,
    driverSetupError,
    vpnError,
    vpnState,
  });

  const selectedRegion = regions.find((r) => r.id === settings.selected_region);
  const cachedLatency = getLatency(settings.selected_region);
  const connectedRegion = findRegionForVpnRegion(regions, vpnRegion);
  const connectedServerName = (() => {
    if (!serverEndpoint) return null;
    const host = serverEndpoint.includes("://")
      ? new URL(serverEndpoint).hostname
      : serverEndpoint.split(":")[0];
    return servers.find((s) => s.ip === host)?.name ?? null;
  })();

  // Live elapsed timer
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (connectedAt === null) {
      setElapsed(0);
      return;
    }
    setElapsed(Math.floor((Date.now() - connectedAt) / 1000));
    const id = setInterval(
      () => setElapsed(Math.floor((Date.now() - connectedAt) / 1000)),
      1000,
    );
    return () => clearInterval(id);
  }, [connectedAt]);

  const canConnect =
    isIdle &&
    (settings.auto_routing_enabled || Boolean(settings.selected_region));

  const primaryDisabled =
    (isTransitioning) ||
    (isIdle && !canConnect && connectStatus.kind !== "driver_missing");

  async function handlePrimary() {
    if (connectStatus.kind === "driver_missing") {
      void installDriver().catch(() => {});
      return;
    }
    if (isConnected) {
      disconnect();
      return;
    }
    if (!isIdle || !canConnect) return;
    await save();
    connect(settings.selected_region, settings.selected_game_presets);
  }

  // Left side content
  const leftContent = (() => {
    if (isConnected) {
      return (
        <div className="flex min-w-0 flex-col gap-0.5 leading-none">
          <span className="text-[9.5px] font-semibold uppercase tracking-[0.12em] text-text-dimmed">
            Active route
          </span>
          <div className="flex items-center gap-2 text-[13px]">
            <span className="font-medium text-text-primary">
              {connectedRegion?.name || vpnRegion || "Unknown"}
            </span>
            {connectedServerName && (
              <>
                <span className="text-text-dimmed">·</span>
                <span className="font-mono text-[11.5px] text-text-muted">
                  {connectedServerName}
                </span>
              </>
            )}
          </div>
        </div>
      );
    }
    if (isTransitioning) {
      return (
        <div className="flex min-w-0 flex-col gap-0.5 leading-none">
          <span className="text-[9.5px] font-semibold uppercase tracking-[0.12em] text-text-dimmed">
            Establishing
          </span>
          <span className="text-[13px] font-medium text-text-secondary">
            {connectStatus.text}
          </span>
        </div>
      );
    }
    // Idle / error
    return (
      <div className="flex min-w-0 flex-col gap-0.5 leading-none">
        <span className="text-[9.5px] font-semibold uppercase tracking-[0.12em] text-text-dimmed">
          Target
        </span>
        {settings.auto_routing_enabled ? (
          <span className="text-[13px] font-medium text-text-primary">
            Auto Route
          </span>
        ) : selectedRegion ? (
          <span className="flex items-center gap-1.5 text-[13px] font-medium text-text-primary">
            <span className="text-[14px] leading-none">
              {countryFlag(selectedRegion.country_code)}
            </span>
            {selectedRegion.name}
          </span>
        ) : (
          <span className="text-[13px] font-medium text-text-muted">
            Select a region to begin
          </span>
        )}
      </div>
    );
  })();

  // Middle telemetry (connected only)
  const telemetry =
    isConnected && (
      <div className="hidden items-center gap-5 md:flex">
        <div className="flex flex-col items-end gap-0.5 leading-none">
          <span className="text-[9.5px] font-semibold uppercase tracking-[0.12em] text-text-dimmed">
            Latency
          </span>
          <span
            className="font-mono text-[16px] font-semibold"
            style={{
              color: ping !== null ? getLatencyColor(ping) : "var(--color-text-muted)",
            }}
          >
            {ping !== null ? `${ping}` : "—"}
            <span className="ml-0.5 text-[10px] font-medium text-text-muted">
              ms
            </span>
          </span>
        </div>
        <div
          className="h-8 w-px"
          style={{ backgroundColor: "var(--color-border-subtle)" }}
        />
        <div className="flex flex-col items-end gap-0.5 leading-none">
          <span className="text-[9.5px] font-semibold uppercase tracking-[0.12em] text-text-dimmed">
            Session
          </span>
          <span className="font-mono text-[16px] font-semibold text-text-primary">
            {formatElapsed(elapsed)}
          </span>
        </div>
      </div>
    );

  // Primary button label
  const buttonLabel = (() => {
    if (connectStatus.kind === "driver_missing") return "Install Driver";
    if (isConnected) return "Disconnect";
    if (isTransitioning) return "Connecting…";
    return "Connect";
  })();

  // Button styling
  const buttonStyle = (() => {
    if (isConnected) {
      return {
        backgroundColor: "var(--color-status-error-soft-10)",
        color: "var(--color-status-error)",
        border: "1px solid var(--color-status-error-soft-20)",
      };
    }
    if (isTransitioning) {
      return {
        backgroundColor: "var(--color-bg-elevated)",
        color: "var(--color-text-muted)",
        border: "1px solid var(--color-border-default)",
      };
    }
    return {
      background:
        "linear-gradient(180deg, var(--color-status-connected), #22b381)",
      color: "#04140e",
      border: "1px solid rgba(40,210,150,0.5)",
      boxShadow:
        "0 0 0 1px rgba(40,210,150,0.25), 0 4px 18px rgba(40,210,150,0.28), inset 0 1px 0 rgba(255,255,255,0.15)",
    };
  })();

  const idleLatencyBadge =
    isIdle && !settings.auto_routing_enabled && cachedLatency !== null ? (
      <span
        className="rounded-[3px] px-1.5 py-0.5 font-mono text-[10.5px] font-semibold"
        style={{
          backgroundColor: "var(--color-bg-elevated)",
          color: getLatencyColor(cachedLatency),
        }}
      >
        {cachedLatency}ms
      </span>
    ) : null;

  // Error state — allow clicking to jump to Connect tab for context
  const inError = vpnState === "error" || connectStatus.kind === "driver_missing";

  return (
    <div
      className="flex shrink-0 items-center gap-4 border-t px-5"
      style={{
        height: "var(--spacing-connect-bar)",
        backgroundColor: "var(--color-bg-sidebar)",
        borderColor: "var(--color-border-subtle)",
      }}
    >
      {/* Left: target / current route */}
      <div className="flex min-w-0 flex-1 items-center gap-2.5">
        {leftContent}
        {idleLatencyBadge}
      </div>

      {/* Middle: telemetry */}
      {telemetry}

      {/* Right: primary action */}
      <button
        type="button"
        onClick={handlePrimary}
        disabled={primaryDisabled}
        className="group relative inline-flex h-10 shrink-0 items-center gap-2 overflow-hidden rounded-[var(--radius-button)] px-5 text-[12.5px] font-semibold uppercase tracking-[0.1em] transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-status-connected)] focus-visible:ring-offset-2 focus-visible:ring-offset-[color:var(--color-bg-sidebar)] disabled:cursor-not-allowed disabled:opacity-60"
        style={buttonStyle}
        onMouseEnter={(e) => {
          if (!primaryDisabled && !isConnected && !isTransitioning) {
            e.currentTarget.style.transform = "translateY(-1px)";
          }
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = "translateY(0)";
        }}
      >
        {/* Shimmer on idle */}
        {isIdle && !primaryDisabled && !inError && (
          <span
            aria-hidden
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                "linear-gradient(100deg, transparent 30%, rgba(255,255,255,0.22) 50%, transparent 70%)",
              animation: "sweep-shine 3.4s ease-in-out infinite",
            }}
          />
        )}

        <span className="relative flex items-center gap-2">
          {isTransitioning ? (
            <Spinner size={12} thickness={1.5} />
          ) : connectStatus.kind === "driver_missing" ? (
            <svg
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 5v14M5 12h14" />
            </svg>
          ) : isConnected ? (
            <svg
              width="11"
              height="11"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect x="5" y="5" width="14" height="14" rx="1" />
            </svg>
          ) : (
            <svg
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 2v10" />
              <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
            </svg>
          )}
          {buttonLabel}
        </span>
      </button>

      {/* Error nudge — if error and not on Connect tab, suggest opening it */}
      {inError &&
        useSettingsStore.getState().activeTab !== "connect" &&
        connectStatus.kind !== "driver_missing" && (
          <button
            type="button"
            onClick={() => setTab("connect")}
            className="text-[10.5px] font-medium text-text-muted underline-offset-2 hover:text-text-primary hover:underline"
          >
            Details
          </button>
        )}
    </div>
  );
}
