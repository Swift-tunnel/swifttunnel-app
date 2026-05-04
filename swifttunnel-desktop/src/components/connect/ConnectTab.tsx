import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import {
  countryFlag,
  formatBytes,
  getLatencyColor,
} from "../../lib/utils";
import { formatConnectedServerLabel } from "../../lib/connectedServer";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import {
  useActiveInterval,
  useRendererActivityStore,
} from "../../lib/rendererActivity";
import {
  isConnectActionBusy,
  resolveConnectStatus,
  stateLabel,
} from "./connectState";
import { LiveGraph, type DataSample } from "./LiveGraph";
import { Button, EmptyState, Tooltip, InfoIcon, Toggle } from "../ui";
import type { ServerRegion } from "../../lib/types";

type ConnectStatus = ReturnType<typeof resolveConnectStatus>;

const DATA_BUFFER_SIZE = 60;

function formatElapsed(s: number): string {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h > 0
    ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
    : `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
}

export function ConnectTab() {
  const vpnState = useVpnStore((s) => s.state);
  const vpnRegion = useVpnStore((s) => s.region);
  const serverEndpoint = useVpnStore((s) => s.serverEndpoint);
  const tunneled = useVpnStore((s) => s.tunneledProcesses);
  const bytesUp = useVpnStore((s) => s.bytesUp);
  const bytesDown = useVpnStore((s) => s.bytesDown);
  const ping = useVpnStore((s) => s.ping);
  const connectedAt = useVpnStore((s) => s.connectedAt);
  const driverSetupState = useVpnStore((s) => s.driverSetupState);
  const driverSetupError = useVpnStore((s) => s.driverSetupError);
  const driverStatus = useVpnStore((s) => s.driverStatus);
  const driverResetAttempted = useVpnStore((s) => s.driverResetAttempted);
  const vpnError = useVpnStore((s) => s.error);
  const connect = useVpnStore((s) => s.connect);
  const disconnect = useVpnStore((s) => s.disconnect);
  const repairDriver = useVpnStore((s) => s.repairDriver);
  const resetDriver = useVpnStore((s) => s.resetDriver);
  const installDriver = useVpnStore((s) => s.installDriver);
  const fetchThroughput = useVpnStore((s) => s.fetchThroughput);
  const fetchPing = useVpnStore((s) => s.fetchPing);
  const fetchState = useVpnStore((s) => s.fetchState);

  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const save = useSettingsStore((s) => s.save);

  const regions = useServerStore((s) => s.regions);
  const servers = useServerStore((s) => s.servers);
  const serversLoading = useServerStore((s) => s.isLoading);
  const serversError = useServerStore((s) => s.error);
  const getLatency = useServerStore((s) => s.getLatency);
  const fetchLatencies = useServerStore((s) => s.fetchLatencies);
  const refreshServers = useServerStore((s) => s.refresh);
  const rendererActive = useRendererActivityStore((s) => s.isActive);

  const connectedRegion = findRegionForVpnRegion(regions, vpnRegion);
  const connectedServerLabel = formatConnectedServerLabel(
    serverEndpoint,
    servers,
    vpnRegion,
  );

  const isConnected = vpnState === "connected";
  const isIdle = vpnState === "disconnected" || vpnState === "error";
  const isTransitioning = !isConnected && !isIdle;
  const isConnectBusy = isConnectActionBusy({ vpnState, driverSetupState });

  const connectStatus = resolveConnectStatus({
    driverSetupState,
    driverSetupError,
    driverStatus,
    vpnError,
    vpnState,
    driverResetAttempted,
  });

  const selectedRegion = regions.find((r) => r.id === settings.selected_region);
  const cachedLatency = getLatency(settings.selected_region);

  const [dataHistory, setDataHistory] = useState<DataSample[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const prevBytesRef = useRef<{ up: number; down: number; t: number } | null>(
    null,
  );
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function saveDebounced() {
    if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
    saveTimeoutRef.current = setTimeout(() => {
      saveTimeoutRef.current = null;
      void save();
    }, 500);
  }

  useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
        void save();
      }
    };
  }, [save]);

  useActiveInterval(fetchThroughput, 1000, isConnected);

  useEffect(() => {
    if (!isConnected) {
      setDataHistory([]);
      prevBytesRef.current = null;
      return;
    }
    if (!rendererActive) {
      prevBytesRef.current = null;
    }
  }, [isConnected, rendererActive]);

  useActiveInterval(
    () => {
      const { bytesUp, bytesDown } = useVpnStore.getState();
      const now = Date.now();
      const prev = prevBytesRef.current;
      if (prev) {
        const dtMs = Math.max(1, now - prev.t);
        const up = Math.max(0, ((bytesUp - prev.up) / dtMs) * 1000);
        const down = Math.max(0, ((bytesDown - prev.down) / dtMs) * 1000);
        setDataHistory((h) =>
          [...h, { t: now, up, down }].slice(-DATA_BUFFER_SIZE),
        );
      }
      prevBytesRef.current = { up: bytesUp, down: bytesDown, t: now };
    },
    1000,
    isConnected,
  );

  useActiveInterval(
    () => fetchState(),
    2000,
    isConnected || isTransitioning,
  );

  useEffect(() => {
    if (!rendererActive) return;
    void fetchLatencies();
  }, [fetchLatencies, rendererActive]);

  useActiveInterval(() => fetchLatencies(), 15000);
  useActiveInterval(fetchPing, 3000, isConnected);

  useEffect(() => {
    if (connectedAt === null) {
      setElapsed(0);
      return;
    }
    setElapsed(Math.floor((Date.now() - connectedAt) / 1000));
  }, [connectedAt, rendererActive]);

  useActiveInterval(
    () => {
      if (connectedAt !== null) {
        setElapsed(Math.floor((Date.now() - connectedAt) / 1000));
      }
    },
    1000,
    connectedAt !== null,
  );

  useEffect(() => {
    if (!rendererActive) return;
    if (isConnected || isTransitioning) {
      void fetchState();
    }
    if (isConnected) {
      void fetchThroughput();
      void fetchPing();
    }
  }, [
    fetchPing,
    fetchState,
    fetchThroughput,
    isConnected,
    isTransitioning,
    rendererActive,
  ]);

  function selectRegion(regionId: string) {
    update({ selected_region: regionId, auto_routing_enabled: false });
    saveDebounced();
  }

  function selectAutoRoute() {
    update({ auto_routing_enabled: true });
    saveDebounced();
  }

  function forceServer(regionId: string, server: string | null) {
    const cur = { ...settings.forced_servers };
    if (server) cur[regionId] = server;
    else delete cur[regionId];
    update({ forced_servers: cur });
    saveDebounced();
  }

  function setRouteAssist(enabled: boolean) {
    update({ enable_api_tunneling: enabled });
    saveDebounced();
  }

  const canConnect =
    isIdle &&
    (settings.auto_routing_enabled || Boolean(settings.selected_region));
  const hasDriverAction =
    connectStatus.kind === "driver_missing" ||
    connectStatus.kind === "driver_repair" ||
    connectStatus.kind === "reboot_resettable" ||
    connectStatus.kind === "driver_outdated";

  const primaryDisabled =
    isConnectBusy ||
    connectStatus.kind === "reboot_required" ||
    (isIdle && !canConnect && !hasDriverAction);

  async function flushSettingsSave() {
    if (saveTimeoutRef.current !== null) {
      clearTimeout(saveTimeoutRef.current);
      saveTimeoutRef.current = null;
    }
    await save();
  }

  async function handlePrimary() {
    if (connectStatus.kind === "driver_missing") {
      void installDriver().catch(() => {});
      return;
    }
    if (connectStatus.kind === "driver_repair") {
      void repairDriver().catch(() => {});
      return;
    }
    if (
      connectStatus.kind === "reboot_resettable" ||
      connectStatus.kind === "driver_outdated"
    ) {
      void resetDriver().catch(() => {});
      return;
    }
    if (connectStatus.kind === "reboot_required") {
      return;
    }
    if (isConnected) {
      void disconnect();
      return;
    }
    if (!isIdle || !canConnect || isConnectBusy) return;
    await flushSettingsSave();
    void connect(settings.selected_region, ["roblox"]);
  }

  const heroEyebrow = isConnected
    ? "Tunneled to"
    : vpnState === "disconnecting"
      ? "Disconnecting"
      : isTransitioning
        ? "Establishing"
        : vpnState === "error"
          ? "Connection failed"
          : "Ready to tunnel";

  const heroRegion = isConnected
    ? connectedRegion
    : !settings.auto_routing_enabled
      ? selectedRegion
      : null;

  const heroRegionName = isConnected
    ? connectedRegion?.name || vpnRegion || "Unknown"
    : isTransitioning
      ? stateLabel(vpnState)
      : settings.auto_routing_enabled
        ? "Auto Route"
        : selectedRegion?.name || "Select a region";

  const heroLatency = isConnected && ping !== null ? ping : cachedLatency;

  const buttonLabel = (() => {
    if (connectStatus.kind === "driver_missing") return "Install driver";
    if (connectStatus.kind === "driver_repair") return connectStatus.buttonText;
    if (connectStatus.kind === "reboot_resettable") return "Reset driver";
    if (connectStatus.kind === "driver_outdated") return "Reset driver";
    if (connectStatus.kind === "reboot_required") return "Restart required";
    if (isConnected) return "Disconnect";
    if (vpnState === "disconnecting") return "Disconnecting…";
    if (isConnectBusy) return isTransitioning ? "Connecting…" : "Working…";
    return "Connect";
  })();

  const buttonVariant: "primary" | "destructive" | "secondary" | "connect" =
    isConnected
      ? "destructive"
      : isConnectBusy || hasDriverAction || connectStatus.kind === "reboot_required"
        ? "secondary"
        : "primary";

  const hasRegions = regions.length > 0;

  return (
    <div className="flex w-full flex-col gap-4 pb-6">
      {/* ── Hero card ── */}
      <section
        className={`relative overflow-hidden rounded-[var(--radius-card)] surface-card ${isConnected ? "connected-ambience" : ""}`}
        style={{
          padding: "20px 22px",
        }}
      >
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <StatusDot vpnState={vpnState} />
              <span className="eyebrow">{heroEyebrow}</span>
              {isConnected && (
                <span
                  className="pill-base"
                  style={{
                    backgroundColor: "var(--color-status-connected-soft-10)",
                    color: "var(--color-status-connected)",
                    border: "1px solid var(--color-status-connected-soft-20)",
                  }}
                >
                  Live
                </span>
              )}
            </div>

            <div className="mt-2.5 flex items-center gap-2.5">
              {heroRegion && (
                <span className="text-[20px] leading-none">
                  {countryFlag(heroRegion.country_code)}
                </span>
              )}
              <span
                className="truncate text-[20px] font-semibold leading-[1.1] text-text-primary"
                style={{ letterSpacing: "-0.02em" }}
              >
                {heroRegionName}
              </span>
            </div>

            {isConnected && (
              <div
                className="mt-1.5 truncate font-mono text-[11.5px] text-text-muted"
                title={connectedServerLabel}
              >
                {connectedServerLabel}
              </div>
            )}

            <div className="mt-4 flex items-center gap-5">
              <HeroStat
                label="Latency"
                value={heroLatency !== null ? String(heroLatency) : "—"}
                unit="ms"
                color={
                  heroLatency !== null
                    ? getLatencyColor(heroLatency)
                    : undefined
                }
              />
              {isConnected && (
                <>
                  <HeroDivider />
                  <HeroStat
                    label="Session"
                    value={formatElapsed(elapsed)}
                    mono
                  />
                </>
              )}
              {isConnected && tunneled.length > 0 && (
                <>
                  <HeroDivider />
                  <HeroStat
                    label="Routing"
                    value={`${tunneled.length}`}
                    unit={tunneled.length === 1 ? "app" : "apps"}
                  />
                </>
              )}
            </div>
          </div>

          <Button
            variant={buttonVariant}
            size="lg"
            onClick={handlePrimary}
            disabled={primaryDisabled}
            loading={isConnectBusy}
          >
            {buttonLabel}
          </Button>
        </div>

        {(connectStatus.kind !== "text" ||
          vpnState === "error" ||
          driverSetupState !== "idle") && (
          <ConnectStatusBanner
            status={connectStatus}
            busy={isConnectBusy}
            onRepair={() => void repairDriver().catch(() => {})}
            onReset={() => void resetDriver().catch(() => {})}
          />
        )}
      </section>

      <RouteAssistPanel
        enabled={settings.enable_api_tunneling}
        disabled={isConnected || isTransitioning}
        onChange={setRouteAssist}
      />

      {/* ── Throughput (connected) ── */}
      {isConnected && (
        <motion.section
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
          className="flex flex-col gap-2.5"
        >
          <LiveGraph samples={dataHistory} />

          <div className="grid grid-cols-4 overflow-hidden rounded-[var(--radius-card)] surface-card">
            <MetricCell label="Upload" value={formatBytes(bytesUp)} mono divider />
            <MetricCell label="Download" value={formatBytes(bytesDown)} mono divider />
            <MetricCell label="Session" value={formatElapsed(elapsed)} mono divider />
            <MetricCell
              label="Ping"
              value={ping !== null ? `${ping}` : "—"}
              hint={ping !== null ? "ms" : undefined}
              mono
              valueColor={
                ping !== null
                  ? getLatencyColor(ping)
                  : "var(--color-text-muted)"
              }
            />
          </div>

          {tunneled.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {tunneled.map((p) => (
                <span
                  key={p}
                  className="inline-flex items-center gap-1.5 rounded-[5px] px-2 py-1 font-mono text-[10.5px]"
                  style={{
                    backgroundColor: "var(--color-bg-card)",
                    border: "1px solid var(--color-border-subtle)",
                    color: "var(--color-text-secondary)",
                  }}
                >
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{
                      backgroundColor: "var(--color-status-connected)",
                      boxShadow: "0 0 4px var(--color-status-connected-glow)",
                    }}
                  />
                  {p}
                </span>
              ))}
            </div>
          )}
        </motion.section>
      )}

      {/* ── Regions ── */}
      <section className="mt-1">
        <div className="mb-2.5 flex items-baseline justify-between">
          <div className="flex items-baseline gap-2">
            <h3
              className="text-[12.5px] font-semibold text-text-primary"
              style={{ letterSpacing: "-0.005em" }}
            >
              Regions
            </h3>
            {hasRegions && (
              <span className="font-mono text-[11px] text-text-dimmed">
                {regions.length}
              </span>
            )}
          </div>
          {hasRegions && !isConnected && (
            <button
              onClick={() => void refreshServers()}
              className="inline-flex items-center gap-1.5 rounded-[5px] px-2 py-1 text-[11px] font-medium text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
            >
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
                <path d="M23 4v6h-6M1 20v-6h6" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </svg>
              Refresh
            </button>
          )}
        </div>

        {!hasRegions ? (
          <EmptyState
            loading={serversLoading}
            title={
              serversLoading
                ? "Loading regions…"
                : serversError
                  ? "Could not load regions"
                  : "No regions available"
            }
            description={
              serversLoading
                ? "Fetching server list"
                : serversError
                  ? "Check your internet connection and try again"
                  : undefined
            }
            action={
              !serversLoading
                ? { label: "Retry", onClick: () => void refreshServers() }
                : undefined
            }
          />
        ) : (
          <div className="flex flex-col overflow-hidden rounded-[var(--radius-card)] surface-card">
            <AutoRouteRow
              active={settings.auto_routing_enabled}
              disabled={isConnected || isTransitioning}
              onClick={selectAutoRoute}
            />
            {regions.map((r, idx) => (
              <RegionRow
                key={r.id}
                region={r}
                selected={
                  !settings.auto_routing_enabled &&
                  settings.selected_region === r.id
                }
                lastUsed={settings.last_connected_region === r.id}
                latency={getLatency(r.id)}
                disabled={isConnected || isTransitioning}
                onSelect={() => selectRegion(r.id)}
                forcedServer={settings.forced_servers[r.id]}
                onForceServer={forceServer}
                isLast={idx === regions.length - 1}
              />
            ))}
          </div>
        )}

        {hasRegions && settings.auto_routing_enabled && (
          <WhitelistPanel
            regions={regions}
            whitelisted={settings.whitelisted_regions}
            disabled={isConnected || isTransitioning}
            onChange={(next) => {
              update({ whitelisted_regions: next });
              saveDebounced();
            }}
          />
        )}
      </section>
    </div>
  );
}

// ── Sub-components ──

function StatusDot({ vpnState }: { vpnState: string }) {
  const isConnected = vpnState === "connected";
  const isError = vpnState === "error";
  const isTransitioning =
    !isConnected &&
    vpnState !== "disconnected" &&
    !isError;

  const color = isConnected
    ? "var(--color-status-connected)"
    : isError
      ? "var(--color-status-error)"
      : isTransitioning
        ? "var(--color-status-warning)"
        : "var(--color-text-dimmed)";

  return (
    <span className="relative inline-flex h-2 w-2 items-center justify-center">
      <span
        className="absolute inset-0 rounded-full"
        style={{
          backgroundColor: color,
          boxShadow: isConnected ? `0 0 6px ${color}` : "none",
          animation: isTransitioning
            ? "status-breath 1.4s ease-in-out infinite"
            : "none",
        }}
      />
    </span>
  );
}

function HeroStat({
  label,
  value,
  unit,
  color,
  mono,
}: {
  label: string;
  value: string;
  unit?: string;
  color?: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <div className="flex items-baseline gap-1">
        <span
          className={`lcd-readout text-[18px] font-medium leading-none ${mono ? "" : ""}`}
          style={{ color: color || "var(--color-text-primary)" }}
        >
          {value}
        </span>
        {unit && (
          <span className="text-[11px] text-text-muted">{unit}</span>
        )}
      </div>
    </div>
  );
}

function HeroDivider() {
  return (
    <span
      className="h-7 w-px"
      style={{ backgroundColor: "var(--color-border-subtle)" }}
    />
  );
}

function RouteAssistPanel({
  enabled,
  disabled,
  onChange,
}: {
  enabled: boolean;
  disabled: boolean;
  onChange: (enabled: boolean) => void;
}) {
  return (
    <section
      className="flex items-center justify-between gap-4 rounded-[var(--radius-card)] px-4 py-3 transition-colors"
      style={{
        backgroundColor: enabled
          ? "var(--color-accent-primary-soft-8)"
          : "var(--color-bg-card)",
        border: `1px solid ${
          enabled
            ? "var(--color-accent-primary-soft-20)"
            : "var(--color-border-subtle)"
        }`,
        boxShadow: enabled
          ? "inset 0 1px 0 rgba(255,255,255,0.04)"
          : "inset 0 1px 0 rgba(255,255,255,0.025)",
      }}
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <svg
            width="13"
            height="13"
            viewBox="0 0 24 24"
            fill="none"
            stroke={enabled ? "var(--color-text-primary)" : "var(--color-text-muted)"}
            strokeWidth="1.85"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M3 12h4l3-9 4 18 3-9h4" />
          </svg>
          <h3
            className="text-[12.5px] font-semibold text-text-primary"
            style={{ letterSpacing: "-0.005em" }}
          >
            Roblox Route Assist
          </h3>
          <Tooltip content="Routes Roblox login/API HTTP(S) through the selected relay, including browser-owned Roblox auth traffic. Non-Roblox browser traffic still bypasses SwiftTunnel.">
            <span className="inline-flex">
              <InfoIcon />
            </span>
          </Tooltip>
          {enabled && (
            <span
              className="pill-base"
              style={{
                backgroundColor: "var(--color-bg-base)",
                color: "var(--color-text-primary)",
                border: "1px solid var(--color-border-default)",
              }}
            >
              ON
            </span>
          )}
        </div>
        <p className="mt-1 max-w-[640px] text-[11.5px] leading-snug text-text-muted">
          Use this when bypassing a network ban, or to increase the chance Roblox places you near your tunneled region.
        </p>
      </div>
      <Toggle
        enabled={enabled}
        disabled={disabled}
        ariaLabel="Roblox Route Assist"
        onChange={onChange}
      />
    </section>
  );
}

function MetricCell({
  label,
  value,
  hint,
  mono,
  valueColor,
  divider,
}: {
  label: string;
  value: string;
  hint?: string;
  mono?: boolean;
  valueColor?: string;
  divider?: boolean;
}) {
  return (
    <div
      className="flex flex-col gap-1 px-4 py-2.5"
      style={{
        borderRight: divider
          ? "1px solid var(--color-border-subtle)"
          : undefined,
      }}
    >
      <span className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <div className="flex items-baseline gap-1">
        <span
          className={`text-[13.5px] font-medium ${mono ? "font-mono tabular-nums" : ""}`}
          style={{ color: valueColor || "var(--color-text-primary)" }}
        >
          {value}
        </span>
        {hint && (
          <span className="text-[10.5px] text-text-muted">{hint}</span>
        )}
      </div>
    </div>
  );
}

function ConnectStatusBanner({
  status,
  busy,
  onRepair,
  onReset,
}: {
  status: ConnectStatus;
  busy: boolean;
  onRepair: () => void;
  onReset: () => void;
}) {
  const isError =
    status.kind === "reboot_required" ||
    status.kind === "reboot_resettable" ||
    status.kind === "driver_outdated";
  const button =
    status.kind === "driver_missing"
      ? { label: "Install", onClick: onRepair }
      : status.kind === "driver_repair"
        ? { label: status.buttonText, onClick: onRepair }
        : status.kind === "reboot_resettable" || status.kind === "driver_outdated"
          ? { label: "Reset driver service", onClick: onReset }
          : null;

  return (
    <div
      className="mt-3 flex flex-wrap items-center gap-2 rounded-[6px] px-3 py-2 text-[11.5px]"
      style={{
        backgroundColor: isError
          ? "var(--color-status-error-soft-10)"
          : "var(--color-bg-elevated)",
        border: `1px solid ${
          isError
            ? "var(--color-status-error-soft-20)"
            : "var(--color-border-subtle)"
        }`,
        color: isError
          ? "var(--color-status-error)"
          : "var(--color-text-secondary)",
      }}
    >
      <span>{status.text}</span>
      {button && (
        <Button
          variant="secondary"
          size="sm"
          onClick={button.onClick}
          disabled={busy}
        >
          {button.label}
        </Button>
      )}
    </div>
  );
}

function AutoRouteRow({
  active,
  disabled,
  onClick,
}: {
  active: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="group relative flex w-full items-center gap-3 px-3.5 py-2.5 text-left transition-colors duration-100 disabled:cursor-not-allowed disabled:opacity-50"
      style={{
        backgroundColor: active
          ? "var(--color-accent-primary-soft-8)"
          : "transparent",
        borderBottom: "1px solid var(--color-border-subtle)",
      }}
      onMouseEnter={(e) => {
        if (!active && !disabled)
          e.currentTarget.style.backgroundColor = "var(--color-bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.backgroundColor = "transparent";
      }}
    >
      {active && (
        <span
          className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2 rounded-r"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        />
      )}
      <span
        className="flex h-7 w-7 items-center justify-center rounded-[6px]"
        style={{
          backgroundColor: active
            ? "var(--color-accent-primary-soft-12)"
            : "var(--color-bg-elevated)",
          border: `1px solid ${active ? "var(--color-accent-primary-soft-20)" : "var(--color-border-subtle)"}`,
        }}
      >
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke={active ? "var(--color-text-primary)" : "var(--color-text-muted)"}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="16 3 21 3 21 8" />
          <line x1="4" y1="20" x2="21" y2="3" />
          <polyline points="21 16 21 21 16 21" />
          <line x1="15" y1="15" x2="21" y2="21" />
        </svg>
      </span>
      <div className="flex min-w-0 flex-1 flex-col leading-tight">
        <div className="flex items-center gap-2">
          <span
            className="text-[12.5px] font-medium text-text-primary"
            style={{ letterSpacing: "-0.005em" }}
          >
            Auto Route
          </span>
          <Tooltip content="Picks the fastest relay to the game server each match.">
            <span className="inline-flex">
              <InfoIcon />
            </span>
          </Tooltip>
        </div>
        <span className="text-[11px] text-text-muted">
          Picks the fastest relay for every match
        </span>
      </div>
      {active && (
        <span
          className="pill-base"
          style={{
            backgroundColor: "var(--color-accent-primary-soft-12)",
            color: "var(--color-text-primary)",
          }}
        >
          Active
        </span>
      )}
    </button>
  );
}

function RegionRow({
  region,
  selected,
  lastUsed,
  latency,
  disabled,
  onSelect,
  forcedServer,
  onForceServer,
  isLast,
}: {
  region: ServerRegion;
  selected: boolean;
  lastUsed: boolean;
  latency: number | null;
  disabled: boolean;
  onSelect: () => void;
  forcedServer: string | undefined;
  onForceServer: (regionId: string, server: string | null) => void;
  isLast: boolean;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [hover, setHover] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const latColor = latency !== null ? getLatencyColor(latency) : null;

  useEffect(() => {
    if (!menuOpen) return;
    function handle(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node))
        setMenuOpen(false);
    }
    document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, [menuOpen]);

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      className={`group relative flex h-[38px] items-center gap-3 px-3.5 text-left transition-colors duration-100 ${
        disabled ? "cursor-not-allowed opacity-50" : ""
      }`}
      style={{
        backgroundColor: selected
          ? "var(--color-accent-primary-soft-8)"
          : hover && !disabled
            ? "var(--color-bg-hover)"
            : "transparent",
        borderBottom: isLast
          ? "none"
          : "1px solid var(--color-border-subtle)",
      }}
    >
      {selected && (
        <span
          className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2 rounded-r"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        />
      )}
      <button
        type="button"
        onClick={onSelect}
        disabled={disabled}
        className="flex min-w-0 flex-1 items-center gap-3 self-stretch text-left disabled:cursor-not-allowed"
      >
        <span className="text-[15px] leading-none">
          {countryFlag(region.country_code)}
        </span>

        <span
          className="truncate text-[12.5px] font-medium text-text-primary"
          style={{ letterSpacing: "-0.005em" }}
        >
          {region.name}
        </span>

        {forcedServer ? (
          <span
            className="font-mono text-[10px] text-text-secondary"
            title={`Forced server: ${forcedServer}`}
          >
            {forcedServer}
          </span>
        ) : (
          <span className="font-mono text-[10px] text-text-dimmed">
            {region.servers.length}
          </span>
        )}

        {lastUsed && !selected && (
          <span
            className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-muted"
          >
            Last
          </span>
        )}

        <span className="flex-1" />
      </button>

      {/* Fixed-width latency slot — always same position */}
      <div className="flex w-[64px] shrink-0 items-center justify-end gap-1.5">
        {latency !== null && latColor ? (
          <>
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: latColor }}
            />
            <span
              className="w-[28px] text-right font-mono text-[11.5px] font-medium tabular-nums text-text-primary"
            >
              {latency}
            </span>
            <span className="w-[14px] text-[10px] text-text-muted">ms</span>
          </>
        ) : null}
      </div>

      {/* Fixed-width menu slot — invisible placeholder when no menu */}
      <div className="flex w-6 shrink-0 items-center justify-center">
        {region.servers.length > 1 && (
          <ServerMenu
            menuRef={menuRef}
            open={menuOpen}
            disabled={disabled}
            onToggle={() => setMenuOpen((v) => !v)}
            servers={region.servers}
            forcedServer={forcedServer}
            onForceServer={(srv) => {
              onForceServer(region.id, srv);
              setMenuOpen(false);
            }}
          />
        )}
      </div>
    </div>
  );
}

function ServerMenu({
  menuRef,
  open,
  disabled,
  onToggle,
  servers,
  forcedServer,
  onForceServer,
}: {
  menuRef: React.RefObject<HTMLDivElement | null>;
  open: boolean;
  disabled: boolean;
  onToggle: () => void;
  servers: string[];
  forcedServer: string | undefined;
  onForceServer: (server: string | null) => void;
}) {
  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        aria-label="Choose server"
        aria-expanded={open}
        disabled={disabled}
        onClick={(e) => {
          e.stopPropagation();
          onToggle();
        }}
        className={`flex h-6 w-6 items-center justify-center rounded-[5px] transition-all focus:opacity-100 group-hover:opacity-100 disabled:cursor-not-allowed ${
          open || forcedServer ? "opacity-100" : "opacity-0"
        }`}
        style={{
          color: forcedServer
            ? "var(--color-text-primary)"
            : "var(--color-text-muted)",
          backgroundColor: open ? "var(--color-bg-hover)" : "transparent",
        }}
      >
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
          <circle cx="12" cy="12" r="1" />
          <circle cx="19" cy="12" r="1" />
          <circle cx="5" cy="12" r="1" />
        </svg>
      </button>

      {open && (
        <div
          onClick={(e) => e.stopPropagation()}
          className="absolute right-0 top-7 z-50 min-w-[140px] overflow-hidden rounded-[6px] surface-elevated"
        >
          <ServerMenuItem
            label="Auto"
            active={!forcedServer}
            onClick={(e) => {
              e.stopPropagation();
              onForceServer(null);
            }}
          />
          <div
            className="h-px"
            style={{ backgroundColor: "var(--color-border-subtle)" }}
          />
          {servers.map((srv) => (
            <ServerMenuItem
              key={srv}
              label={srv}
              active={forcedServer === srv}
              mono
              onClick={(e) => {
                e.stopPropagation();
                onForceServer(srv);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ServerMenuItem({
  label,
  active,
  mono,
  onClick,
}: {
  label: string;
  active: boolean;
  mono?: boolean;
  onClick: (e: React.MouseEvent) => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-[11px] transition-colors hover:bg-bg-hover ${mono ? "font-mono" : ""}`}
      style={{
        color: active
          ? "var(--color-text-primary)"
          : "var(--color-text-secondary)",
      }}
    >
      {active ? (
        <svg
          width="10"
          height="10"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <span className="w-[10px]" />
      )}
      {label}
    </button>
  );
}

function WhitelistPanel({
  regions,
  whitelisted,
  disabled,
  onChange,
}: {
  regions: ServerRegion[];
  whitelisted: string[];
  disabled: boolean;
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="mt-3 rounded-[var(--radius-card)] surface-card p-3.5">
      <div className="text-[10.5px] font-semibold uppercase tracking-[0.12em] text-text-muted">
        Regions to skip
      </div>
      <div className="mt-2.5 flex flex-wrap gap-1.5">
        {regions.map((r) => {
          const active = whitelisted.includes(r.name);
          return (
            <button
              key={r.id}
              type="button"
              disabled={disabled}
              onClick={() =>
                onChange(
                  active
                    ? whitelisted.filter((n) => n !== r.name)
                    : [...whitelisted, r.name],
                )
              }
              className="flex items-center gap-1.5 rounded-[5px] px-2 py-1 text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                backgroundColor: active
                  ? "var(--color-accent-primary-soft-12)"
                  : "var(--color-bg-elevated)",
                border: `1px solid ${active ? "var(--color-accent-primary-soft-20)" : "var(--color-border-subtle)"}`,
                color: active
                  ? "var(--color-text-primary)"
                  : "var(--color-text-muted)",
              }}
            >
              <span className="text-[12px] leading-none">
                {countryFlag(r.country_code)}
              </span>
              {r.name}
            </button>
          );
        })}
      </div>
    </div>
  );
}
