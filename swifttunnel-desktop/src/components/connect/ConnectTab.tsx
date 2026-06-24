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
  isConnectActionBusy,
  resolveConnectStatus,
  stateLabel,
} from "./connectState";
import {
  LiveGraph,
  MAX_SAMPLES,
  SAMPLE_INTERVAL_MS,
  type DataSample,
} from "./LiveGraph";
import { AdapterSelectionPanel } from "./AdapterSelectionPanel";
import { StatusRing } from "./StatusRing";
import { Button, EmptyState, Tooltip, InfoIcon, Toggle } from "../ui";
import type { ServerRegion } from "../../lib/types";

type ConnectStatus = ReturnType<typeof resolveConnectStatus>;

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

  useEffect(() => {
    if (!isConnected) {
      setDataHistory([]);
      prevBytesRef.current = null;
      return;
    }
    // Fetch and sample in the same tick so each rate is computed from the
    // bytes that fetch just delivered. Two separate 1s timers used to alias
    // against each other and produce zero/double-rate spikes in the graph.
    let cancelled = false;
    let inFlight = false;
    const sample = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        await fetchThroughput();
      } finally {
        inFlight = false;
      }
      if (cancelled) return;
      const { bytesUp, bytesDown } = useVpnStore.getState();
      const now = Date.now();
      const prev = prevBytesRef.current;
      if (prev) {
        const dtMs = Math.max(1, now - prev.t);
        const up = Math.max(0, ((bytesUp - prev.up) / dtMs) * 1000);
        const down = Math.max(0, ((bytesDown - prev.down) / dtMs) * 1000);
        setDataHistory((h) =>
          [...h, { t: now, up, down }].slice(-MAX_SAMPLES),
        );
      }
      prevBytesRef.current = { up: bytesUp, down: bytesDown, t: now };
    };
    void sample();
    const id = setInterval(() => void sample(), SAMPLE_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
      prevBytesRef.current = null;
    };
  }, [isConnected, fetchThroughput]);

  useEffect(() => {
    if (!isConnected && !isTransitioning) return;
    const id = setInterval(() => void fetchState(), 2000);
    return () => clearInterval(id);
  }, [isConnected, isTransitioning, fetchState]);

  useEffect(() => {
    void fetchLatencies();
    const id = setInterval(() => void fetchLatencies(), 15000);
    return () => clearInterval(id);
  }, [fetchLatencies]);

  useEffect(() => {
    if (!isConnected) return;
    void fetchPing();
    const id = setInterval(() => void fetchPing(), 3000);
    return () => clearInterval(id);
  }, [isConnected, fetchPing]);

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
    if (enabled && settings.enable_partial_country_ban) {
      update({ enable_api_tunneling: false });
      saveDebounced();
      return;
    }
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

  const heroSubline = isConnected
    ? connectedServerLabel
    : isTransitioning
      ? "Negotiating with relay…"
      : settings.auto_routing_enabled
        ? "Fastest relay picked automatically each match"
        : selectedRegion
          ? `${selectedRegion.servers.length} ${selectedRegion.servers.length === 1 ? "relay" : "relays"} available`
          : "Pick a region from the list below";

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
      {/* ── Hero: command deck ── */}
      <section
        className={`relative overflow-hidden rounded-[var(--radius-card)] surface-card ${isConnected ? "connected-ambience" : ""}`}
      >
        <div
          className="dot-grid pointer-events-none absolute inset-x-0 top-0 h-[140px]"
          style={{ opacity: 0.55 }}
        />

        <div className="relative flex items-center gap-5 px-6 pb-5 pt-6">
          <StatusRing state={vpnState} />

          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
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

            <div className="mt-2 flex items-center gap-2.5">
              {heroRegion && (
                <span className="text-[22px] leading-none">
                  {countryFlag(heroRegion.country_code)}
                </span>
              )}
              <span
                className="truncate text-[24px] font-semibold leading-[1.05] text-text-primary"
                style={{ letterSpacing: "-0.022em" }}
              >
                {heroRegionName}
              </span>
            </div>

            <div
              className={`mt-2 truncate text-[11.5px] ${isConnected ? "font-mono" : ""} text-text-muted`}
              title={heroSubline}
            >
              {heroSubline}
            </div>
          </div>

          <Button
            variant={buttonVariant}
            size="lg"
            onClick={handlePrimary}
            disabled={primaryDisabled}
            loading={isConnectBusy}
            className="min-w-[132px]"
          >
            {buttonLabel}
          </Button>
        </div>

        {(connectStatus.kind !== "text" ||
          vpnState === "error" ||
          driverSetupState !== "idle") && (
          <div className="relative px-6 pb-4">
            <ConnectStatusBanner
              status={connectStatus}
              busy={isConnectBusy}
              onRepair={() => void repairDriver().catch(() => {})}
              onReset={() => void resetDriver().catch(() => {})}
            />
          </div>
        )}

        {/* Stats strip */}
        <div
          className="relative grid grid-cols-3 border-t"
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          <HeroStat
            label="Latency"
            value={heroLatency !== null ? String(heroLatency) : "—"}
            unit={heroLatency !== null ? "ms" : undefined}
            color={
              heroLatency !== null ? getLatencyColor(heroLatency) : undefined
            }
            divider
          />
          <HeroStat
            label="Session"
            value={isConnected ? formatElapsed(elapsed) : "—"}
            divider
          />
          <HeroStat
            label="Routing"
            value={isConnected && tunneled.length > 0 ? String(tunneled.length) : "—"}
            unit={
              isConnected && tunneled.length > 0
                ? tunneled.length === 1
                  ? "app"
                  : "apps"
                : undefined
            }
          />
        </div>
      </section>

      <AdapterSelectionPanel disabled={isConnected || isTransitioning} />

      <RouteAssistPanel
        enabled={
          settings.enable_api_tunneling && !settings.enable_partial_country_ban
        }
        disabled={
          isConnected || isTransitioning || settings.enable_partial_country_ban
        }
        partialBypassActive={settings.enable_partial_country_ban}
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

function HeroStat({
  label,
  value,
  unit,
  color,
  divider,
}: {
  label: string;
  value: string;
  unit?: string;
  color?: string;
  divider?: boolean;
}) {
  return (
    <div
      className="flex flex-col gap-1 px-6 py-3.5"
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
          className="lcd-readout text-[17px] font-medium leading-none"
          style={{ color: color || "var(--color-text-primary)" }}
        >
          {value}
        </span>
        {unit && <span className="text-[10.5px] text-text-muted">{unit}</span>}
      </div>
    </div>
  );
}

function LatencyBars({ latency }: { latency: number }) {
  const color = getLatencyColor(latency);
  const level = latency < 60 ? 3 : latency < 130 ? 2 : 1;
  const heights = [5, 8, 11];
  return (
    <span className="flex items-end gap-[2px]" aria-hidden>
      {heights.map((h, i) => (
        <span
          key={h}
          className="w-[3px] rounded-[1px]"
          style={{
            height: h,
            backgroundColor: i < level ? color : "var(--color-bg-active)",
          }}
        />
      ))}
    </span>
  );
}

function IconTile({
  active,
  children,
}: {
  active?: boolean;
  children: React.ReactNode;
}) {
  return (
    <span
      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[7px]"
      style={{
        backgroundColor: active
          ? "var(--color-accent-primary-soft-12)"
          : "var(--color-bg-elevated)",
        border: `1px solid ${active ? "var(--color-accent-primary-soft-20)" : "var(--color-border-subtle)"}`,
      }}
    >
      {children}
    </span>
  );
}

function RouteAssistPanel({
  enabled,
  disabled,
  partialBypassActive,
  onChange,
}: {
  enabled: boolean;
  disabled: boolean;
  partialBypassActive: boolean;
  onChange: (enabled: boolean) => void;
}) {
  return (
    <section
      className="flex items-center justify-between gap-4 rounded-[var(--radius-card)] px-4 py-3 transition-colors"
      style={{
        backgroundColor: enabled
          ? "var(--color-accent-primary-soft-6)"
          : "var(--color-bg-card)",
        border: `1px solid ${
          enabled
            ? "var(--color-accent-primary-soft-20)"
            : "var(--color-border-subtle)"
        }`,
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.025)",
      }}
    >
      <div className="flex min-w-0 items-center gap-3">
        <IconTile active={enabled}>
          <svg
            width="13"
            height="13"
            viewBox="0 0 24 24"
            fill="none"
            stroke={
              enabled ? "var(--color-text-primary)" : "var(--color-text-muted)"
            }
            strokeWidth="1.85"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M3 12h4l3-9 4 18 3-9h4" />
          </svg>
        </IconTile>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3
              className="text-[12.5px] font-semibold text-text-primary"
              style={{ letterSpacing: "-0.005em" }}
            >
              Roblox Route Assist
            </h3>
            <Tooltip
              content={
                partialBypassActive
                  ? "Partial Bypass already routes the Roblox join path and keeps gameplay direct."
                  : "Routes Roblox matchmaking/login traffic through the selected relay so Roblox places you in game servers near your tunneled region. For blocked countries, use the Bypass toggles in Optimize instead."
              }
            >
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          </div>
          <p className="mt-0.5 truncate text-[11px] leading-snug text-text-muted">
            {partialBypassActive
              ? "Disabled while Partial Bypass is active."
              : "Lands you in game servers near your tunneled region."}
          </p>
        </div>
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
      className="flex flex-wrap items-center gap-2 rounded-[7px] px-3 py-2 text-[11.5px]"
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
      className="group relative flex w-full items-center gap-3 px-3.5 py-3 text-left transition-colors duration-100 disabled:cursor-not-allowed disabled:opacity-50"
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
          className="absolute left-0 top-1/2 h-6 w-[2px] -translate-y-1/2 rounded-r"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        />
      )}
      <IconTile active={active}>
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
      </IconTile>
      <div className="flex min-w-0 flex-1 flex-col gap-[3px] leading-tight">
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
        <span className="text-[10.5px] text-text-muted">
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
  const [hover, setHover] = useState(false);
  const relayCountLabel = `${region.servers.length} ${
    region.servers.length === 1 ? "relay" : "relays"
  }`;
  const expanded = selected && region.servers.length > 0;

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      className={`group relative text-left transition-colors duration-100 ${
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
          className="absolute left-0 top-[11px] h-6 w-[2px] rounded-r"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        />
      )}
      <div className="flex h-[46px] items-center gap-3 px-3.5">
      <button
        type="button"
        onClick={onSelect}
        disabled={disabled}
        className="flex min-w-0 flex-1 items-center gap-3 self-stretch text-left disabled:cursor-not-allowed"
      >
        <IconTile active={selected}>
          <span className="text-[14px] leading-none">
            {countryFlag(region.country_code)}
          </span>
        </IconTile>

        <span className="flex min-w-0 flex-col gap-[3px] leading-tight">
          <span className="flex items-center gap-2">
            <span
              className="truncate text-[12.5px] font-medium text-text-primary"
              style={{ letterSpacing: "-0.005em" }}
            >
              {region.name}
            </span>
            {lastUsed && !selected && (
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
                Last
              </span>
            )}
          </span>
          <span
            className="truncate font-mono text-[10px] text-text-dimmed"
            title={forcedServer ? `Pinned server: ${forcedServer}` : undefined}
          >
            {forcedServer
              ? `Pinned · ${forcedServer}`
              : relayCountLabel}
          </span>
        </span>

        <span className="flex-1" />
      </button>

      {/* Fixed-width latency slot — always same position */}
      <div className="flex w-[76px] shrink-0 items-center justify-end gap-2">
        {latency !== null ? (
          <>
            <LatencyBars latency={latency} />
            <span className="w-[28px] text-right font-mono text-[11.5px] font-medium tabular-nums text-text-primary">
              {latency}
            </span>
            <span className="w-[14px] text-[10px] text-text-muted">ms</span>
          </>
        ) : null}
      </div>

      </div>

      {expanded && (
        <div className="pb-3 pl-[58px] pr-3.5">
          <div
            className="w-full max-w-[460px] overflow-hidden rounded-[8px]"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            <InlineServerOption
              label="Auto"
              description={`Best ${region.name} relay`}
              active={!forcedServer}
              disabled={disabled}
              onClick={() => onForceServer(region.id, null)}
            />
            {region.servers.map((srv) => (
              <InlineServerOption
                key={srv}
                label={srv}
                active={forcedServer === srv}
                disabled={disabled}
                mono
                onClick={() => onForceServer(region.id, srv)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function InlineServerOption({
  label,
  description,
  active,
  disabled,
  mono,
  onClick,
}: {
  label: string;
  description?: string;
  active: boolean;
  disabled: boolean;
  mono?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      aria-pressed={active}
      onClick={onClick}
      className="flex h-8 w-full items-center gap-2 px-2.5 text-left transition-colors hover:bg-bg-hover disabled:cursor-not-allowed"
      style={{
        backgroundColor: active
          ? "var(--color-bg-hover)"
          : "transparent",
        color: active
          ? "var(--color-text-primary)"
          : "var(--color-text-secondary)",
      }}
    >
      <span
        className="flex h-4 w-4 shrink-0 items-center justify-center"
        style={{
          color: active
            ? "var(--color-accent-primary)"
            : "var(--color-text-dimmed)",
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
        ) : null}
      </span>
      <span className="flex min-w-0 items-baseline gap-2">
        <span
          className={`truncate text-[11.5px] font-medium ${mono ? "font-mono" : ""}`}
        >
          {label}
        </span>
        {description && (
          <span className="truncate text-[10px] text-text-dimmed">
            {description}
          </span>
        )}
      </span>
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
