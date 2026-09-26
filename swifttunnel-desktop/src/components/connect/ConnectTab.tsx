import { useEffect, useRef, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import {
  formatBytes,
  getLatencyColor,
} from "../../lib/utils";
import { formatConnectedServerLabel } from "../../lib/connectedServer";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { useFocusAwareInterval } from "../../lib/useFocusAwareInterval";
import { useLiveUpdates } from "../../lib/useLiveUpdates";
import { vpnGetThroughput } from "../../lib/commands";
import { RouteDiagram } from "./RouteDiagram";
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
import { SessionCards } from "./SessionCards";
import { Button, EmptyState, Tooltip, InfoIcon, Toggle } from "../ui";
import type { ServerRegion } from "../../lib/types";
import { Icon } from "../ui/Icon";
import { Flag } from "../ui/Flag";

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
  const showLiveGraph = settings.show_live_graph;
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
  // Every sample lands here first; state (and so a redraw) only follows while
  // the window is in front. In game they keep piling up, so the graph shows
  // the match on the way back without being redrawn behind the game.
  const samplesRef = useRef<DataSample[]>([]);
  const live = useLiveUpdates();
  const liveRef = useRef(live);
  liveRef.current = live;
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
    // No graph means nothing consumes these samples, so skip the whole loop:
    // a throughput IPC call every 500ms plus a state update that re-renders
    // the tab. This is what the setting is actually for.
    if (!isConnected || !showLiveGraph) {
      samplesRef.current = [];
      setDataHistory([]);
      prevBytesRef.current = null;
      return;
    }
    // Fetch and sample in the same tick so each rate is computed from the
    // bytes that fetch just delivered. Two separate 1s timers used to alias
    // against each other and produce zero/double-rate spikes in the graph.
    let cancelled = false;
    let inFlight = false;
    const readTotals = async (): Promise<{ up: number; down: number } | null> => {
      if (liveRef.current) {
        await fetchThroughput();
        const { bytesUp, bytesDown } = useVpnStore.getState();
        return { up: bytesUp, down: bytesDown };
      }
      // In game: read the counters without publishing them to the store,
      // which would redraw the totals for nobody.
      try {
        const stats = await vpnGetThroughput();
        return stats ? { up: stats.bytes_up, down: stats.bytes_down } : null;
      } catch {
        return null;
      }
    };
    const sample = async () => {
      if (inFlight) return;
      inFlight = true;
      let totals: { up: number; down: number } | null = null;
      try {
        totals = await readTotals();
      } finally {
        inFlight = false;
      }
      if (cancelled || !totals) return;
      const now = Date.now();
      const prev = prevBytesRef.current;
      if (prev) {
        const dtMs = Math.max(1, now - prev.t);
        const up = Math.max(0, ((totals.up - prev.up) / dtMs) * 1000);
        const down = Math.max(0, ((totals.down - prev.down) / dtMs) * 1000);
        samplesRef.current = [
          ...samplesRef.current,
          { t: now, up, down },
        ].slice(-MAX_SAMPLES);
        if (liveRef.current) setDataHistory(samplesRef.current);
      }
      prevBytesRef.current = { up: totals.up, down: totals.down, t: now };
    };
    void sample();
    // Sampled through a plain interval because the closure owns per-tick
    // state (prevBytesRef). Deliberately kept sampling in game: the graph is
    // most useful for the period you were playing, which is exactly when the
    // window is not in front. Only the drawing waits.
    const id = setInterval(() => void sample(), SAMPLE_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
      prevBytesRef.current = null;
    };
  }, [isConnected, showLiveGraph, fetchThroughput]);

  // Back in front: draw what piled up meanwhile and refresh the totals.
  useEffect(() => {
    if (!live || !isConnected) return;
    setDataHistory(samplesRef.current);
    void fetchThroughput();
  }, [live, isConnected, fetchThroughput]);

  useFocusAwareInterval(() => void fetchState(), 2000, {
    enabled: isConnected || isTransitioning,
  });

  useEffect(() => {
    void fetchLatencies();
  }, [fetchLatencies]);
  useFocusAwareInterval(() => void fetchLatencies(), 15000, { idleMs: 60_000 });

  useEffect(() => {
    if (!isConnected) return;
    void fetchPing();
  }, [isConnected, fetchPing]);
  useFocusAwareInterval(() => void fetchPing(), 3000, { enabled: isConnected });

  function selectRegion(regionId: string) {
    update({ selected_region: regionId, auto_routing_enabled: false });
    saveDebounced();
  }

  function selectAutoRoute() {
    update({ auto_routing_enabled: true });
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
        ? "Auto"
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
      {/* overflow-clip, not overflow-hidden: the glow below reaches past the
          right edge, and a hidden-overflow box is still scrollable from code.
          Focusing the button scrolled it sideways and cut off the left side
          at narrower window sizes. A clip box cannot scroll at all. */}
      <section
        className={`corner-frame relative overflow-clip rounded-[var(--radius-card)] surface-card ${isConnected ? "connected-ambience" : ""}`}
      >
        <div
          className="dot-grid pointer-events-none absolute inset-0"
          style={{ opacity: 0.8 }}
        />
        {/* Light source behind the deck so it has atmosphere, and turns green
            once the tunnel is actually carrying traffic. */}
        <div className={`aurora ${isConnected ? "aurora-live" : ""}`} aria-hidden />

        <div className="relative flex items-center gap-5 px-6 pb-5 pt-6">
          <StatusRing state={vpnState} />

          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="eyebrow">{heroEyebrow}</span>
              {isConnected && (
                <span
                  className="pill-base"
                  style={{
                    backgroundColor: "var(--color-bg-elevated)",
                    color: "var(--color-text-secondary)",
                    border: "1px solid var(--color-border-default)",
                  }}
                >
                  Live
                </span>
              )}
            </div>

            <div className="mt-2 flex items-center gap-2.5">
              {heroRegion && (
                <Flag code={heroRegion.country_code} size={24} shape="logo" />
              )}
              <span
                className="truncate text-[26px] font-semibold leading-[1.05] text-text-primary"
                style={{ letterSpacing: "-0.024em" }}
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

        {/* Route diagram lives inside the deck: the connect state and the path
            it produces are one instrument, not two stacked cards. */}
        <RouteDiagram
          regionName={
            (isConnected ? connectedRegion : selectedRegion)?.name ?? null
          }
          countryCode={
            (isConnected ? connectedRegion : selectedRegion)?.country_code ??
            null
          }
          /* Same source as the Latency stat below, the two must never
             disagree, and the region's cached latency is a real measurement
             even when we're disconnected. */
          ping={heroLatency}
          connected={isConnected}
          relayName={isConnected ? connectedServerLabel : null}
        />

        {/* Stats strip */}
        <div
          className="relative grid grid-cols-3 border-t"
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          <HeroStat
            label="Relay RTT"
            value={heroLatency !== null ? String(heroLatency) : "—"}
            unit={heroLatency !== null ? "ms" : undefined}
            divider
          />
          <HeroStat
            label="Session"
            value={isConnected ? <SessionClock connectedAt={connectedAt} /> : "—"}
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

      <SessionCards />

      <AdapterSelectionPanel disabled={isConnected || isTransitioning} />

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
          {showLiveGraph ? (
            <LiveGraph
              samples={dataHistory}
              onDisable={() => {
                update({ show_live_graph: false });
                saveDebounced();
              }}
            />
          ) : (
            // Hiding the graph must not be a one-way door. Without this the
            // only way back was the Settings tab, which is a poor place to
            // look for something you turned off here.
            <button
              type="button"
              onClick={() => {
                update({ show_live_graph: true });
                saveDebounced();
              }}
              className="flex items-center justify-center gap-2 rounded-[var(--radius-card)] surface-card px-4 py-3 text-[12.5px] font-semibold text-text-muted transition-colors hover:text-text-primary"
            >
              <Icon name="pulse" size={15} strokeWidth={2} />
              Show connection graph
            </button>
          )}

          <div className="grid grid-cols-4 overflow-hidden rounded-[var(--radius-card)] surface-card">
            <TransferCell direction="up" />
            <TransferCell direction="down" />
            <MetricCell
              label="Session"
              value={<SessionClock connectedAt={connectedAt} />}
              mono
              divider
            />
            <MetricCell
              label="Ping"
              value={ping !== null ? `${ping}` : "—"}
              hint={ping !== null ? "ms" : undefined}
              mono
              valueColor={ping !== null ? undefined : "var(--color-text-muted)"}
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
      <section id="connect-regions" className="mt-1 scroll-mt-4">
        <div className="mb-2.5 flex items-baseline justify-between">
          <div className="flex items-baseline gap-2">
            <h3
              className="text-[16px] font-semibold text-text-primary"
              style={{ letterSpacing: "-0.01em" }}
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
              // Nothing guarded this before, so holding down a click fired
              // overlapping refreshes, each racing to overwrite the store.
              disabled={serversLoading}
              className="inline-flex items-center gap-1.5 rounded-[5px] px-2 py-1 text-[11px] font-medium text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary disabled:pointer-events-none disabled:opacity-50"
            >
              <Icon name="sync" size={11} strokeWidth={2.4} />
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
          <div className="instrument flex flex-col overflow-hidden">
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
                // The region we are actually on reports its live in-tunnel RTT
                // rather than the periodic batch probe. The two are measured
                // differently and refresh on different schedules, so leaving
                // the probe here put a stale number next to the live one and
                // made the same relay look like two different pings.
                latency={
                  isConnected && settings.selected_region === r.id && ping !== null
                    ? ping
                    : getLatency(r.id)
                }
                disabled={isConnected || isTransitioning}
                onSelect={() => selectRegion(r.id)}
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

/**
 * Session length, in its own component so the once-a-second tick re-renders
 * one text node instead of the whole tab. It stops ticking while the player
 * is in game and catches up the moment the window is back in front.
 */
function SessionClock({ connectedAt }: { connectedAt: number | null }) {
  const live = useLiveUpdates();
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (connectedAt === null || !live) return;
    setNow(Date.now());
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [connectedAt, live]);

  const seconds =
    connectedAt === null ? 0 : Math.max(0, Math.floor((now - connectedAt) / 1000));
  return <>{formatElapsed(seconds)}</>;
}

/**
 * Upload or download total. Subscribed here rather than in ConnectTab so a
 * counter update repaints one number, not the tab. While the player is in
 * game it holds the last value: the overlay polls the same counters every
 * second, and redrawing them behind the game helps no one.
 */
function TransferCell({ direction }: { direction: "up" | "down" }) {
  const live = useLiveUpdates();
  const bytes = useVpnStore((s) => (direction === "up" ? s.bytesUp : s.bytesDown));
  const shown = useRef(bytes);
  if (live) shown.current = bytes;
  return (
    <MetricCell
      label={direction === "up" ? "Upload" : "Download"}
      value={formatBytes(shown.current)}
      mono
      divider
    />
  );
}

function HeroStat({
  label,
  value,
  unit,
  color,
  divider,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  color?: string;
  divider?: boolean;
}) {
  return (
    <div
      className="flex flex-col gap-1.5 px-6 py-4"
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
          className="lcd-readout text-[30px] font-semibold leading-none"
          style={{
            color: color || "var(--color-text-primary)",
            letterSpacing: "-0.04em",
          }}
        >
          {value}
        </span>
        {unit && <span className="text-[12px] text-text-muted">{unit}</span>}
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
          <Icon
            name="pulse"
            size={14}
            style={{
              color: enabled ? "var(--color-text-primary)" : "var(--color-text-muted)",
            }}
          />
        </IconTile>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3
              className="text-[12.5px] font-semibold text-text-primary"
              style={{ letterSpacing: "-0.005em" }}
            >
              Route Assist
            </h3>
            <Tooltip
              content="Join game servers in your relay's region"
            >
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          </div>
          <p className="mt-0.5 truncate text-[11px] leading-snug text-text-muted">
            Join game servers in your relay's region.
          </p>
        </div>
      </div>
      <Toggle
        enabled={enabled}
        disabled={disabled}
        ariaLabel="Route Assist"
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
  value: ReactNode;
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
        <Icon
          name="shuffle"
          size={14}
          strokeWidth={2}
          style={{ color: active ? "var(--color-text-primary)" : "var(--color-text-muted)" }}
        />
      </IconTile>
      <div className="flex min-w-0 flex-1 flex-col gap-[3px] leading-tight">
        <div className="flex items-center gap-2">
          <span
            className="text-[12.5px] font-medium text-text-primary"
            style={{ letterSpacing: "-0.005em" }}
          >
            Auto
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
  isLast,
}: {
  region: ServerRegion;
  selected: boolean;
  lastUsed: boolean;
  latency: number | null;
  disabled: boolean;
  onSelect: () => void;
  isLast: boolean;
}) {
  const [hover, setHover] = useState(false);
  const relayCountLabel = `${region.servers.length} ${
    region.servers.length === 1 ? "relay" : "relays"
  }`;

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
        {/* Same width as the Auto row's tile, so the names line up. */}
        <span className="flex w-7 shrink-0 justify-center">
          <Flag code={region.country_code} size={24} shape="logo" />
        </span>

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
          <span className="truncate font-mono text-[10px] text-text-dimmed">
            {relayCountLabel}
          </span>
        </span>

        <span className="flex-1" />
      </button>

      {/* Fixed-width latency slot, always same position */}
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

    </div>
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
              <Flag code={r.country_code} size={14} />
              {r.name}
            </button>
          );
        })}
      </div>
    </div>
  );
}
