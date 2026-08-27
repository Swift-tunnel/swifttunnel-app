import { useEffect, useRef, useState } from "react";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import { countryFlag, formatBytes, getLatencyColor } from "../../lib/utils";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { useFocusAwareInterval } from "../../lib/useFocusAwareInterval";
import {
  isConnectActionBusy,
  resolveConnectStatus,
  stateLabel,
} from "../connect/connectState";
import { Chevron, Group, PrimaryButton, Row, Switch, Value } from "./ui";

function formatElapsed(s: number): string {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const mm = String(m).padStart(2, "0");
  const ss = String(sec).padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

/**
 * Lite's Connect screen.
 *
 * The full app opens on a 220px status ring over a route diagram, with the
 * regions laid out as a grid of cards below and a live throughput canvas
 * beside them. All of that is worth the space in a window you sit and watch.
 *
 * Here the state is a dot and two lines, the action is one button, and the
 * region list is a second view rather than a grid, so the first screen is
 * short enough to be read at a glance and then closed.
 */
export function LiteConnect() {
  const vpnState = useVpnStore((s) => s.state);
  const vpnRegion = useVpnStore((s) => s.region);
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

  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const save = useSettingsStore((s) => s.save);

  const regions = useServerStore((s) => s.regions);
  const getLatency = useServerStore((s) => s.getLatency);
  const fetchLatencies = useServerStore((s) => s.fetchLatencies);

  const [picking, setPicking] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const isConnected = vpnState === "connected";
  const isIdle = vpnState === "disconnected" || vpnState === "error";
  const isConnectBusy = isConnectActionBusy({ vpnState, driverSetupState });

  const connectStatus = resolveConnectStatus({
    driverSetupState,
    driverSetupError,
    driverStatus,
    vpnError,
    vpnState,
    driverResetAttempted,
  });

  const connectedRegion = findRegionForVpnRegion(regions, vpnRegion);
  const selectedRegion = regions.find((r) => r.id === settings.selected_region);
  const selectedLatency = getLatency(settings.selected_region);

  // Throughput and ping, but only while connected and only while the window is
  // actually being looked at. The full app polls these twice a second to feed
  // the graph; there is no graph here, so once a second is plenty.
  useFocusAwareInterval(
    () => {
      void fetchThroughput();
      void fetchPing();
    },
    1_000,
    { enabled: isConnected },
  );

  useEffect(() => {
    if (connectedAt === null) {
      setElapsed(0);
      return;
    }
    setElapsed(Math.floor((Date.now() - connectedAt) / 1000));
    const id = window.setInterval(
      () => setElapsed(Math.floor((Date.now() - connectedAt) / 1000)),
      1000,
    );
    return () => window.clearInterval(id);
  }, [connectedAt]);

  // Latencies are only worth measuring when the list is actually on screen.
  useEffect(() => {
    if (picking) void fetchLatencies();
  }, [picking, fetchLatencies]);

  function saveDebounced() {
    if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
    saveTimeoutRef.current = setTimeout(() => {
      saveTimeoutRef.current = null;
      void save();
    }, 500);
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
    if (connectStatus.kind === "reboot_required") return;
    if (isConnected) {
      void disconnect();
      return;
    }
    if (!isIdle || !canConnect || isConnectBusy) return;
    // Flush the debounced save first: connect() reads the region from the
    // settings file, so a pick made within the last half second would be lost.
    if (saveTimeoutRef.current !== null) {
      clearTimeout(saveTimeoutRef.current);
      saveTimeoutRef.current = null;
    }
    await save();
    void connect(settings.selected_region, ["roblox"]);
  }

  // ── Region picker, shown in place of the screen ───────────────────────────
  if (picking) {
    return (
      <>
        <button
          type="button"
          onClick={() => setPicking(false)}
          className="mb-2 flex items-center gap-1.5 px-1 py-1 text-[11.5px] font-medium"
          style={{ color: "var(--color-text-muted)" }}
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden
          >
            <path d="m15 18-6-6 6-6" />
          </svg>
          Region
        </button>
        <Group>
          <Row
            first
            label="Automatic"
            sub="Pick the fastest relay at connect time"
            onClick={() => {
              update({ auto_routing_enabled: true });
              saveDebounced();
              setPicking(false);
            }}
            right={
              settings.auto_routing_enabled ? (
                <Tick />
              ) : (
                <span style={{ width: 12 }} />
              )
            }
          />
          {regions.map((region) => {
            const latency = getLatency(region.id);
            const active =
              !settings.auto_routing_enabled &&
              settings.selected_region === region.id;
            return (
              <Row
                key={region.id}
                label={`${countryFlag(region.country_code)}  ${region.name}`}
                onClick={() => {
                  update({
                    selected_region: region.id,
                    auto_routing_enabled: false,
                  });
                  saveDebounced();
                  setPicking(false);
                }}
                right={
                  <>
                    <Value color={getLatencyColor(latency)}>
                      {latency === null ? "--" : `${latency} ms`}
                    </Value>
                    {active ? <Tick /> : <span style={{ width: 12 }} />}
                  </>
                }
              />
            );
          })}
        </Group>
      </>
    );
  }

  // ── Status ────────────────────────────────────────────────────────────────
  const headline = isConnected
    ? connectedRegion?.name || vpnRegion || "Connected"
    : isIdle
      ? settings.auto_routing_enabled
        ? "Automatic"
        : selectedRegion?.name || "No region"
      : stateLabel(vpnState);

  const sub = isConnected ? "Roblox traffic is tunneled" : connectStatus.text;

  const dotColor = isConnected
    ? "var(--color-status-connected)"
    : vpnState === "error"
      ? "var(--color-status-error)"
      : isIdle
        ? "var(--color-status-inactive)"
        : "var(--color-status-warning)";

  return (
    <>
      <div className="flex items-start gap-2.5 px-1 pb-3 pt-1">
        <span
          className="shrink-0 rounded-full"
          style={{
            width: 8,
            height: 8,
            marginTop: 5,
            backgroundColor: dotColor,
            transition: "background-color 150ms linear",
          }}
        />
        <div className="min-w-0 flex-1">
          <div
            className="truncate text-[15px] font-semibold leading-tight tracking-[-0.015em]"
            style={{ color: "var(--color-text-primary)" }}
          >
            {headline}
          </div>
          <div
            className="mt-0.5 text-[10.5px] leading-snug"
            style={{
              color:
                vpnState === "error"
                  ? "var(--color-status-error)"
                  : "var(--color-text-muted)",
              display: "-webkit-box",
              WebkitLineClamp: 2,
              WebkitBoxOrient: "vertical",
              overflow: "hidden",
            }}
          >
            {sub}
          </div>
        </div>
        {isConnected && (
          <span
            className="shrink-0 text-[11px] font-medium tabular-nums"
            style={{ color: "var(--color-text-dimmed)", marginTop: 3 }}
          >
            {formatElapsed(elapsed)}
          </span>
        )}
      </div>

      <div className="pb-3.5">
        <PrimaryButton
          onClick={() => void handlePrimary()}
          disabled={primaryDisabled}
          variant={isConnected ? "outline" : "solid"}
        >
          {primaryLabel(
            connectStatus.kind,
            vpnState,
            isConnected,
            isConnectBusy,
          )}
        </PrimaryButton>
      </div>

      {isConnected && (
        <div
          className="mb-3.5 flex overflow-hidden rounded-[8px]"
          style={{
            backgroundColor: "var(--color-bg-card)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          <Stat label="Ping" value={ping === null ? "--" : `${ping} ms`} />
          <Stat label="Down" value={formatBytes(bytesDown)} divider />
          <Stat label="Up" value={formatBytes(bytesUp)} divider />
        </div>
      )}

      <Group title="Tunnel">
        <Row
          first
          label="Region"
          onClick={() => setPicking(true)}
          right={
            <>
              <Value>
                {settings.auto_routing_enabled
                  ? "Automatic"
                  : selectedRegion
                    ? `${countryFlag(selectedRegion.country_code)} ${selectedRegion.name}`
                    : "Choose"}
              </Value>
              {!settings.auto_routing_enabled && selectedLatency !== null && (
                <Value color={getLatencyColor(selectedLatency)}>
                  {selectedLatency} ms
                </Value>
              )}
              <Chevron />
            </>
          }
        />
        <Row
          label="Route Assist"
          sub="Join servers in the tunneled region"
          right={
            <Switch
              label="Route Assist"
              checked={settings.enable_api_tunneling}
              onChange={(next) => {
                update({ enable_api_tunneling: next });
                saveDebounced();
              }}
            />
          }
        />
        <Row
          label="Bypass country ban"
          sub="Use when Roblox is blocked entirely"
          right={
            <Switch
              label="Bypass country ban"
              checked={settings.enable_country_ban}
              onChange={(next) => {
                update({ enable_country_ban: next });
                saveDebounced();
              }}
            />
          }
        />
      </Group>
    </>
  );
}

function primaryLabel(
  kind: string,
  vpnState: string,
  isConnected: boolean,
  busy: boolean,
): string {
  if (kind === "driver_missing") return "Install driver";
  if (kind === "driver_repair") return "Repair driver";
  if (kind === "driver_outdated" || kind === "reboot_resettable")
    return "Reset driver service";
  if (kind === "reboot_required") return "Restart required";
  if (isConnected) return "Disconnect";
  if (busy) return stateLabel(vpnState);
  return "Connect";
}

function Stat({
  label,
  value,
  divider,
}: {
  label: string;
  value: string;
  divider?: boolean;
}) {
  return (
    <div
      className="min-w-0 flex-1 px-2.5 py-2"
      style={{
        borderLeft: divider ? "1px solid var(--color-border-subtle)" : "none",
      }}
    >
      <div
        className="text-[9px] font-semibold uppercase tracking-[0.08em]"
        style={{ color: "var(--color-text-dimmed)" }}
      >
        {label}
      </div>
      <div
        className="mt-0.5 truncate text-[12px] font-semibold tabular-nums"
        style={{ color: "var(--color-text-primary)" }}
      >
        {value}
      </div>
    </div>
  );
}

function Tick() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-status-connected)"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
