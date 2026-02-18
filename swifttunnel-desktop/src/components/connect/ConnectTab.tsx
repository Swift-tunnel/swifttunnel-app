import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import { countryFlag, getLatencyColor, formatBytes } from "../../lib/utils";
import { isAdminPrivilegeError } from "../../lib/adminErrors";
import {
  systemCheckDriver,
  systemInstallDriver,
  systemRestartAsAdmin,
} from "../../lib/commands";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import type { ServerRegion } from "../../lib/types";
import "./connect.css";

const GAMES = [
  { id: "roblox", name: "Roblox", icon: "\u{1F3AE}" },
  { id: "valorant", name: "Valorant", icon: "\u{1F3AF}" },
  { id: "fortnite", name: "Fortnite", icon: "\u{1F3D7}\uFE0F" },
];

function stateLabel(state: string): string {
  switch (state) {
    case "disconnected":
      return "Ready to connect";
    case "fetching_config":
      return "Resolving relay\u2026";
    case "creating_adapter":
      return "Creating adapter\u2026";
    case "connecting":
      return "Establishing tunnel\u2026";
    case "configuring_split_tunnel":
      return "Configuring split tunnel\u2026";
    case "configuring_routes":
      return "Setting routes\u2026";
    case "connected":
      return "Connected";
    case "disconnecting":
      return "Disconnecting\u2026";
    case "error":
      return "Connection failed";
    default:
      return state;
  }
}

// ── Main Component ──

export function ConnectTab() {
  const vpnState = useVpnStore((s) => s.state);
  const vpnRegion = useVpnStore((s) => s.region);
  const splitActive = useVpnStore((s) => s.splitTunnelActive);
  const tunneled = useVpnStore((s) => s.tunneledProcesses);
  const vpnError = useVpnStore((s) => s.error);
  const bytesUp = useVpnStore((s) => s.bytesUp);
  const bytesDown = useVpnStore((s) => s.bytesDown);
  const connect = useVpnStore((s) => s.connect);
  const disconnect = useVpnStore((s) => s.disconnect);
  const ping = useVpnStore((s) => s.ping);
  const fetchThroughput = useVpnStore((s) => s.fetchThroughput);
  const fetchPing = useVpnStore((s) => s.fetchPing);
  const fetchVpnState = useVpnStore((s) => s.fetchState);

  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const save = useSettingsStore((s) => s.save);

  const regions = useServerStore((s) => s.regions);
  const serversLoading = useServerStore((s) => s.isLoading);
  const serversError = useServerStore((s) => s.error);
  const getLatency = useServerStore((s) => s.getLatency);
  const fetchLatencies = useServerStore((s) => s.fetchLatencies);
  const refreshServers = useServerStore((s) => s.refresh);

  const isConnected = vpnState === "connected";
  const isIdle = vpnState === "disconnected" || vpnState === "error";
  const isTransitioning = !isConnected && !isIdle;

  const selectedRegion = regions.find((r) => r.id === settings.selected_region);
  const selectedLatency = getLatency(settings.selected_region);
  const connectedRegion = findRegionForVpnRegion(regions, vpnRegion);

  useEffect(() => {
    if (!isConnected) return;
    const id = setInterval(fetchThroughput, 1000);
    return () => clearInterval(id);
  }, [isConnected, fetchThroughput]);

  // Real-time ICMP ping to the actual relay server
  useEffect(() => {
    if (!isConnected) return;
    void fetchPing();
    const id = setInterval(() => void fetchPing(), 3000);
    return () => clearInterval(id);
  }, [isConnected, fetchPing]);

  // Poll VPN state while connected so auto-routing region switches show up
  useEffect(() => {
    if (!isConnected) return;
    const id = setInterval(fetchVpnState, 2000);
    return () => clearInterval(id);
  }, [isConnected, fetchVpnState]);

  useEffect(() => {
    void fetchLatencies();
    const id = setInterval(() => void fetchLatencies(), 15000);
    return () => clearInterval(id);
  }, [fetchLatencies]);

  function handleConnect() {
    if (isConnected) disconnect();
    else if (isIdle)
      connect(settings.selected_region, settings.selected_game_presets);
  }

  function togglePreset(presetId: string) {
    const current = settings.selected_game_presets;
    const next = current.includes(presetId)
      ? current.filter((p) => p !== presetId)
      : [...current, presetId];
    update({ selected_game_presets: next });
    save();
  }

  function selectRegion(regionId: string) {
    update({ selected_region: regionId, auto_routing_enabled: false });
    save();
  }

  function selectAutoRoute() {
    update({ auto_routing_enabled: true });
    save();
  }

  function forceServer(regionId: string, server: string | null) {
    const current = { ...settings.forced_servers };
    if (server) {
      current[regionId] = server;
    } else {
      delete current[regionId];
    }
    update({ forced_servers: current });
    save();
  }

  const ringColor = isConnected
    ? "rgba(40, 210, 150, 0.5)"
    : isTransitioning
      ? "rgba(60, 130, 246, 0.3)"
      : "rgba(60, 130, 246, 0.45)";

  const ringSpeed = isTransitioning ? 3.5 : 55;
  const innerSpeed = isTransitioning ? 2.8 : 38;

  const [driverInstallState, setDriverInstallState] = useState<
    "idle" | "installing" | "installed" | "error"
  >("idle");
  const [driverInstallError, setDriverInstallError] = useState<string | null>(
    null,
  );

  const driverMissing =
    !!vpnError &&
    vpnError.toLowerCase().includes("split tunnel driver not available") &&
    vpnError.toLowerCase().includes("windows packet filter driver");
  const adminRequired = isAdminPrivilegeError(vpnError);
  const [elevationRestartState, setElevationRestartState] = useState<
    "idle" | "restarting" | "error"
  >("idle");
  const [elevationRestartError, setElevationRestartError] = useState<
    string | null
  >(null);

  async function handleInstallDriver() {
    try {
      setDriverInstallState("installing");
      setDriverInstallError(null);
      await systemInstallDriver();
      const check = await systemCheckDriver();
      if (!check.installed) {
        throw new Error(
          "Driver installation completed, but the driver is still not detected.",
        );
      }
      setDriverInstallState("installed");
    } catch (e) {
      setDriverInstallState("error");
      setDriverInstallError(String(e));
    }
  }

  async function handleRestartAsAdmin() {
    try {
      setElevationRestartState("restarting");
      setElevationRestartError(null);
      await systemRestartAsAdmin();
    } catch (e) {
      setElevationRestartState("error");
      setElevationRestartError(String(e));
    }
  }

  function renderStatusLine() {
    if (elevationRestartState === "restarting") {
      return "Restarting SwiftTunnel as Administrator\u2026";
    }

    if (elevationRestartState === "error") {
      return elevationRestartError || "Failed to restart as Administrator.";
    }

    if (driverInstallState === "installing") {
      return "Installing Windows Packet Filter driver\u2026";
    }

    if (driverInstallState === "installed") {
      return "Driver installed. Click Connect to retry.";
    }

    if (driverInstallState === "error") {
      return driverInstallError || "Driver install failed.";
    }

    if (adminRequired) {
      return (
        <span className="inline-flex flex-wrap items-center justify-center gap-x-1.5 gap-y-1">
          <span>Administrator privileges required.</span>
          <button
            type="button"
            onClick={() => void handleRestartAsAdmin()}
            disabled={isTransitioning}
            className="rounded-full px-2 py-0.5 text-[11px] font-semibold transition-opacity hover:opacity-90 disabled:opacity-60"
            style={{
              backgroundColor: "rgba(60,130,246,0.18)",
              color: "var(--color-accent-secondary)",
              border: "1px solid rgba(60,130,246,0.35)",
            }}
            title="Close this instance and relaunch SwiftTunnel with UAC prompt"
          >
            Restart as Administrator
          </button>
        </span>
      );
    }

    if (driverMissing) {
      return (
        <span className="inline-flex flex-wrap items-center justify-center gap-x-1.5 gap-y-1">
          <span>Split tunnel driver not available. Install</span>
          <button
            type="button"
            onClick={() => void handleInstallDriver()}
            disabled={isTransitioning}
            className="rounded-full px-2 py-0.5 text-[11px] font-semibold transition-opacity hover:opacity-90 disabled:opacity-60"
            style={{
              backgroundColor: "rgba(60,130,246,0.18)",
              color: "var(--color-accent-secondary)",
              border: "1px solid rgba(60,130,246,0.35)",
            }}
            title="Install Windows Packet Filter (WinpkFilter) driver"
          >
            Windows Packet Filter driver
          </button>
        </span>
      );
    }

    return vpnError || stateLabel(vpnState);
  }

  return (
    <div className="connect-tab mx-auto flex w-full max-w-[640px] flex-col gap-5 pb-4">
      {/* ── Hero: Connect Core ── */}
      <section className="relative flex flex-col items-center py-1">
        {/* Ambient glow */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background: `radial-gradient(ellipse at 50% 40%, ${
              isConnected
                ? "rgba(40,210,150,0.06)"
                : "rgba(60,130,246,0.04)"
            }, transparent 70%)`,
          }}
        />

        {/* Ring Assembly */}
        <div
          className="relative"
          style={{ width: 156, height: 156, overflow: "visible" }}
        >
          <svg
            width="156"
            height="156"
            viewBox="0 0 156 156"
            className="absolute inset-0"
          >
            {/* Outer dashed ring */}
            <circle
              cx="78"
              cy="78"
              r="75"
              fill="none"
              stroke={ringColor}
              strokeWidth="0.6"
              strokeDasharray="10 7"
              style={{
                animation: `orbit-cw ${ringSpeed}s linear infinite`,
                transformOrigin: "center",
                transition: "stroke 0.6s ease",
              }}
            />
            {/* Middle static ring */}
            <circle
              cx="78"
              cy="78"
              r="63"
              fill="none"
              stroke={ringColor}
              strokeWidth="0.3"
              opacity={0.2}
              style={{ transition: "stroke 0.6s ease" }}
            />
            {/* Inner dotted ring */}
            <circle
              cx="78"
              cy="78"
              r="60"
              fill="none"
              stroke={ringColor}
              strokeWidth="0.6"
              strokeDasharray="3 6"
              style={{
                animation: `orbit-ccw ${innerSpeed}s linear infinite`,
                transformOrigin: "center",
                transition: "stroke 0.6s ease",
              }}
            />
          </svg>

          {/* Broadcast rings (connected only) */}
          {isConnected && (
            <div
              className="absolute"
              style={{ width: 100, height: 100, top: 28, left: 28 }}
            >
              <div
                className="absolute inset-0 rounded-full"
                style={{
                  border: "1.5px solid rgba(40,210,150,0.3)",
                  animation: "broadcast-pulse 2.8s ease-out infinite",
                }}
              />
              <div
                className="absolute inset-0 rounded-full"
                style={{
                  border: "1px solid rgba(40,210,150,0.18)",
                  animation: "broadcast-pulse 2.8s ease-out infinite 1.2s",
                }}
              />
            </div>
          )}

          {/* Glow behind button */}
          <div
            className="pointer-events-none absolute"
            style={{
              width: 116,
              height: 116,
              top: 20,
              left: 20,
              borderRadius: "50%",
              background: isConnected
                ? "radial-gradient(circle, rgba(40,210,150,0.18) 0%, transparent 70%)"
                : "radial-gradient(circle, rgba(60,130,246,0.12) 0%, transparent 70%)",
              filter: "blur(10px)",
              animation: isConnected
                ? "glow-breathe 3.2s ease-in-out infinite"
                : "none",
              opacity: isTransitioning ? 0.25 : 1,
              transition: "opacity 0.4s ease",
            }}
          />

          {/* Connect Button */}
          <motion.button
            onClick={handleConnect}
            disabled={isTransitioning}
            whileHover={!isTransitioning ? { scale: 1.05 } : undefined}
            whileTap={!isTransitioning ? { scale: 0.95 } : undefined}
            transition={{ type: "spring", stiffness: 400, damping: 22 }}
            className="absolute flex items-center justify-center rounded-full focus:outline-none"
            style={{
              width: 100,
              height: 100,
              top: 28,
              left: 28,
              cursor: isTransitioning ? "wait" : "pointer",
              background: isConnected
                ? "linear-gradient(145deg, #28d296, #1fa87a)"
                : isTransitioning
                  ? "var(--color-bg-elevated)"
                  : "linear-gradient(145deg, #3c82f6, #5a9fff)",
              boxShadow: isConnected
                ? "0 0 35px rgba(40,210,150,0.18), inset 0 1px 0 rgba(255,255,255,0.1)"
                : isTransitioning
                  ? "none"
                  : "0 0 30px rgba(60,130,246,0.12), inset 0 1px 0 rgba(255,255,255,0.08)",
              transition: "background 0.5s ease, box-shadow 0.5s ease",
            }}
            aria-label={isConnected ? "Disconnect" : "Connect"}
          >
            {isTransitioning ? (
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-white/70 border-t-transparent" />
            ) : (
              <svg
                width="30"
                height="30"
                viewBox="0 0 24 24"
                fill="none"
                stroke="white"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{ filter: "drop-shadow(0 1px 2px rgba(0,0,0,0.15))" }}
              >
                <path d="M5 12.55a11 11 0 0 1 14.08 0" />
                <path d="M1.42 9a16 16 0 0 1 21.16 0" />
                <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
                <circle cx="12" cy="20" r="1" fill="white" />
              </svg>
            )}
          </motion.button>
        </div>

        {/* Region badge + status */}
        <div className="mt-3 flex flex-col items-center gap-1">
          <div className="flex items-center gap-1.5 text-sm">
            {isConnected ? (
              <>
                <span className="text-base">
                  {connectedRegion
                    ? countryFlag(connectedRegion.country_code)
                    : "\u{1F310}"}
                </span>
                <span className="font-medium text-text-primary">
                  {vpnRegion}
                </span>
                <span className="text-text-dimmed">·</span>
                <span
                  className="connect-data text-xs font-medium"
                  style={{ color: "var(--color-status-connected)" }}
                >
                  V3 Relay
                </span>
              </>
            ) : selectedRegion ? (
              <>
                <span className="text-base">
                  {countryFlag(selectedRegion.country_code)}
                </span>
                <span className="font-medium text-text-primary">
                  {selectedRegion.name}
                </span>
                {selectedLatency !== null && (
                  <>
                    <span className="text-text-dimmed">·</span>
                    <span
                      className="connect-data text-xs font-medium"
                      style={{ color: getLatencyColor(selectedLatency) }}
                    >
                      {selectedLatency}ms
                    </span>
                  </>
                )}
              </>
            ) : (
              <span className="text-text-muted">No region selected</span>
            )}
          </div>

          <div
            className="text-xs"
            style={{
              color: isConnected
                ? "var(--color-status-connected)"
                : driverInstallState === "installed"
                  ? "var(--color-status-connected)"
                  : elevationRestartState === "restarting"
                    ? "var(--color-text-secondary)"
                  : vpnError || driverInstallState === "error"
                    ? "var(--color-status-error)"
                    : "var(--color-text-muted)",
            }}
          >
            {renderStatusLine()}
          </div>
        </div>
      </section>

      {/* ── Connection HUD ── */}
      <AnimatePresence>
        {isConnected && (
          <motion.section
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10, transition: { duration: 0.15 } }}
            transition={{ duration: 0.3, ease: "easeOut" }}
          >
            <div
              className="overflow-hidden rounded-[var(--radius-card)]"
              style={{ backgroundColor: "var(--color-border-subtle)" }}
            >
              <div className="grid grid-cols-3 gap-px">
                <HudCell label="Mode" value="V3 Relay" accent />
                <HudCell
                  label="Ping"
                  value={
                    ping !== null ? `${ping}ms` : "\u2014"
                  }
                  mono
                />
                <HudCell
                  label="Split Tunnel"
                  value={splitActive ? "Active" : "Inactive"}
                  accent={splitActive}
                />
                <HudCell label="Upload" value={formatBytes(bytesUp)} mono />
                <HudCell
                  label="Download"
                  value={formatBytes(bytesDown)}
                  mono
                />
                <HudCell
                  label="Tunneled"
                  value={`${tunneled.length} process${tunneled.length !== 1 ? "es" : ""}`}
                />
              </div>
            </div>

            {tunneled.length > 0 && (
              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {tunneled.map((proc) => (
                  <span
                    key={proc}
                    className="flex items-center gap-1.5 rounded-full px-2.5 py-1"
                    style={{ backgroundColor: "var(--color-bg-elevated)" }}
                  >
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{
                        backgroundColor: "var(--color-status-connected)",
                      }}
                    />
                    <span className="connect-data text-[11px] font-medium text-text-secondary">
                      {proc}
                    </span>
                  </span>
                ))}
              </div>
            )}
          </motion.section>
        )}
      </AnimatePresence>

      {/* ── Game Presets ── */}
      <section>
        <SectionHeader>Games</SectionHeader>
        <div className="flex gap-2">
          {GAMES.map((game) => {
            const sel = settings.selected_game_presets.includes(game.id);
            return (
              <button
                key={game.id}
                onClick={() => togglePreset(game.id)}
                className="flex items-center gap-2 rounded-[var(--radius-button)] border px-4 py-2.5 text-sm transition-all"
                style={{
                  backgroundColor: sel
                    ? "var(--color-accent-primary-soft-10)"
                    : "var(--color-bg-card)",
                  borderColor: sel
                    ? "var(--color-accent-primary)"
                    : "var(--color-border-subtle)",
                  color: sel
                    ? "var(--color-accent-secondary)"
                    : "var(--color-text-secondary)",
                }}
              >
                <span>{game.icon}</span>
                <span className="font-medium">{game.name}</span>
                {sel && (
                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                )}
              </button>
            );
          })}
        </div>
      </section>

      {/* ── Region Selector ── */}
      <section>
        <div className="mb-3 flex items-center justify-between">
          <SectionHeader noMargin>Regions</SectionHeader>
          {!serversLoading && !isConnected && (
            <button
              onClick={() => void refreshServers()}
              className="text-[11px] font-medium text-text-muted transition-colors hover:text-text-secondary"
            >
              Refresh
            </button>
          )}
        </div>

        {regions.length === 0 ? (
          <div className="rounded-[var(--radius-card)] border border-border-subtle bg-bg-card p-5">
            <p className="text-sm text-text-secondary">
              {serversLoading
                ? "Loading regions\u2026"
                : serversError
                  ? "Could not load regions."
                  : "No regions available."}
            </p>
            {!serversLoading && (
              <button
                onClick={() => void refreshServers()}
                className="mt-3 rounded-[var(--radius-button)] border border-border-default px-3 py-1 text-xs text-text-primary transition-colors hover:bg-bg-hover"
              >
                Retry
              </button>
            )}
          </div>
        ) : (
          <>
          <div className="grid grid-cols-2 gap-2">
            {/* Auto Route option */}
            <motion.button
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.04, duration: 0.28 }}
              onClick={selectAutoRoute}
              disabled={isConnected}
              className="col-span-2 relative rounded-[var(--radius-card)] border text-left transition-all disabled:opacity-50"
              style={{
                backgroundColor: settings.auto_routing_enabled
                  ? "var(--color-accent-primary-soft-8)"
                  : "var(--color-bg-card)",
                borderColor: settings.auto_routing_enabled
                  ? "var(--color-accent-primary)"
                  : "var(--color-border-subtle)",
                borderLeftWidth: settings.auto_routing_enabled ? 3 : 1,
                padding: settings.auto_routing_enabled
                  ? "12px 14px 12px 12px"
                  : "12px 14px",
              }}
            >
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <svg
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <polyline points="16 3 21 3 21 8" />
                    <line x1="4" y1="20" x2="21" y2="3" />
                    <polyline points="21 16 21 21 16 21" />
                    <line x1="15" y1="15" x2="21" y2="21" />
                    <line x1="4" y1="4" x2="9" y2="9" />
                  </svg>
                  <span className="text-[13px] font-medium text-text-primary">
                    Auto Route
                  </span>
                </span>
                <span className="text-[11px] text-text-muted">
                  Auto-switches to the best server for you
                </span>
              </div>
            </motion.button>

            {regions.map((r, i) => (
              <RegionCard
                key={r.id}
                region={r}
                selected={
                  !settings.auto_routing_enabled &&
                  settings.selected_region === r.id
                }
                lastUsed={settings.last_connected_region === r.id}
                latency={getLatency(r.id)}
                disabled={isConnected}
                index={i}
                onSelect={() => selectRegion(r.id)}
                forcedServer={settings.forced_servers[r.id]}
                onForceServer={forceServer}
              />
            ))}
          </div>

          {/* Don't-tunnel panel (visible when auto routing is active) */}
          {settings.auto_routing_enabled && (
            <div className="mt-3 rounded-[var(--radius-card)] border border-border-subtle bg-bg-card p-4">
              <div
                className="text-[10px] font-medium uppercase text-text-muted"
                style={{ letterSpacing: "0.08em" }}
              >
                Direct Connect
              </div>
              <div className="mt-1 text-xs text-text-muted">
                {"Don't tunnel for these regions during Auto Routing."}
              </div>

              <div className="mt-2 flex flex-wrap gap-1.5">
                {regions.map((r) => {
                  const active = settings.whitelisted_regions.includes(r.name);
                  return (
                    <button
                      key={r.id}
                      type="button"
                      disabled={isConnected}
                      onClick={() => {
                        const next = active
                          ? settings.whitelisted_regions.filter(
                              (n) => n !== r.name,
                            )
                          : [...settings.whitelisted_regions, r.name];
                        update({ whitelisted_regions: next });
                        save();
                      }}
                      className="flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-60"
                      style={{
                        backgroundColor: active
                          ? "var(--color-accent-primary-soft-15)"
                          : "var(--color-bg-hover)",
                        color: active
                          ? "var(--color-accent-secondary)"
                          : "var(--color-text-muted)",
                      }}
                      title={isConnected ? "Disconnect to edit" : undefined}
                    >
                      {active ? (
                        <svg
                          width="14"
                          height="14"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                        </svg>
                      ) : (
                        <svg
                          width="14"
                          height="14"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                      )}
                      {r.name}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          </>
        )}
      </section>
    </div>
  );
}

// ── Sub-components ──

function HudCell({
  label,
  value,
  mono,
  accent,
}: {
  label: string;
  value: string;
  mono?: boolean;
  accent?: boolean;
}) {
  return (
    <div
      className="px-3.5 py-2.5"
      style={{ backgroundColor: "var(--color-bg-card)" }}
    >
      <div
        className="text-[10px] font-medium uppercase text-text-muted"
        style={{ letterSpacing: "0.08em" }}
      >
        {label}
      </div>
      <div
        className={`mt-0.5 text-[13px] font-medium ${mono ? "connect-data" : ""}`}
        style={{
          color: accent
            ? "var(--color-status-connected)"
            : "var(--color-text-primary)",
        }}
      >
        {value}
      </div>
    </div>
  );
}

function RegionCard({
  region,
  selected,
  lastUsed,
  latency,
  disabled,
  index,
  onSelect,
  forcedServer,
  onForceServer,
}: {
  region: ServerRegion;
  selected: boolean;
  lastUsed: boolean;
  latency: number | null;
  disabled: boolean;
  index: number;
  onSelect: () => void;
  forcedServer: string | undefined;
  onForceServer: (regionId: string, server: string | null) => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const barWidth =
    latency !== null ? Math.max(8, 100 - latency / 2.5) : 0;

  useEffect(() => {
    if (!menuOpen) return;
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node))
        setMenuOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [menuOpen]);

  return (
    <motion.button
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.04 + index * 0.025, duration: 0.28 }}
      onClick={onSelect}
      disabled={disabled}
      className="relative rounded-[var(--radius-card)] border text-left transition-all disabled:opacity-50"
      style={{
        backgroundColor: selected
          ? "var(--color-accent-primary-soft-8)"
          : "var(--color-bg-card)",
        borderColor: selected
          ? "var(--color-accent-primary)"
          : "var(--color-border-subtle)",
        borderLeftWidth: selected ? 3 : 1,
        padding: selected ? "12px 14px 12px 12px" : "12px 14px",
      }}
    >
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-2">
          <span className="text-base leading-none">
            {countryFlag(region.country_code)}
          </span>
          <span className="text-[13px] font-medium text-text-primary">
            {region.name}
          </span>
        </span>
        <span className="flex items-center gap-1.5">
          {latency !== null && (
            <span
              className="connect-data text-xs font-medium"
              style={{ color: getLatencyColor(latency) }}
            >
              {latency}ms
            </span>
          )}
          {/* Gear icon for server forcing */}
          {region.servers.length > 1 && (
            <div className="relative" ref={menuRef}>
              <span
                role="button"
                tabIndex={0}
                onClick={(e) => {
                  e.stopPropagation();
                  setMenuOpen((v) => !v);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.stopPropagation();
                    e.preventDefault();
                    setMenuOpen((v) => !v);
                  }
                }}
                className="flex h-5 w-5 items-center justify-center rounded transition-colors"
                style={{
                  color: forcedServer
                    ? "var(--color-accent-secondary)"
                    : "var(--color-text-muted)",
                  backgroundColor: menuOpen
                    ? "var(--color-bg-hover)"
                    : "transparent",
                }}
                title={
                  forcedServer
                    ? `Forced: ${forcedServer}`
                    : "Select specific server"
                }
              >
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
                  <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </span>

              {/* Dropdown */}
              <AnimatePresence>
                {menuOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -4, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -4, scale: 0.95 }}
                    transition={{ duration: 0.12 }}
                    onClick={(e) => e.stopPropagation()}
                    className="absolute right-0 top-7 z-50 min-w-[130px] overflow-hidden rounded-[var(--radius-card)] border shadow-lg"
                    style={{
                      backgroundColor: "var(--color-bg-elevated)",
                      borderColor: "var(--color-border-subtle)",
                    }}
                  >
                    <div className="py-1">
                      {/* Auto option */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onForceServer(region.id, null);
                          setMenuOpen(false);
                        }}
                        className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition-colors hover:bg-bg-hover"
                        style={{
                          color: !forcedServer
                            ? "var(--color-accent-secondary)"
                            : "var(--color-text-secondary)",
                        }}
                      >
                        {!forcedServer && (
                          <svg
                            width="10"
                            height="10"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="3"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          >
                            <polyline points="20 6 9 17 4 12" />
                          </svg>
                        )}
                        <span className={!forcedServer ? "" : "ml-[18px]"}>
                          Auto
                        </span>
                      </button>

                      {/* Divider */}
                      <div
                        className="my-1 h-px"
                        style={{
                          backgroundColor: "var(--color-border-subtle)",
                        }}
                      />

                      {/* Individual servers */}
                      {region.servers.map((srv) => {
                        const isForced = forcedServer === srv;
                        return (
                          <button
                            key={srv}
                            onClick={(e) => {
                              e.stopPropagation();
                              onForceServer(region.id, srv);
                              setMenuOpen(false);
                            }}
                            className="flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors hover:bg-bg-hover"
                            style={{
                              color: isForced
                                ? "var(--color-accent-secondary)"
                                : "var(--color-text-secondary)",
                            }}
                          >
                            {isForced && (
                              <svg
                                width="10"
                                height="10"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="3"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                              >
                                <polyline points="20 6 9 17 4 12" />
                              </svg>
                            )}
                            <span
                              className={`connect-data text-[11px] ${isForced ? "" : "ml-[18px]"}`}
                            >
                              {srv}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
        </span>
      </div>

      <div className="mt-1 flex items-center gap-2">
        <span className="text-[11px] text-text-muted">
          {forcedServer ? (
            <>
              <span className="connect-data" style={{ color: "var(--color-accent-secondary)" }}>
                {forcedServer}
              </span>
              {" "}· {region.servers.length} available
            </>
          ) : (
            <>
              {region.servers.length} server{region.servers.length !== 1 ? "s" : ""}
            </>
          )}
        </span>
        {lastUsed && (
          <span
            className="text-[9px] font-semibold uppercase"
            style={{
              color: "var(--color-accent-secondary)",
              letterSpacing: "0.06em",
            }}
          >
            LAST
          </span>
        )}
      </div>

      {/* Latency quality bar */}
      {latency !== null && (
        <div
          className="absolute bottom-0 left-0 h-[2px] rounded-full"
          style={{
            width: `${barWidth}%`,
            backgroundColor: getLatencyColor(latency),
            opacity: 0.2,
            transition: "width 0.5s ease",
          }}
        />
      )}
    </motion.button>
  );
}

function SectionHeader({
  children,
  noMargin,
}: {
  children: string;
  noMargin?: boolean;
}) {
  return (
    <h3
      className={`text-[11px] font-semibold uppercase text-text-muted ${noMargin ? "" : "mb-3"}`}
      style={{ letterSpacing: "0.1em" }}
    >
      {children}
    </h3>
  );
}
