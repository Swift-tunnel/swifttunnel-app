import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import {
  countryFlag,
  getLatencyColor,
  getLatencyLabel,
  formatBytes,
} from "../../lib/utils";
import { formatConnectedServerLabel } from "../../lib/connectedServer";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { GAMES, resolveConnectStatus } from "./connectState";
import { Tooltip, InfoIcon } from "../common/Tooltip";
import type { ServerRegion } from "../../lib/types";
import "./connect.css";

export function ConnectTab() {
  const vpnState = useVpnStore((s) => s.state);
  const vpnRegion = useVpnStore((s) => s.region);
  const vpnServerEndpoint = useVpnStore((s) => s.serverEndpoint);
  const splitActive = useVpnStore((s) => s.splitTunnelActive);
  const tunneled = useVpnStore((s) => s.tunneledProcesses);
  const vpnError = useVpnStore((s) => s.error);
  const driverSetupState = useVpnStore((s) => s.driverSetupState);
  const driverSetupError = useVpnStore((s) => s.driverSetupError);
  const driverResetAttempted = useVpnStore((s) => s.driverResetAttempted);
  const bytesUp = useVpnStore((s) => s.bytesUp);
  const bytesDown = useVpnStore((s) => s.bytesDown);
  const connect = useVpnStore((s) => s.connect);
  const disconnect = useVpnStore((s) => s.disconnect);
  const installDriver = useVpnStore((s) => s.installDriver);
  const resetDriver = useVpnStore((s) => s.resetDriver);
  const ping = useVpnStore((s) => s.ping);
  const connectedAt = useVpnStore((s) => s.connectedAt);
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

  const isConnected = vpnState === "connected";
  const isIdle = vpnState === "disconnected" || vpnState === "error";
  const isTransitioning = !isConnected && !isIdle;

  const prevStateRef = useRef(vpnState);
  const [showSuccess, setShowSuccess] = useState(false);

  // Debounce settings persistence so a burst of clicks (region picker, preset
  // toggles, whitelist edits) collapses into a single disk write 500ms after
  // the last change instead of one write per click. The local store update
  // happens immediately so the UI still feels instant.
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  function saveDebounced() {
    if (saveTimeoutRef.current !== null) {
      clearTimeout(saveTimeoutRef.current);
    }
    saveTimeoutRef.current = setTimeout(() => {
      saveTimeoutRef.current = null;
      void save();
    }, 500);
  }
  useEffect(() => {
    return () => {
      if (saveTimeoutRef.current !== null) {
        clearTimeout(saveTimeoutRef.current);
        // Flush a pending write on unmount so the user doesn't lose changes
        // they made right before navigating away.
        void save();
      }
    };
  }, [save]);

  useEffect(() => {
    if (prevStateRef.current !== "connected" && vpnState === "connected") {
      setShowSuccess(true);
      const timer = setTimeout(() => setShowSuccess(false), 1500);
      prevStateRef.current = vpnState;
      return () => clearTimeout(timer);
    }
    prevStateRef.current = vpnState;
  }, [vpnState]);

  const selectedRegion = regions.find((r) => r.id === settings.selected_region);
  const selectedLatency = getLatency(settings.selected_region);
  const connectedRegion = findRegionForVpnRegion(regions, vpnRegion);
  const connectedServerLabel = formatConnectedServerLabel(vpnServerEndpoint, servers, vpnRegion);

  useEffect(() => {
    if (!isConnected) return;
    const id = setInterval(fetchThroughput, 1000);
    return () => clearInterval(id);
  }, [isConnected, fetchThroughput]);

  useEffect(() => {
    if (!isConnected) return;
    void fetchPing();
    const id = setInterval(() => void fetchPing(), 3000);
    return () => clearInterval(id);
  }, [isConnected, fetchPing]);

  // Connect/disconnect transitions arrive instantly via the VPN_STATE_CHANGED
  // event subscription in lib/events.ts. We still poll at low frequency because
  // background tasks in the core (auto-routing relay switches in
  // connection.rs::commit_switch, the relay health monitor) mutate
  // ConnectionState without going through a Tauri command, so the UI would
  // otherwise miss those changes until the next manual refresh.
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

  async function handleConnect() {
    if (isConnected) {
      disconnect();
      return;
    }
    if (!isIdle) return;
    // Flush any pending debounced settings save BEFORE connecting — vpn_connect
    // reads connect-time options (auto_routing, whitelist, forced servers, QoS)
    // from the backend AppState.settings, so a stale snapshot in the 500 ms
    // debounce window would silently override the user's last click.
    if (saveTimeoutRef.current !== null) {
      clearTimeout(saveTimeoutRef.current);
      saveTimeoutRef.current = null;
      await save();
    }
    connect(settings.selected_region, settings.selected_game_presets);
  }

  function togglePreset(presetId: string) {
    const current = settings.selected_game_presets;
    const next = current.includes(presetId)
      ? current.filter((p) => p !== presetId)
      : [...current, presetId];
    update({ selected_game_presets: next });
    saveDebounced();
  }

  function selectRegion(regionId: string) {
    update({ selected_region: regionId, auto_routing_enabled: false });
    saveDebounced();
  }

  function selectAutoRoute() {
    update({ auto_routing_enabled: true });
    saveDebounced();
  }

  function forceServer(regionId: string, server: string | null) {
    const current = { ...settings.forced_servers };
    if (server) current[regionId] = server;
    else delete current[regionId];
    update({ forced_servers: current });
    saveDebounced();
  }

  const ringColor = isConnected
    ? "rgba(40, 210, 150, 0.5)"
    : isTransitioning ? "rgba(60, 130, 246, 0.3)" : "rgba(60, 130, 246, 0.45)";
  const ringSpeed = isTransitioning ? 3.5 : 55;
  const innerSpeed = isTransitioning ? 2.8 : 38;

  const connectStatus = resolveConnectStatus({
    driverSetupState,
    driverSetupError,
    vpnError,
    vpnState,
    driverResetAttempted,
  });

  return (
    <div className="connect-tab mx-auto flex w-full max-w-[660px] flex-col gap-4 pb-4">
      {/* ── Hero ── */}
      <section className="relative flex flex-col items-center py-1">
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background: `radial-gradient(ellipse at 50% 40%, ${
              isConnected ? "rgba(40,210,150,0.06)" : "rgba(60,130,246,0.04)"
            }, transparent 70%)`,
          }}
        />

        <RingAssembly
          ringColor={ringColor}
          ringSpeed={ringSpeed}
          innerSpeed={innerSpeed}
          isConnected={isConnected}
          isTransitioning={isTransitioning}
          showSuccess={showSuccess}
          onClick={() => void handleConnect()}
        />

        {/* Region badge + status */}
        <div className="mt-3 flex flex-col items-center gap-1">
          <div className="flex items-center gap-1.5 text-sm">
            {isConnected ? (
              <>
                <span className="text-base">
                  {connectedRegion ? countryFlag(connectedRegion.country_code) : "\u{1F310}"}
                </span>
                <span className="font-medium text-text-primary">{vpnRegion}</span>
                <span className="text-text-dimmed">{"\u00B7"}</span>
                <span className="connect-data text-xs font-medium" style={{ color: "var(--color-status-connected)" }}>
                  V3 Relay
                </span>
              </>
            ) : selectedRegion ? (
              <>
                <span className="text-base">{countryFlag(selectedRegion.country_code)}</span>
                <span className="font-medium text-text-primary">{selectedRegion.name}</span>
                {selectedLatency !== null && (
                  <>
                    <span className="text-text-dimmed">{"\u00B7"}</span>
                    <span className="connect-data text-xs font-medium" style={{ color: getLatencyColor(selectedLatency) }}>
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
                : driverSetupState === "installed"
                  ? "var(--color-status-connected)"
                  : vpnError || driverSetupState === "error"
                    ? "var(--color-status-error)"
                    : "var(--color-text-muted)",
            }}
          >
            {connectStatus.kind === "driver_missing" ? (
              <span className="inline-flex flex-wrap items-center justify-center gap-x-1.5 gap-y-1">
                <span>{connectStatus.text}</span>
                <button
                  type="button"
                  onClick={() => void installDriver().catch(() => {})}
                  disabled={isTransitioning}
                  className="rounded-full px-2 py-0.5 text-[11px] font-semibold transition-opacity hover:opacity-90 disabled:opacity-60"
                  style={{
                    backgroundColor: "rgba(60,130,246,0.18)",
                    color: "var(--color-accent-secondary)",
                    border: "1px solid rgba(60,130,246,0.35)",
                  }}
                >
                  Windows Packet Filter driver
                </button>
              </span>
            ) : connectStatus.kind === "reboot_required" ? (
              // No action button: only a reboot actually fixes 1641/3010, and
              // we must not relaunch installDriver here — that was the 1.25.2
              // bug where pressing the "install" CTA after a reboot-required
              // error silently succeeded and then failed on the next connect.
              <span className="inline-flex flex-wrap items-center justify-center gap-x-1.5 gap-y-1">
                <span>{connectStatus.text}</span>
              </span>
            ) : connectStatus.kind === "driver_outdated" ? (
              <span className="inline-flex flex-wrap items-center justify-center gap-x-1.5 gap-y-1">
                <span>Older split tunnel driver detected.</span>
                <button
                  type="button"
                  onClick={() => void resetDriver().catch(() => {})}
                  disabled={isTransitioning}
                  className="rounded-full px-2 py-0.5 text-[11px] font-semibold transition-opacity hover:opacity-90 disabled:opacity-60"
                  style={{
                    backgroundColor: "rgba(60,130,246,0.18)",
                    color: "var(--color-accent-secondary)",
                    border: "1px solid rgba(60,130,246,0.35)",
                  }}
                >
                  Reset driver service
                </button>
              </span>
            ) : connectStatus.text}
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
            transition={{ duration: 0.3 }}
          >
            <div
              className="overflow-hidden rounded-[var(--radius-card)]"
              style={{ backgroundColor: "var(--color-border-subtle)" }}
            >
              <div className="grid grid-cols-3 gap-px">
                <HudCell label="Server" value={connectedServerLabel} />
                <HudCell label="Ping" value={ping !== null ? `${ping}ms` : "\u2014"} mono />
                <HudCell label="Split Tunnel" value={splitActive ? "Active" : "Inactive"} accent={splitActive} />
                <HudCell label="Upload" value={formatBytes(bytesUp)} mono />
                <HudCell label="Download" value={formatBytes(bytesDown)} mono />
                <SessionTimer connectedAt={connectedAt} />
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
                    <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "var(--color-status-connected)" }} />
                    <span className="connect-data text-[11px] font-medium text-text-secondary">{proc}</span>
                  </span>
                ))}
              </div>
            )}
          </motion.section>
        )}
      </AnimatePresence>

      {/* ── Games ── */}
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
                  backgroundColor: sel ? "var(--color-accent-primary-soft-10)" : "var(--color-bg-card)",
                  borderColor: sel ? "var(--color-accent-primary)" : "var(--color-border-subtle)",
                  color: sel ? "var(--color-accent-secondary)" : "var(--color-text-secondary)",
                }}
              >
                <span>{game.icon}</span>
                <span className="font-medium">{game.name}</span>
                {sel && <CheckIcon size={14} />}
              </button>
            );
          })}
        </div>
      </section>

      {/* ── Regions ── */}
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
          <EmptyState
            loading={serversLoading}
            error={serversError}
            onRetry={() => void refreshServers()}
          />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2">
              <AutoRouteCard
                active={settings.auto_routing_enabled}
                disabled={isConnected}
                onClick={selectAutoRoute}
              />

              {regions.map((r, i) => (
                <RegionCard
                  key={r.id}
                  region={r}
                  selected={!settings.auto_routing_enabled && settings.selected_region === r.id}
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

            {settings.auto_routing_enabled && (
              <WhitelistPanel
                regions={regions}
                whitelisted={settings.whitelisted_regions}
                disabled={isConnected}
                onChange={(next) => { update({ whitelisted_regions: next }); saveDebounced(); }}
              />
            )}
          </>
        )}
      </section>
    </div>
  );
}

// ── Sub-components ──

function CheckIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function SectionHeader({ children, noMargin }: { children: string; noMargin?: boolean }) {
  return (
    <h3
      className={`text-[11px] font-semibold uppercase tracking-widest text-text-dimmed ${noMargin ? "" : "mb-3"}`}
    >
      {children}
    </h3>
  );
}

function HudCell({ label, value, mono, accent }: { label: string; value: string; mono?: boolean; accent?: boolean }) {
  return (
    <div className="bg-bg-card px-3.5 py-2.5">
      <div className="text-[10px] font-medium uppercase tracking-wide text-text-muted">{label}</div>
      <div
        className={`mt-0.5 text-[13px] font-medium ${mono ? "connect-data" : ""}`}
        style={{ color: accent ? "var(--color-status-connected)" : "var(--color-text-primary)" }}
      >
        {value}
      </div>
    </div>
  );
}

function useElapsedTime(startAt: number | null): number {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (startAt === null) { setElapsed(0); return; }
    setElapsed(Math.floor((Date.now() - startAt) / 1000));
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - startAt) / 1000)), 1000);
    return () => clearInterval(id);
  }, [startAt]);
  return elapsed;
}

function formatElapsed(totalSecs: number): string {
  const h = Math.floor(totalSecs / 3600);
  const m = Math.floor((totalSecs % 3600) / 60);
  const s = totalSecs % 60;
  return h > 0
    ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
    : `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function SessionTimer({ connectedAt }: { connectedAt: number | null }) {
  const elapsed = useElapsedTime(connectedAt);
  return <HudCell label="Session" value={formatElapsed(elapsed)} mono />;
}

function RingAssembly({
  ringColor, ringSpeed, innerSpeed, isConnected, isTransitioning, showSuccess, onClick,
}: {
  ringColor: string; ringSpeed: number; innerSpeed: number;
  isConnected: boolean; isTransitioning: boolean; showSuccess: boolean;
  onClick: () => void;
}) {
  return (
    <div className="relative" style={{ width: 156, height: 156, overflow: "visible" }}>
      <svg width="156" height="156" viewBox="0 0 156 156" className="absolute inset-0">
        <circle cx="78" cy="78" r="75" fill="none" stroke={ringColor} strokeWidth="0.6" strokeDasharray="10 7"
          style={{ animation: `orbit-cw ${ringSpeed}s linear infinite`, transformOrigin: "center", transition: "stroke 0.6s ease" }}
        />
        <circle cx="78" cy="78" r="63" fill="none" stroke={ringColor} strokeWidth="0.3" opacity={0.2}
          style={{ transition: "stroke 0.6s ease" }}
        />
        <circle cx="78" cy="78" r="60" fill="none" stroke={ringColor} strokeWidth="0.6" strokeDasharray="3 6"
          style={{ animation: `orbit-ccw ${innerSpeed}s linear infinite`, transformOrigin: "center", transition: "stroke 0.6s ease" }}
        />
      </svg>

      {isConnected && (
        <div className="absolute" style={{ width: 100, height: 100, top: 28, left: 28 }}>
          <div className="absolute inset-0 rounded-full" style={{ border: "1.5px solid rgba(40,210,150,0.3)", animation: "broadcast-pulse 2.8s ease-out infinite" }} />
          <div className="absolute inset-0 rounded-full" style={{ border: "1px solid rgba(40,210,150,0.18)", animation: "broadcast-pulse 2.8s ease-out infinite 1.2s" }} />
        </div>
      )}

      <div
        className="pointer-events-none absolute"
        style={{
          width: 116, height: 116, top: 20, left: 20, borderRadius: "50%",
          background: isConnected
            ? "radial-gradient(circle, rgba(40,210,150,0.18) 0%, transparent 70%)"
            : "radial-gradient(circle, rgba(60,130,246,0.12) 0%, transparent 70%)",
          filter: "blur(10px)",
          animation: isConnected ? "glow-breathe 3.2s ease-in-out infinite" : "none",
          opacity: isTransitioning ? 0.25 : 1,
          transition: "opacity 0.4s ease",
        }}
      />

      <motion.button
        onClick={onClick}
        disabled={isTransitioning}
        whileHover={!isTransitioning ? { scale: 1.05 } : undefined}
        whileTap={!isTransitioning ? { scale: 0.95 } : undefined}
        transition={{ type: "spring", stiffness: 400, damping: 22 }}
        className="absolute flex items-center justify-center rounded-full focus:outline-none"
        style={{
          width: 100, height: 100, top: 28, left: 28,
          cursor: isTransitioning ? "wait" : "pointer",
          background: isConnected
            ? "linear-gradient(145deg, #28d296, #1fa87a)"
            : isTransitioning ? "var(--color-bg-elevated)" : "linear-gradient(145deg, #3c82f6, #5a9fff)",
          boxShadow: isConnected
            ? "0 0 35px rgba(40,210,150,0.18), inset 0 1px 0 rgba(255,255,255,0.1)"
            : isTransitioning ? "none" : "0 0 30px rgba(60,130,246,0.12), inset 0 1px 0 rgba(255,255,255,0.08)",
          transition: "background 0.5s ease, box-shadow 0.5s ease",
          animation: showSuccess ? "connect-success-glow 0.8s ease-in-out" : "none",
        }}
        aria-label={isConnected ? "Disconnect" : "Connect"}
      >
        {isTransitioning ? (
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-white/70 border-t-transparent" />
        ) : showSuccess ? (
          <motion.svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: "drop-shadow(0 1px 2px rgba(0,0,0,0.15))" }}>
            <motion.path d="M20 6 9 17l-5-5" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 0.4, ease: "easeOut" }} />
          </motion.svg>
        ) : (
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ filter: "drop-shadow(0 1px 2px rgba(0,0,0,0.15))" }}>
            <path d="M12 2v10" />
            <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
          </svg>
        )}
      </motion.button>
    </div>
  );
}

function AutoRouteCard({ active, disabled, onClick }: { active: boolean; disabled: boolean; onClick: () => void }) {
  return (
    <motion.button
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.04, duration: 0.28 }}
      onClick={onClick}
      disabled={disabled}
      className="col-span-2 relative rounded-[var(--radius-card)] border text-left transition-all disabled:opacity-50"
      style={{
        backgroundColor: active ? "var(--color-accent-primary-soft-8)" : "var(--color-bg-card)",
        borderColor: active ? "var(--color-accent-primary)" : "var(--color-border-subtle)",
        borderLeftWidth: active ? 3 : 1,
        padding: active ? "12px 14px 12px 12px" : "12px 14px",
      }}
    >
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="16 3 21 3 21 8" />
            <line x1="4" y1="20" x2="21" y2="3" />
            <polyline points="21 16 21 21 16 21" />
            <line x1="15" y1="15" x2="21" y2="21" />
            <line x1="4" y1="4" x2="9" y2="9" />
          </svg>
          <span className="text-[13px] font-medium text-text-primary">Auto Route</span>
          <Tooltip content="Automatically connects to the server closest to your game server for the lowest latency.">
            <InfoIcon />
          </Tooltip>
        </span>
        <span className="text-[11px] text-text-muted">Auto-switches to the best server for you</span>
      </div>
    </motion.button>
  );
}

function RegionCard({
  region, selected, lastUsed, latency, disabled, index, onSelect, forcedServer, onForceServer,
}: {
  region: ServerRegion; selected: boolean; lastUsed: boolean; latency: number | null;
  disabled: boolean; index: number; onSelect: () => void;
  forcedServer: string | undefined; onForceServer: (regionId: string, server: string | null) => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const barWidth = latency !== null ? Math.max(8, 100 - latency / 2.5) : 0;
  const qualityLabel = getLatencyLabel(latency);

  useEffect(() => {
    if (!menuOpen) return;
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
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
        backgroundColor: selected ? "var(--color-accent-primary-soft-8)" : "var(--color-bg-card)",
        borderColor: selected ? "var(--color-accent-primary)" : "var(--color-border-subtle)",
        borderLeftWidth: selected ? 3 : 1,
        padding: selected ? "12px 14px 12px 12px" : "12px 14px",
      }}
    >
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-2">
          <span className="text-base leading-none">{countryFlag(region.country_code)}</span>
          <span className="text-[13px] font-medium text-text-primary">{region.name}</span>
        </span>
        <span className="flex items-center gap-1.5">
          {latency !== null && (
            <>
              <span
                className="rounded-full px-1.5 py-0.5 text-[9px] font-semibold"
                style={{ backgroundColor: `${qualityLabel.color}15`, color: qualityLabel.color }}
              >
                {qualityLabel.text}
              </span>
              <span className="connect-data text-xs font-medium" style={{ color: getLatencyColor(latency) }}>
                {latency}ms
              </span>
            </>
          )}
          {region.servers.length > 1 && (
            <ServerMenu
              ref={menuRef}
              open={menuOpen}
              onToggle={() => setMenuOpen((v) => !v)}
              servers={region.servers}
              forcedServer={forcedServer}
              onForceServer={(srv) => { onForceServer(region.id, srv); setMenuOpen(false); }}
            />
          )}
        </span>
      </div>

      <div className="mt-1 flex items-center gap-2">
        <span className="text-[11px] text-text-muted">
          {forcedServer ? (
            <>
              <span className="connect-data" style={{ color: "var(--color-accent-secondary)" }}>{forcedServer}</span>
              {" \u00B7 "}{region.servers.length} available
            </>
          ) : (
            <>{region.servers.length} server{region.servers.length !== 1 ? "s" : ""}</>
          )}
        </span>
        {lastUsed && (
          <span className="text-[9px] font-semibold uppercase tracking-wide" style={{ color: "var(--color-accent-secondary)" }}>
            LAST
          </span>
        )}
      </div>

      {latency !== null && (
        <div
          className="absolute bottom-0 left-0 h-[2px] rounded-full"
          style={{ width: `${barWidth}%`, backgroundColor: getLatencyColor(latency), opacity: 0.2, transition: "width 0.5s ease" }}
        />
      )}
    </motion.button>
  );
}

const ServerMenu = ({
  ref, open, onToggle, servers, forcedServer, onForceServer,
}: {
  ref: React.Ref<HTMLDivElement>;
  open: boolean;
  onToggle: () => void;
  servers: string[];
  forcedServer: string | undefined;
  onForceServer: (server: string | null) => void;
}) => (
  <div className="relative" ref={ref}>
    <span
      role="button"
      tabIndex={0}
      onClick={(e) => { e.stopPropagation(); onToggle(); }}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.stopPropagation(); e.preventDefault(); onToggle(); } }}
      className="flex h-5 w-5 items-center justify-center rounded transition-colors"
      style={{
        color: forcedServer ? "var(--color-accent-secondary)" : "var(--color-text-muted)",
        backgroundColor: open ? "var(--color-bg-hover)" : "transparent",
      }}
      title={forcedServer ? `Forced: ${forcedServer}` : "Select specific server"}
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
        <circle cx="12" cy="12" r="3" />
      </svg>
    </span>

    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0, y: -4, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -4, scale: 0.95 }}
          transition={{ duration: 0.12 }}
          onClick={(e) => e.stopPropagation()}
          className="absolute right-0 top-7 z-50 min-w-[130px] overflow-hidden rounded-[var(--radius-card)] border shadow-lg"
          style={{ backgroundColor: "var(--color-bg-elevated)", borderColor: "var(--color-border-subtle)" }}
        >
          <div className="py-1">
            <ServerMenuItem
              label="Auto"
              active={!forcedServer}
              onClick={(e) => { e.stopPropagation(); onForceServer(null); }}
            />
            <div className="my-1 h-px" style={{ backgroundColor: "var(--color-border-subtle)" }} />
            {servers.map((srv) => (
              <ServerMenuItem
                key={srv}
                label={srv}
                active={forcedServer === srv}
                mono
                onClick={(e) => { e.stopPropagation(); onForceServer(srv); }}
              />
            ))}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  </div>
);

function ServerMenuItem({ label, active, mono, onClick }: { label: string; active: boolean; mono?: boolean; onClick: (e: React.MouseEvent) => void }) {
  return (
    <button
      onClick={onClick}
      className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition-colors hover:bg-bg-hover"
      style={{ color: active ? "var(--color-accent-secondary)" : "var(--color-text-secondary)" }}
    >
      {active ? <CheckIcon size={10} /> : <span className="w-[18px]" />}
      <span className={mono ? "connect-data text-[11px]" : ""}>{label}</span>
    </button>
  );
}

function WhitelistPanel({
  regions, whitelisted, disabled, onChange,
}: {
  regions: ServerRegion[]; whitelisted: string[]; disabled: boolean;
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="mt-3 rounded-[var(--radius-card)] border border-border-subtle bg-bg-card p-4">
      <div className="text-[10px] font-medium uppercase tracking-wide text-text-muted">Direct Connect</div>
      <div className="mt-1 text-xs text-text-muted">{"Don't tunnel for these regions during Auto Routing."}</div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {regions.map((r) => {
          const active = whitelisted.includes(r.name);
          return (
            <button
              key={r.id}
              type="button"
              disabled={disabled}
              onClick={() => {
                onChange(active ? whitelisted.filter((n) => n !== r.name) : [...whitelisted, r.name]);
              }}
              className="flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                backgroundColor: active ? "var(--color-accent-primary-soft-15)" : "var(--color-bg-hover)",
                color: active ? "var(--color-accent-secondary)" : "var(--color-text-muted)",
              }}
              title={disabled ? "Disconnect to edit" : undefined}
            >
              {active ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                </svg>
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              )}
              {r.name}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function EmptyState({ loading, error, onRetry }: { loading: boolean; error: string | null; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-[var(--radius-card)] border border-border-subtle bg-bg-card px-6 py-8">
      <div
        className={`flex h-10 w-10 items-center justify-center rounded-full ${loading ? "animate-pulse" : ""}`}
        style={{ backgroundColor: "var(--color-bg-elevated)" }}
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-text-muted)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d={loading ? "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20" : "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"} />
        </svg>
      </div>
      <div className="text-center">
        <div className="text-sm font-medium text-text-primary">
          {loading ? "Loading regions..." : error ? "Could not load regions" : "No regions available"}
        </div>
        <div className="mt-1 text-xs text-text-muted">
          {loading ? "Fetching server list" : error ? "Check your internet connection and try again" : "No server regions are currently available"}
        </div>
      </div>
      {!loading && (
        <button
          onClick={onRetry}
          className="rounded-[var(--radius-button)] border border-border-default px-3 py-1 text-xs text-text-primary transition-colors hover:bg-bg-hover"
        >
          Retry
        </button>
      )}
    </div>
  );
}
