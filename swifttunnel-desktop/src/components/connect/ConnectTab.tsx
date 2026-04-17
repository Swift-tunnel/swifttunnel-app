import { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import {
  countryFlag,
  formatBytes,
  getLatencyColor,
  getLatencyLabel,
} from "../../lib/utils";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { GAMES, type GameId } from "./connectState";
import { LiveGraph, type DataSample } from "./LiveGraph";
import {
  SectionHeader,
  EmptyState,
  Chip,
  Tooltip,
  InfoIcon,
} from "../ui";
import type { ServerRegion } from "../../lib/types";

const DATA_BUFFER_SIZE = 60;

export function ConnectTab() {
  const vpnState = useVpnStore((s) => s.state);
  const vpnRegion = useVpnStore((s) => s.region);
  const serverEndpoint = useVpnStore((s) => s.serverEndpoint);
  const splitActive = useVpnStore((s) => s.splitTunnelActive);
  const tunneled = useVpnStore((s) => s.tunneledProcesses);
  const bytesUp = useVpnStore((s) => s.bytesUp);
  const bytesDown = useVpnStore((s) => s.bytesDown);
  const vpnError = useVpnStore((s) => s.error);
  const fetchThroughput = useVpnStore((s) => s.fetchThroughput);
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
  const connectedServerName = (() => {
    if (!serverEndpoint) return null;
    const host = serverEndpoint.includes("://")
      ? new URL(serverEndpoint).hostname
      : serverEndpoint.split(":")[0];
    return servers.find((s) => s.ip === host)?.name ?? null;
  })();

  const isConnected = vpnState === "connected";
  const isTransitioning =
    !isConnected && vpnState !== "disconnected" && vpnState !== "error";

  const [dataHistory, setDataHistory] = useState<DataSample[]>([]);
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
    if (!isConnected) return;
    const id = setInterval(fetchThroughput, 1000);
    return () => clearInterval(id);
  }, [isConnected, fetchThroughput]);

  useEffect(() => {
    if (!isConnected) {
      setDataHistory([]);
      prevBytesRef.current = null;
      return;
    }
    const id = setInterval(() => {
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
    }, 1000);
    return () => {
      clearInterval(id);
      prevBytesRef.current = null;
    };
  }, [isConnected]);

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

  function togglePreset(id: GameId) {
    const cur = settings.selected_game_presets;
    const next = cur.includes(id) ? cur.filter((p) => p !== id) : [...cur, id];
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
    const cur = { ...settings.forced_servers };
    if (server) cur[regionId] = server;
    else delete cur[regionId];
    update({ forced_servers: cur });
    saveDebounced();
  }

  const hasRegions = regions.length > 0;
  const showError =
    vpnState === "error" && vpnError && !vpnError.toLowerCase().includes("driver");

  return (
    <div className="flex w-full flex-col gap-5 pb-4">
      {showError && (
        <div
          className="rounded-[var(--radius-card)] px-4 py-3 text-[12px]"
          style={{
            backgroundColor: "var(--color-status-error-soft-10)",
            border: "1px solid var(--color-status-error-soft-20)",
            color: "var(--color-status-error)",
          }}
        >
          <div className="font-medium">Connection failed</div>
          <div className="mt-0.5 text-[11px] opacity-90">{vpnError}</div>
        </div>
      )}

      {/* ── Live monitor (connected) ── */}
      {isConnected && (
        <motion.section
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
          className="flex flex-col gap-2.5"
        >
          <SectionHeader label="Live" tag="Connected" />

          {/* Active route strip: target region + relay server */}
          <div
            className="flex items-center gap-3 rounded-[var(--radius-card)] px-3.5 py-2.5"
            style={{
              backgroundColor: "var(--color-bg-card)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            <span className="text-[9.5px] font-semibold uppercase tracking-[0.12em] text-text-dimmed">
              Tunneled to
            </span>
            <span className="flex items-center gap-1.5">
              {connectedRegion && (
                <span className="text-[14px] leading-none">
                  {countryFlag(connectedRegion.country_code)}
                </span>
              )}
              <span
                className="text-[13px] font-semibold"
                style={{
                  color: "var(--color-status-connected)",
                  letterSpacing: "-0.01em",
                }}
              >
                {connectedRegion?.name || vpnRegion || "Unknown"}
              </span>
            </span>
            <svg
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="var(--color-text-dimmed)"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden
            >
              <path d="M5 12h14M13 5l7 7-7 7" />
            </svg>
            <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-text-secondary">
              {connectedServerName || "—"}
            </span>
            <span className="flex items-center gap-1.5 shrink-0">
              <span
                className="relative h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: "var(--color-status-connected)" }}
              >
                <span
                  className="absolute inset-0 animate-ping rounded-full opacity-60"
                  style={{ backgroundColor: "var(--color-status-connected)" }}
                />
              </span>
              <span
                className="text-[10px] font-semibold uppercase tracking-[0.1em]"
                style={{ color: "var(--color-status-connected)" }}
              >
                Live
              </span>
            </span>
          </div>

          <div className="grid gap-3 lg:grid-cols-[1fr_260px]">
            <LiveGraph samples={dataHistory} />
            <div
              className="flex flex-col gap-2 rounded-[var(--radius-card)] p-4"
              style={{
                backgroundColor: "var(--color-bg-card)",
                border: "1px solid var(--color-border-subtle)",
              }}
            >
              <LiveStat
                label="Split tunnel"
                value={splitActive ? "Active" : "Inactive"}
                valueColor={
                  splitActive
                    ? "var(--color-status-connected)"
                    : "var(--color-text-muted)"
                }
              />
              <LiveStat
                label="Total upload"
                value={formatBytes(bytesUp)}
                mono
              />
              <LiveStat
                label="Total download"
                value={formatBytes(bytesDown)}
                mono
              />
              <LiveStat
                label="Tunneled"
                value={`${tunneled.length} ${tunneled.length === 1 ? "process" : "processes"}`}
              />
            </div>
          </div>

          {tunneled.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {tunneled.map((p) => (
                <span
                  key={p}
                  className="inline-flex items-center gap-1.5 rounded-[4px] px-2 py-1 font-mono text-[10.5px]"
                  style={{
                    backgroundColor: "var(--color-bg-card)",
                    border: "1px solid var(--color-border-subtle)",
                    color: "var(--color-text-secondary)",
                  }}
                >
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ backgroundColor: "var(--color-status-connected)" }}
                  />
                  {p}
                </span>
              ))}
            </div>
          )}
        </motion.section>
      )}

      {/* ── Targets ── */}
      <section>
        <SectionHeader
          label="Targets"
          description="Games that route through the tunnel"
          tag={`${settings.selected_game_presets.length} / ${GAMES.length}`}
        />
        <div className="flex flex-wrap gap-2">
          {GAMES.map((game) => {
            const sel = settings.selected_game_presets.includes(game.id);
            return (
              <button
                key={game.id}
                onClick={() => togglePreset(game.id)}
                className="group flex items-center gap-2 rounded-[var(--radius-button)] px-3 py-2 transition-all"
                style={{
                  backgroundColor: sel
                    ? "var(--color-accent-primary-soft-8)"
                    : "var(--color-bg-card)",
                  border: `1px solid ${sel ? "var(--color-accent-primary)" : "var(--color-border-subtle)"}`,
                }}
              >
                <GameLogo id={game.id} brandColor={game.brandColor} active={sel} />
                <span
                  className="text-[12.5px] font-medium"
                  style={{
                    color: sel
                      ? "var(--color-text-primary)"
                      : "var(--color-text-secondary)",
                    letterSpacing: "-0.01em",
                  }}
                >
                  {game.name}
                </span>
                {sel && (
                  <svg
                    width="12"
                    height="12"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="var(--color-accent-secondary)"
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

      {/* ── Regions ── */}
      <section>
        <SectionHeader
          label="Regions"
          tag={hasRegions ? `${regions.length} available` : undefined}
          action={
            hasRegions &&
            !isConnected && (
              <button
                onClick={() => void refreshServers()}
                className="inline-flex items-center gap-1 text-[10.5px] font-medium text-text-muted transition-colors hover:text-text-secondary"
              >
                <svg
                  width="10"
                  height="10"
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
            )
          }
        />

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
          <div className="flex flex-col gap-2">
            <AutoRouteRow
              active={settings.auto_routing_enabled}
              disabled={isConnected || isTransitioning}
              onClick={selectAutoRoute}
            />
            <div className="grid grid-cols-2 gap-2 lg:grid-cols-3 2xl:grid-cols-4">
              {regions.map((r) => (
                <RegionCard
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
                />
              ))}
            </div>

            {settings.auto_routing_enabled && (
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
          </div>
        )}
      </section>
    </div>
  );
}

// ── Sub-components ──

function LiveStat({
  label,
  value,
  valueColor,
  mono,
}: {
  label: string;
  value: string;
  valueColor?: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <span
        className={`text-[12.5px] font-semibold ${mono ? "font-mono" : ""}`}
        style={{ color: valueColor || "var(--color-text-primary)" }}
      >
        {value}
      </span>
    </div>
  );
}

function GameLogo({
  id,
  brandColor,
  active,
}: {
  id: GameId;
  brandColor: string;
  active: boolean;
}) {
  const color = active ? brandColor : "var(--color-text-muted)";
  const bg = active ? `${brandColor}22` : "var(--color-bg-elevated)";

  return (
    <span
      className="flex h-5 w-5 shrink-0 items-center justify-center rounded-[3px]"
      style={{ backgroundColor: bg }}
    >
      {id === "roblox" && (
        <svg width="12" height="12" viewBox="0 0 24 24" fill={color}>
          <path d="M4.6 3.5 L20.5 7.7 L16.3 23.6 L0.4 19.4 Z M10.8 11.5 L9.7 15.7 L13.8 16.8 L14.9 12.7 Z" />
        </svg>
      )}
      {id === "valorant" && (
        <svg width="12" height="12" viewBox="0 0 24 24" fill={color}>
          <path d="M2 3 L7.2 3 L14 18.5 L11.6 21.5 Z M22 3 L16.8 3 L12 13.5 L14 18 Z" />
        </svg>
      )}
      {id === "fortnite" && (
        <svg width="12" height="12" viewBox="0 0 24 24" fill={color}>
          <path d="M7 2.5 L18 2.5 L18 6.5 L11 6.5 L11 10 L16.5 10 L16 14 L11 14 L11 21 L8 22 L8 13 L6 13 L6.5 10 L8 10 L8 6.5 L7 6.5 Z" />
        </svg>
      )}
    </span>
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
      className="flex w-full items-center gap-3 rounded-[var(--radius-card)] px-3.5 py-3 text-left transition-all disabled:cursor-not-allowed disabled:opacity-50"
      style={{
        backgroundColor: active
          ? "var(--color-accent-primary-soft-8)"
          : "var(--color-bg-card)",
        border: `1px solid ${active ? "var(--color-accent-primary)" : "var(--color-border-subtle)"}`,
      }}
    >
      <span
        className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[5px]"
        style={{
          backgroundColor: active
            ? "var(--color-accent-primary-soft-15)"
            : "var(--color-bg-elevated)",
        }}
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke={
            active
              ? "var(--color-accent-secondary)"
              : "var(--color-text-muted)"
          }
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
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-2">
          <span
            className="text-[13px] font-semibold"
            style={{
              color: active
                ? "var(--color-accent-secondary)"
                : "var(--color-text-primary)",
            }}
          >
            Auto Route
          </span>
          <Tooltip content="Picks the fastest relay to the game server each match.">
            <span className="inline-flex">
              <InfoIcon />
            </span>
          </Tooltip>
          {active && (
            <Chip tone="accent" uppercase size="xs">
              Active
            </Chip>
          )}
        </div>
        <span className="mt-0.5 text-[11px] text-text-muted">
          Picks the fastest relay for every match
        </span>
      </div>
    </button>
  );
}

function RegionCard({
  region,
  selected,
  lastUsed,
  latency,
  disabled,
  onSelect,
  forcedServer,
  onForceServer,
}: {
  region: ServerRegion;
  selected: boolean;
  lastUsed: boolean;
  latency: number | null;
  disabled: boolean;
  onSelect: () => void;
  forcedServer: string | undefined;
  onForceServer: (regionId: string, server: string | null) => void;
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
    <button
      type="button"
      onClick={onSelect}
      disabled={disabled}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      className="group relative flex h-10 items-center gap-2.5 rounded-[var(--radius-card)] pr-2.5 text-left transition-colors duration-100 disabled:cursor-not-allowed disabled:opacity-50"
      style={{
        backgroundColor: selected
          ? "var(--color-accent-primary-soft-8)"
          : hover
            ? "var(--color-bg-hover)"
            : "var(--color-bg-card)",
        border: `1px solid ${selected ? "var(--color-accent-primary)" : "var(--color-border-subtle)"}`,
        paddingLeft: selected ? 9 : 10,
      }}
    >
      {/* Selected accent rail */}
      {selected && (
        <span
          aria-hidden
          className="absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-r"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        />
      )}

      {/* Flag */}
      <span className="text-[14px] leading-none">
        {countryFlag(region.country_code)}
      </span>

      {/* Name + secondary info */}
      <div className="flex min-w-0 flex-1 items-baseline gap-1.5">
        <span
          className="truncate text-[12.5px] font-semibold"
          style={{
            color: selected
              ? "var(--color-accent-secondary)"
              : "var(--color-text-primary)",
            letterSpacing: "-0.01em",
          }}
        >
          {region.name}
        </span>
        {forcedServer ? (
          <span
            className="truncate font-mono text-[9.5px]"
            style={{ color: "var(--color-accent-secondary)" }}
            title={`Forced server: ${forcedServer}`}
          >
            {forcedServer}
          </span>
        ) : (
          <span className="shrink-0 font-mono text-[9.5px] text-text-dimmed">
            {region.servers.length}
          </span>
        )}
        {lastUsed && !selected && (
          <span
            className="shrink-0 text-[8.5px] font-bold uppercase tracking-[0.12em]"
            style={{ color: "var(--color-accent-secondary)" }}
          >
            Last
          </span>
        )}
      </div>

      {/* Right: latency with color dot */}
      {latency !== null && latColor && (
        <span className="flex shrink-0 items-center gap-1.5">
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{
              backgroundColor: latColor,
              boxShadow: latency < 50 ? `0 0 4px ${latColor}` : "none",
            }}
          />
          <span
            className="font-mono text-[11.5px] font-semibold tabular-nums"
            style={{ color: latColor }}
          >
            {latency}
            <span className="ml-px text-[9.5px] font-medium text-text-dimmed">
              ms
            </span>
          </span>
        </span>
      )}

      {/* Server override gear — hover / forced only */}
      {region.servers.length > 1 && (hover || menuOpen || forcedServer) && (
        <ServerMenu
          menuRef={menuRef}
          open={menuOpen}
          onToggle={() => setMenuOpen((v) => !v)}
          servers={region.servers}
          forcedServer={forcedServer}
          onForceServer={(srv) => {
            onForceServer(region.id, srv);
            setMenuOpen(false);
          }}
        />
      )}
    </button>
  );
}

function ServerMenu({
  menuRef,
  open,
  onToggle,
  servers,
  forcedServer,
  onForceServer,
}: {
  menuRef: React.RefObject<HTMLDivElement | null>;
  open: boolean;
  onToggle: () => void;
  servers: string[];
  forcedServer: string | undefined;
  onForceServer: (server: string | null) => void;
}) {
  return (
    <div className="relative" ref={menuRef}>
      <span
        role="button"
        tabIndex={0}
        onClick={(e) => {
          e.stopPropagation();
          onToggle();
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.stopPropagation();
            e.preventDefault();
            onToggle();
          }
        }}
        className="flex h-5 w-5 items-center justify-center rounded transition-colors"
        style={{
          color: forcedServer
            ? "var(--color-accent-secondary)"
            : "var(--color-text-muted)",
          backgroundColor: open ? "var(--color-bg-hover)" : "transparent",
        }}
      >
        <svg
          width="10"
          height="10"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      </span>

      {open && (
        <div
          onClick={(e) => e.stopPropagation()}
          className="absolute right-0 top-7 z-50 min-w-[130px] overflow-hidden rounded-[5px] shadow-xl"
          style={{
            backgroundColor: "var(--color-bg-elevated)",
            border: "1px solid var(--color-border-default)",
          }}
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
          ? "var(--color-accent-secondary)"
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
    <div
      className="mt-2 rounded-[var(--radius-card)] p-3.5"
      style={{
        backgroundColor: "var(--color-bg-card)",
        border: "1px solid var(--color-border-subtle)",
      }}
    >
      <div className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-secondary">
        Select which regions to not tunnel
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
              className="flex items-center gap-1.5 rounded-[4px] px-2 py-1 text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                backgroundColor: active
                  ? "var(--color-accent-primary-soft-15)"
                  : "var(--color-bg-elevated)",
                color: active
                  ? "var(--color-accent-secondary)"
                  : "var(--color-text-muted)",
              }}
            >
              <span className="text-[11px] leading-none">
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
