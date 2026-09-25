import type { ReactNode } from "react";

import { useBoostStore } from "../../stores/boostStore";
import { useServerStore } from "../../stores/serverStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { Button, Icon, Watermark } from "../ui";
import {
  averagePing,
  jitter,
  useSessionStatsStore,
  type SessionStats,
} from "../../stores/sessionStatsStore";
import { useVpnStore } from "../../stores/vpnStore";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { Flag } from "../ui/Flag";

function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  return h > 0 ? `${h}h ${String(m).padStart(2, "0")}m` : `${m}m`;
}

function scrollToRegions() {
  document
    .getElementById("connect-regions")
    ?.scrollIntoView({ behavior: "smooth", block: "start" });
}

/** Section title above a card, with an optional link on the right, as on
 *  ExitLag's home screen ("Last session data", "Go to ... >"). */
function CardTitle({
  title,
  action,
  onAction,
}: {
  title: string;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 px-0.5">
      <h3 className="text-[15px] font-bold text-text-primary">{title}</h3>
      {action && (
        <button
          type="button"
          onClick={onAction}
          className="flex items-center gap-0.5 text-[12px] font-semibold text-text-muted transition-colors hover:text-text-primary"
        >
          {action}
          <Icon name="chevron-right" size={13} strokeWidth={2.2} />
        </button>
      )}
    </div>
  );
}

/** A plain grey label over a white value. */
function Stat({
  label,
  value,
  unit,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[12px] text-text-muted">{label}</span>
      <span className="text-[16px] font-bold leading-none tabular-nums text-text-primary">
        {value}
        {unit && (
          <span className="ml-1 text-[12px] font-semibold text-text-muted">{unit}</span>
        )}
      </span>
    </div>
  );
}

function Meter({ fraction }: { fraction: number }) {
  return (
    <div className="mt-2 h-[5px] overflow-hidden rounded-full bg-bg-elevated">
      <div
        className="h-full rounded-full bg-text-primary"
        style={{ width: `${Math.round(Math.min(1, Math.max(0, fraction)) * 100)}%` }}
      />
    </div>
  );
}

function SessionCard({ stats, live }: { stats: SessionStats | null; live: boolean }) {
  const regions = useServerStore((s) => s.regions);
  const relay = useVpnStore((s) => s.region);
  const region = stats ? findRegionForVpnRegion(regions, stats.region) : undefined;
  const avg = stats ? averagePing(stats) : null;
  const jit = stats ? jitter(stats) : null;

  return (
    <div className="relative isolate flex flex-1 flex-col gap-4 overflow-hidden rounded-[var(--radius-card)] surface-card p-5">
      <Watermark icon="pulse" at="right" size={150} rotate={-8} fade />
      <div className="flex items-center justify-between gap-3">
        <span className="flex min-w-0 items-center gap-2.5">
          {region ? (
            <Flag code={region.country_code} size={24} shape="logo" />
          ) : (
            <Icon name="globe" size={22} style={{ color: "var(--color-text-muted)" }} />
          )}
          <span className="truncate text-[15px] font-bold text-text-primary">
            {region?.name ?? "No session yet"}
          </span>
        </span>
        <Button
          size="sm"
          variant="secondary"
          className="shrink-0 whitespace-nowrap"
          leadingIcon={<Icon name="globe" size={13} strokeWidth={2} />}
          onClick={scrollToRegions}
        >
          Change region
        </Button>
      </div>

      <div className="text-[12.5px] text-text-muted">
        {live && relay ? (
          <>
            Relay <b className="ml-1 text-[15px] font-bold text-text-primary">{relay}</b>
          </>
        ) : stats ? (
          <>
            Duration{" "}
            <b className="ml-1 text-[15px] font-bold text-text-primary">
              {formatDuration((stats.endedAt ?? stats.startedAt) - stats.startedAt)}
            </b>
          </>
        ) : (
          "Pick where your game traffic goes"
        )}
      </div>

      {!stats || stats.samples === 0 ? (
        <p className="border-t pt-4 text-[12.5px] leading-relaxed text-text-muted" style={{ borderColor: "var(--color-border-subtle)" }}>
          Ping stats show up here after the first few readings.
        </p>
      ) : (
        <div className="mt-auto grid grid-cols-4 gap-3 border-t pt-4" style={{ borderColor: "var(--color-border-subtle)" }}>
          <Stat label="Lowest ping" value={stats.lowest} unit="ms" />
          <Stat label="Average ping" value={avg} unit="ms" />
          <Stat label="Jitter" value={jit ?? "Measuring"} unit={jit !== null ? "ms" : undefined} />
          <Stat label="Readings" value={stats.samples} />
        </div>
      )}
    </div>
  );
}

function RobloxCard() {
  const running = useBoostStore((s) => s.robloxRunning);
  const cpu = useBoostStore((s) => s.cpuUsage);
  const ramMb = useBoostStore((s) => s.ramUsage);
  const ramTotalMb = useBoostStore((s) => s.ramTotal);
  const fps = useBoostStore((s) => s.fps);
  const roblox = useSettingsStore((s) => s.settings.config.roblox_settings);
  const profile = useSettingsStore((s) => s.settings.config.profile);

  return (
    <div className="relative isolate flex flex-1 flex-col gap-4 overflow-hidden rounded-[var(--radius-card)] surface-card p-5">
      {/* Big faded Roblox mark in the corner, like the game cards in ExitLag. */}
      <Watermark icon="roblox" size={168} opacity={0.045} />
      <div className="flex items-center gap-2.5">
        <span
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[8px]"
          style={{ backgroundColor: "#fafafa", color: "#111114" }}
        >
          <Icon name="roblox" size={17} />
        </span>
        <span className="flex min-w-0 flex-col gap-0.5">
          <span className="text-[15px] font-bold leading-none text-text-primary">Roblox</span>
          <span className="flex items-center gap-1.5 text-[12px] text-text-muted">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{
                backgroundColor: running
                  ? "var(--color-status-connected)"
                  : "var(--color-text-dimmed)",
              }}
            />
            {running ? "Running" : "Not running"}
          </span>
        </span>
      </div>

      {running ? (
        <div className="grid grid-cols-3 gap-4 border-t pt-4" style={{ borderColor: "var(--color-border-subtle)" }}>
          <div>
            <Stat label="CPU" value={Math.round(cpu)} unit="%" />
            <Meter fraction={cpu / 100} />
          </div>
          <div>
            <Stat
              label="Memory"
              value={ramMb >= 1024 ? (ramMb / 1024).toFixed(1) : Math.round(ramMb)}
              unit={ramMb >= 1024 ? "GB" : "MB"}
            />
            <Meter fraction={ramTotalMb > 0 ? ramMb / ramTotalMb : 0} />
          </div>
          <div>
            <Stat label="FPS" value={fps > 0 ? fps : "Overlay off"} />
            <Meter fraction={fps > 0 ? Math.min(1, fps / 240) : 0} />
          </div>
        </div>
      ) : (
        <p className="border-t pt-4 text-[12.5px] leading-relaxed text-text-muted" style={{ borderColor: "var(--color-border-subtle)" }}>
          Start Roblox to see how much CPU and memory it uses.
        </p>
      )}

      <div className="mt-auto flex flex-wrap items-center gap-2">
        <Chip label="FPS cap" value={roblox.unlock_fps ? String(roblox.target_fps) : "60"} />
        <Chip label="Profile" value={profile} />
        <Chip label="Graphics" value={String(roblox.graphics_quality)} />
      </div>
    </div>
  );
}

function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="whitespace-nowrap rounded-[7px] border px-2 py-1 text-[11.5px] text-text-muted" style={{ borderColor: "var(--color-border-default)", backgroundColor: "var(--color-bg-elevated)" }}>
      {label} <b className="font-semibold text-text-primary">{value}</b>
    </span>
  );
}

/**
 * The session and Roblox cards under the Connect hero, each under its own
 * title as on ExitLag's home screen: ping stats for this session (or the last
 * one), and what Roblox is using right now.
 */
export function SessionCards() {
  const isConnected = useVpnStore((s) => s.state === "connected");
  const current = useSessionStatsStore((s) => s.current);
  const last = useSessionStatsStore((s) => s.last);
  const setTab = useSettingsStore((s) => s.setTab);
  const stats = isConnected ? current : last;

  return (
    <div className="grid grid-cols-2 gap-3">
      <section className="flex flex-col gap-2.5">
        <CardTitle title={isConnected ? "This session" : "Last session data"} />
        <SessionCard stats={stats} live={isConnected} />
      </section>
      <section className="flex flex-col gap-2.5">
        <CardTitle title="Game data" action="Roblox settings" onAction={() => setTab("games")} />
        <RobloxCard />
      </section>
    </div>
  );
}
