import type { ReactNode } from "react";

import { useBoostStore } from "../../stores/boostStore";
import { useServerStore } from "../../stores/serverStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { Button, Icon } from "../ui";
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

function Stat({
  label,
  value,
  unit,
  color,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  color?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <span
        className="font-mono text-[17px] font-semibold leading-none tabular-nums"
        style={{ color: color ?? "var(--color-text-primary)" }}
      >
        {value}
        {unit && (
          <span className="ml-1 text-[11px] font-medium text-text-muted">{unit}</span>
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
    <div className="flex flex-col gap-4 rounded-[var(--radius-card)] surface-card p-5">
      <div className="flex items-center justify-between gap-3">
        <span className="text-[13.5px] font-semibold text-text-primary">
          {live ? "This session" : "Last session"}
        </span>
        {region && (
          <span className="flex items-center gap-1.5 text-[12px] text-text-muted">
            <Flag code={region.country_code} size={14} />
            {region.name}
          </span>
        )}
      </div>

      {!stats || stats.samples === 0 ? (
        <p className="text-[12.5px] leading-relaxed text-text-muted">
          Ping stats show up here after the first few readings.
        </p>
      ) : (
        <div className="grid grid-cols-4 gap-3 border-t pt-4" style={{ borderColor: "var(--color-border-subtle)" }}>
          <Stat label="Lowest" value={stats.lowest} unit="ms" />
          <Stat label="Average" value={avg} unit="ms" />
          <Stat label="Jitter" value={jit ?? "Measuring"} unit={jit !== null ? "ms" : undefined} />
          {live ? (
            <Stat label="Readings" value={stats.samples} />
          ) : (
            <Stat
              label="Duration"
              value={formatDuration((stats.endedAt ?? stats.startedAt) - stats.startedAt)}
            />
          )}
        </div>
      )}

      <div className="mt-auto flex items-center gap-2 border-t pt-4" style={{ borderColor: "var(--color-border-subtle)" }}>
        <span className="text-[11.5px] text-text-muted">
          {live && relay ? (
            <>
              Relay <b className="font-mono font-semibold text-text-primary">{relay}</b>
            </>
          ) : (
            "Pick where your game traffic goes"
          )}
        </span>
        <Button
          size="sm"
          variant="secondary"
          className="ml-auto"
          onClick={() =>
            document
              .getElementById("connect-regions")
              ?.scrollIntoView({ behavior: "smooth", block: "start" })
          }
        >
          Change region
        </Button>
      </div>
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
  const setTab = useSettingsStore((s) => s.setTab);

  return (
    <div className="relative flex flex-col gap-4 overflow-hidden rounded-[var(--radius-card)] surface-card p-5">
      {/* Big faded Roblox mark in the corner, like the game cards in ExitLag. */}
      <Icon
        name="roblox"
        size={168}
        className="pointer-events-none absolute -bottom-12 -right-10"
        style={{ color: "var(--color-text-primary)", opacity: 0.045 }}
      />
      <div className="relative flex items-center justify-between gap-3">
        <span className="text-[13.5px] font-semibold text-text-primary">Roblox</span>
        <span
          className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.08em]"
          style={{
            color: running
              ? "var(--color-text-secondary)"
              : "var(--color-text-muted)",
          }}
        >
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
      </div>

      {running ? (
        <div className="relative grid grid-cols-3 gap-4 border-t pt-4" style={{ borderColor: "var(--color-border-subtle)" }}>
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
        <p className="relative text-[12.5px] leading-relaxed text-text-muted">
          Start Roblox to see how much CPU and memory it uses.
        </p>
      )}

      <div className="relative mt-auto flex flex-wrap items-center gap-2 border-t pt-4" style={{ borderColor: "var(--color-border-subtle)" }}>
        <Chip label="FPS cap" value={roblox.unlock_fps ? String(roblox.target_fps) : "60"} />
        <Chip label="Profile" value={profile} />
        <Chip label="Graphics" value={String(roblox.graphics_quality)} />
        <Button size="sm" className="ml-auto whitespace-nowrap" onClick={() => setTab("games")}>
          Roblox settings
        </Button>
      </div>
    </div>
  );
}

function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="whitespace-nowrap rounded-[7px] border px-2 py-1 text-[11px] text-text-muted" style={{ borderColor: "var(--color-border-default)", backgroundColor: "var(--color-bg-elevated)" }}>
      {label} <b className="font-semibold text-text-primary">{value}</b>
    </span>
  );
}

/**
 * The session and Roblox cards under the Connect hero: ping stats for this
 * session (or the last one), and what Roblox is using right now.
 */
export function SessionCards() {
  const isConnected = useVpnStore((s) => s.state === "connected");
  const current = useSessionStatsStore((s) => s.current);
  const last = useSessionStatsStore((s) => s.last);
  const stats = isConnected ? current : last;

  return (
    <div className="grid grid-cols-2 gap-3">
      <SessionCard stats={stats} live={isConnected} />
      <RobloxCard />
    </div>
  );
}
