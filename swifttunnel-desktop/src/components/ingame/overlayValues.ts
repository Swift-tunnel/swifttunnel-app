import type { OverlayMetric } from "../../lib/types";

export interface OverlayPerformance {
  fps: number;
  cpuUsage: number;
  ramUsage: number;
  ramTotal: number;
  robloxRunning: boolean;
}
export interface OverlayRates {
  uploadBps: number | null;
  downloadBps: number | null;
}
const pad = (n: number) => String(n).padStart(2, "0");
function rate(value: number | null) {
  if (value === null || !Number.isFinite(value) || value < 0) return "--";
  if (value < 1024) return `${Math.round(value)} B/s`;
  const kb = value / 1024;
  return kb < 1024
    ? `${kb.toFixed(kb >= 10 ? 0 : 1)} KB/s`
    : `${(kb / 1024).toFixed(1)} MB/s`;
}
export function overlayValues(
  b: OverlayPerformance,
  sessionMs: number,
  traffic: OverlayRates,
  relayPing: number | null,
  gamePing: number | null,
  now = new Date(),
): Partial<Record<OverlayMetric, string>> {
  const seconds = Math.max(0, Math.floor(sessionMs / 1000));
  return {
    fps:
      b.robloxRunning && Number.isFinite(b.fps) && b.fps > 0
        ? String(Math.round(b.fps))
        : "--",
    cpu:
      b.robloxRunning && Number.isFinite(b.cpuUsage)
        ? `${Math.round(Math.max(0, Math.min(100, b.cpuUsage)))}%`
        : "--",
    ram:
      b.robloxRunning && Number.isFinite(b.ramUsage) && b.ramUsage > 0
        ? b.ramUsage >= 1024
          ? `${(b.ramUsage / 1024).toFixed(1)} GB`
          : `${Math.round(b.ramUsage)} MB`
        : "--",
    ping:
      relayPing !== null && Number.isFinite(relayPing) && relayPing >= 0
        ? `${Math.round(relayPing)} ms`
        : "--",
    game_ping:
      gamePing !== null && Number.isFinite(gamePing) && gamePing >= 0
        ? `~${Math.round(gamePing)} ms`
        : "--",
    time: `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`,
    playtime: b.robloxRunning
      ? `${Math.floor(seconds / 3600) > 0 ? `${pad(Math.floor(seconds / 3600))}:` : ""}${pad(Math.floor(seconds / 60) % 60)}:${pad(seconds % 60)}`
      : "--",
    upload: rate(traffic.uploadBps),
    download: rate(traffic.downloadBps),
  };
}
