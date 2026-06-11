import { useEffect, useRef } from "react";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import { pushOverlayRender } from "../components/ingame/overlayBus";
import type { OverlayConfig, OverlayMetric } from "../lib/types";

const pad = (n: number) => String(n).padStart(2, "0");

function formatClock(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`;
}

interface BoostSnapshot {
  fps: number;
  cpuUsage: number;
  ramUsage: number;
  ramTotal: number;
  robloxRunning: boolean;
}

function computeValues(
  b: BoostSnapshot,
  sessionMs: number,
): Partial<Record<OverlayMetric, string>> {
  const now = new Date();
  const ramPct =
    b.ramTotal > 0 ? Math.round((b.ramUsage / b.ramTotal) * 100) : null;
  return {
    fps: b.fps > 0 ? String(Math.round(b.fps)) : "--",
    time: `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`,
    playtime: b.robloxRunning ? formatClock(sessionMs) : "00:00:00",
    cpu: `${Math.round(b.cpuUsage)}%`,
    ram: ramPct === null ? "--" : `${ramPct}%`,
    // Not wired yet (need throughput / sensors / ETW).
    download: "--",
    upload: "--",
    battery: "--",
    cpu_temp: "--",
    gpu: "--",
    gpu_temp: "--",
    disk: "--",
  };
}

/**
 * Main-window driver for the in-game stats overlay. While enabled, polls metrics
 * and pushes a config+values snapshot to the "overlay-stats" window ~1x/sec.
 * When disabled, pushes one snapshot so that window hides itself.
 */
export function useOverlayDriver() {
  const overlay = useSettingsStore((s) => s.settings.config.overlay);
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const ovRef = useRef<OverlayConfig>(overlay);
  ovRef.current = overlay;

  useEffect(() => {
    if (!overlay.enabled) {
      void pushOverlayRender({
        enabled: false,
        metrics: overlay.metrics,
        size: overlay.size,
        color: overlay.color,
        style: overlay.style,
        position: overlay.position,
        values: {},
      }).catch(() => {});
      return;
    }

    let disposed = false;
    let sessionStart = 0;
    let wasRunning = false;

    const tick = async () => {
      if (disposed) return;
      try {
        await fetchMetrics();
      } catch {
        /* keep last values */
      }
      const b = useBoostStore.getState();
      if (b.robloxRunning && !wasRunning) sessionStart = Date.now();
      wasRunning = b.robloxRunning;
      const sessionMs = sessionStart ? Date.now() - sessionStart : 0;
      const cfg = ovRef.current;
      await pushOverlayRender({
        enabled: true,
        metrics: cfg.metrics,
        size: cfg.size,
        color: cfg.color,
        style: cfg.style,
        position: cfg.position,
        values: computeValues(b, sessionMs),
      }).catch(() => {});
    };

    void tick();
    const id = window.setInterval(() => void tick(), 1000);
    return () => {
      disposed = true;
      window.clearInterval(id);
    };
    // Re-run only when enabled flips; live config is read via ovRef each tick.
  }, [overlay.enabled, fetchMetrics]);
}
