import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import { useVpnStore } from "../stores/vpnStore";
import {
  OVERLAY_POSITION_EVENT,
  pushOverlayRender,
  type OverlayPositionPayload,
} from "../components/ingame/overlayBus";
import type { Config, OverlayConfig, OverlayMetric } from "../lib/types";

const pad = (n: number) => String(n).padStart(2, "0");

function formatRate(bytesPerSecond: number | null): string {
  if (bytesPerSecond === null) return "--";
  if (bytesPerSecond < 1024) return `${Math.round(bytesPerSecond)} B/s`;
  const kib = bytesPerSecond / 1024;
  if (kib < 1024) return `${kib.toFixed(kib >= 10 ? 0 : 1)} KB/s`;
  const mib = kib / 1024;
  return `${mib.toFixed(mib >= 10 ? 0 : 1)} MB/s`;
}

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

interface TunnelRateSnapshot {
  uploadBps: number | null;
  downloadBps: number | null;
}

function computeValues(
  b: BoostSnapshot,
  sessionMs: number,
  tunnelRates: TunnelRateSnapshot,
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
    download: formatRate(tunnelRates.downloadBps),
    upload: formatRate(tunnelRates.uploadBps),
    battery: "--",
    cpu_temp: "--",
    gpu: "--",
    gpu_temp: "--",
    disk: "--",
  };
}

/**
 * Main-window driver for the in-game stats overlay. While enabled, polls metrics
 * and pushes a config+values snapshot to the "overlay-stats" window ~1x/sec. The
 * overlay only shows while Roblox is the foreground window (`robloxForeground`)
 * so it never covers the desktop or other apps. Repositioning happens on the
 * overlay itself (grab the bar); this driver just persists the dropped position.
 */
export function useOverlayDriver() {
  const overlay = useSettingsStore((s) => s.settings.config.overlay);
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const fetchThroughput = useVpnStore((s) => s.fetchThroughput);
  const ovRef = useRef<OverlayConfig>(overlay);
  const trafficRef = useRef<{
    bytesUp: number;
    bytesDown: number;
    at: number;
  } | null>(null);
  ovRef.current = overlay;

  // Push render snapshots.
  useEffect(() => {
    if (!overlay.enabled) {
      void pushOverlayRender({
        enabled: false,
        metrics: overlay.metrics,
        size: overlay.size,
        color: overlay.color,
        style: overlay.style,
        position: overlay.position,
        customX: overlay.custom_x,
        customY: overlay.custom_y,
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
      const needsThroughput =
        ovRef.current.metrics.includes("upload") ||
        ovRef.current.metrics.includes("download");
      const vpnBefore = useVpnStore.getState();
      if (needsThroughput && vpnBefore.state === "connected") {
        try {
          await fetchThroughput();
        } catch {
          /* keep last throughput sample */
        }
      }
      const b = useBoostStore.getState();
      const vpn = useVpnStore.getState();
      const nowMs = Date.now();
      let tunnelRates: TunnelRateSnapshot = {
        uploadBps: null,
        downloadBps: null,
      };
      if (vpn.state === "connected") {
        const previous = trafficRef.current;
        trafficRef.current = {
          bytesUp: vpn.bytesUp,
          bytesDown: vpn.bytesDown,
          at: nowMs,
        };
        if (previous) {
          const seconds = Math.max((nowMs - previous.at) / 1000, 0.001);
          tunnelRates = {
            uploadBps: Math.max(0, vpn.bytesUp - previous.bytesUp) / seconds,
            downloadBps:
              Math.max(0, vpn.bytesDown - previous.bytesDown) / seconds,
          };
        }
      } else {
        trafficRef.current = null;
      }
      if (b.robloxRunning && !wasRunning) sessionStart = Date.now();
      wasRunning = b.robloxRunning;
      // Show only while Roblox is the FOREGROUND window (not just running) so
      // it never covers the desktop or apps you've alt-tabbed to.
      const gate = b.robloxForeground;
      const cfg = ovRef.current;
      await pushOverlayRender({
        enabled: gate,
        metrics: cfg.metrics,
        size: cfg.size,
        color: cfg.color,
        style: cfg.style,
        position: cfg.position,
        customX: cfg.custom_x,
        customY: cfg.custom_y,
        // Compute values whenever the game is running (not just foreground) so
        // the bar isn't blanked to "--" if it's held visible mid-interaction
        // across a foreground blip.
        values:
          gate || b.robloxRunning
            ? computeValues(
                b,
                sessionStart ? Date.now() - sessionStart : 0,
                tunnelRates,
              )
            : {},
      }).catch(() => {});
    };

    void tick();
    const id = window.setInterval(() => void tick(), 1000);
    return () => {
      disposed = true;
      window.clearInterval(id);
    };
  }, [overlay.enabled, fetchMetrics, fetchThroughput]);

  // Persist the position when the user drags the bar on the overlay.
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<OverlayPositionPayload>(OVERLAY_POSITION_EVENT, (e) => {
      const cfg = useSettingsStore.getState().settings.config;
      const next: Config = {
        ...cfg,
        overlay: { ...cfg.overlay, custom_x: e.payload.x, custom_y: e.payload.y },
      };
      updateSettings({ config: next });
      void saveSettings();
    }).then((u) => (disposed ? u() : (unlisten = u)));
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [updateSettings, saveSettings]);
}
