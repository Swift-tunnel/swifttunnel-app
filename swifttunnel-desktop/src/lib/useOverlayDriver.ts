import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import {
  OVERLAY_POSITION_EVENT,
  pushOverlayRender,
  type OverlayPositionPayload,
} from "../components/ingame/overlayBus";
import type { Config, OverlayConfig, OverlayMetric } from "../lib/types";

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
 * and pushes a config+values snapshot to the "overlay-stats" window ~1x/sec. The
 * overlay only shows while Roblox is the foreground window (`robloxForeground`)
 * so it never covers the desktop or other apps. Repositioning happens on the
 * overlay itself (grab the bar); this driver just persists the dropped position.
 */
export function useOverlayDriver() {
  const overlay = useSettingsStore((s) => s.settings.config.overlay);
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const ovRef = useRef<OverlayConfig>(overlay);
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
      const b = useBoostStore.getState();
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
        values: gate
          ? computeValues(b, sessionStart ? Date.now() - sessionStart : 0)
          : {},
      }).catch(() => {});
    };

    void tick();
    const id = window.setInterval(() => void tick(), 1000);
    return () => {
      disposed = true;
      window.clearInterval(id);
    };
  }, [overlay.enabled, fetchMetrics]);

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
