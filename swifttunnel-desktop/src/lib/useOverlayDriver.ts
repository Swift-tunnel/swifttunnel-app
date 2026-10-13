import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useBoostStore } from "../stores/boostStore";
import { useSettingsStore } from "../stores/settingsStore";
import { useVpnStore } from "../stores/vpnStore";
import {
  OVERLAY_POSITION_EVENT,
  pushOverlayRender,
  type OverlayPositionPayload,
} from "../components/ingame/overlayBus";
import type { Config, OverlayConfig } from "../lib/types";
import { supportedOverlayMetrics } from "../components/ingame/overlayMetrics";
import {
  overlayValues,
  type OverlayRates,
} from "../components/ingame/overlayValues";
import {
  validOverlayMonitor,
  type OverlayMonitor,
} from "../components/ingame/overlayGeometry";
import { useGameLibraryStore } from "../stores/gameLibraryStore";
import {
  OVERLAY_HOTKEY,
  useOverlayRuntimeStore,
} from "../stores/overlayRuntimeStore";

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
  const fetchPing = useVpnStore((s) => s.fetchPing);
  const ovRef = useRef<OverlayConfig>(overlay);
  const sessionRef = useRef<{ pid: number | null; startedAt: number } | null>(
    null,
  );
  const pingRef = useRef<{ value: number; at: number } | null>(null);
  const trafficRef = useRef<{
    bytesUp: number;
    bytesDown: number;
    at: number;
  } | null>(null);
  const overlayMetricsKey = overlay.metrics.join("|");
  ovRef.current = overlay;

  // Push render snapshots.
  useEffect(() => {
    if (!overlay.enabled || !supportedOverlayMetrics(overlay.metrics).length) {
      void pushOverlayRender({
        enabled: false,
        forceHide: true,
        metrics: supportedOverlayMetrics(overlay.metrics),
        size: overlay.size,
        color: overlay.color,
        style: overlay.style,
        position: overlay.position,
        customX: overlay.custom_x,
        customY: overlay.custom_y,
        locked: overlay.locked ?? true,
        values: {},
      }).catch(() => {});
      return;
    }

    let disposed = false;
    let inFlight = false;

    // The stats window is built the first time the overlay is switched on,
    // not during startup. It costs its own WebView2 renderer process (~60MB
    // measured) and the feature is off by default. Creation failures surface
    // in the Overlay tab instead of silently polling a missing window.
    const overlayWindowReady = invoke("ensure_overlay_window", {
      label: "overlay-stats",
    })
      .then(() => true)
      .catch(() => {
        if (disposed) return false;
        useOverlayRuntimeStore.setState({
          error: "The overlay could not open. Turn it off and on to retry.",
        });
        return false;
      });

    const sample = async () => {
      const cfgBefore = ovRef.current;
      if (disposed) return;
      if (!(await overlayWindowReady)) return;
      if (disposed) return;
      const vpnBefore = useVpnStore.getState();
      let metricsFresh = false;
      try {
        metricsFresh = await fetchMetrics({
          overlayWantsFps: cfgBefore.metrics.includes("fps"),
          overlayWantsPing: false,
        });
      } catch {
        /* A stale foreground flag must not keep a topmost overlay visible. */
      }
      if (disposed) return;
      const needsThroughput =
        cfgBefore.metrics.includes("upload") ||
        cfgBefore.metrics.includes("download");
      const needsPing = cfgBefore.metrics.includes("ping");
      let trafficFresh = false;
      if (needsThroughput && vpnBefore.state === "connected") {
        try {
          trafficFresh = await fetchThroughput();
        } catch {
          /* keep last throughput sample */
        }
      }
      if (disposed) return;
      if (needsPing && vpnBefore.state === "connected") {
        try {
          await fetchPing();
        } catch {
          /* keep last ping sample */
        }
      }
      if (disposed) return;
      const b = useBoostStore.getState();
      const vpn = useVpnStore.getState();
      const nowMs = Date.now();
      let tunnelRates: OverlayRates = {
        uploadBps: null,
        downloadBps: null,
      };
      const sameTunnel =
        vpn.state === "connected" &&
        vpnBefore.state === "connected" &&
        vpn.region === vpnBefore.region;
      if (sameTunnel && trafficFresh) {
        const previous = trafficRef.current;
        trafficRef.current = {
          bytesUp: vpn.bytesUp,
          bytesDown: vpn.bytesDown,
          at: nowMs,
        };
        if (
          previous &&
          nowMs - previous.at <= 5000 &&
          vpn.bytesUp >= previous.bytesUp &&
          vpn.bytesDown >= previous.bytesDown
        ) {
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
      if (
        sameTunnel &&
        vpn.pingReadings > vpnBefore.pingReadings &&
        vpn.ping !== null
      )
        pingRef.current = { value: vpn.ping, at: nowMs };
      if (!sameTunnel) pingRef.current = null;
      if (metricsFresh) {
        if (!b.robloxRunning) sessionRef.current = null;
        else if (!sessionRef.current || sessionRef.current.pid !== b.processId)
          sessionRef.current = { pid: b.processId, startedAt: nowMs };
      }
      let monitor: OverlayMonitor | null = null;
      if (metricsFresh && b.robloxRunning) {
        try {
          const value = await invoke<OverlayMonitor | null>(
            "overlay_game_monitor",
          );
          if (validOverlayMonitor(value)) monitor = value;
        } catch {
          /* Keep last known screen. */
        }
      }
      if (disposed) return;
      // Show only while Roblox is the FOREGROUND window (not just running) so
      // it never covers the desktop or apps you've alt-tabbed to.
      const gate = metricsFresh && b.robloxForeground;
      const cfg = ovRef.current;
      await pushOverlayRender({
        enabled: cfg.enabled && gate,
        forceHide: !cfg.enabled || !metricsFresh,
        metrics: supportedOverlayMetrics(cfg.metrics),
        size: cfg.size,
        color: cfg.color,
        style: cfg.style,
        position: cfg.position,
        customX: cfg.custom_x,
        customY: cfg.custom_y,
        locked: cfg.locked ?? true,
        monitor,
        // Compute values whenever the game is running (not just foreground) so
        // the bar isn't blanked to "--" if it's held visible mid-interaction
        // across a foreground blip.
        values:
          gate || b.robloxRunning
            ? overlayValues(
                b,
                sessionRef.current ? nowMs - sessionRef.current.startedAt : 0,
                tunnelRates,
                sameTunnel &&
                  pingRef.current &&
                  nowMs - pingRef.current.at <= 5000
                  ? pingRef.current.value
                  : null,
                sameTunnel &&
                  !vpn.gameRoute?.bypassed &&
                  vpn.gameRoute?.game_server_ip ===
                    useGameLibraryStore.getState().library?.current?.ip
                  ? (vpn.gameRoute?.estimated_path_ms ?? null)
                  : null,
              )
            : {},
      })
        .then(() => useOverlayRuntimeStore.setState({ error: null }))
        .catch(() => {
          useOverlayRuntimeStore.setState({
            error:
              "The overlay stopped receiving stats. Turn it off and on to retry.",
          });
        });
    };

    // A slow native call must occupy one tick, not accumulate a new waiting
    // continuation every second. Keep the guard through the render IPC too.
    const tick = async () => {
      if (disposed || inFlight) return;
      inFlight = true;
      try {
        await sample();
      } finally {
        inFlight = false;
      }
    };

    void tick();
    const id = window.setInterval(() => void tick(), 1000);
    return () => {
      disposed = true;
      window.clearInterval(id);
    };
  }, [
    overlay.enabled,
    overlayMetricsKey,
    fetchMetrics,
    fetchThroughput,
    fetchPing,
  ]);

  // Persist the position when the user drags the bar on the overlay.
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<OverlayPositionPayload>(OVERLAY_POSITION_EVENT, (e) => {
      if (disposed || !Number.isFinite(e.payload.x) || !Number.isFinite(e.payload.y))
        return;
      const cfg = useSettingsStore.getState().settings.config;
      const next: Config = {
        ...cfg,
        overlay: {
          ...cfg.overlay,
          custom_x: e.payload.x,
          custom_y: e.payload.y,
        },
      };
      updateSettings({ config: next });
      void saveSettings();
    }).then((u) => (disposed ? u() : (unlisten = u))).catch(() => {
      if (!disposed) useOverlayRuntimeStore.setState({ error: "Overlay position could not be saved. Turn it off and on to retry." });
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [updateSettings, saveSettings]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen("overlay-toggle-request", () => {
      if (disposed) return;
      const store = useSettingsStore.getState();
      const config = store.settings.config;
      const metrics = supportedOverlayMetrics(config.overlay.metrics);
      if (!metrics.length) return;
      store.update({
        config: {
          ...config,
          overlay: {
            ...config.overlay,
            metrics,
            enabled: !config.overlay.enabled,
            hotkey: OVERLAY_HOTKEY,
          },
        },
      });
      void store.save();
    })
      .then(async (stop) => {
        if (disposed) {
          stop();
          return;
        }
        unlisten = stop;
        try {
          await invoke("ensure_overlay_shortcut");
          if (!disposed)
            useOverlayRuntimeStore.setState({ shortcutAvailable: true });
        } catch {
          if (!disposed)
            useOverlayRuntimeStore.setState({ shortcutAvailable: false });
        }
      })
      .catch(() => {
        if (!disposed) useOverlayRuntimeStore.setState({ shortcutAvailable: false });
      });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);
}
