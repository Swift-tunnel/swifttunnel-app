import { useEffect, useRef, useState } from "react";
import { useVpnStore } from "../stores/vpnStore";
import { vpnGetThroughput } from "./commands";
import { useLiveUpdates } from "./useLiveUpdates";
import { isMainWindowHidden, subscribeMainWindowVisibility } from "./mainWindowVisibility";
import { MAX_SAMPLES, SAMPLE_INTERVAL_MS, type DataSample } from "../components/connect/LiveGraph";

/** Own the fast graph updates below the connection controls and relay picker. */
export function useTrafficSamples(showGraph: boolean): DataSample[] {
  const [history, setHistory] = useState<DataSample[]>([]);
  const samples = useRef<DataSample[]>([]);
  const live = useLiveUpdates();
  const liveRef = useRef(live);
  liveRef.current = live;
  const shouldSample = showGraph || live;

  useEffect(() => {
    if (!shouldSample) return;
    let cancelled = false;
    let inFlight = false;
    let visibilityRevision = 0;
    let timer: number | undefined;
    let previous: { up: number; down: number; at: number } | null = null;
    let session: { region: string | null; connectedAt: number } | null = null;
    samples.current = [];
    setHistory([]);

    const sample = async () => {
      if (cancelled || inFlight || isMainWindowHidden()) return;
      // A hidden graph needs no history. Keep only its visible transfer totals
      // current, and leave the background window idle.
      if (!showGraph && !liveRef.current) return;
      const before = useVpnStore.getState();
      if (before.state !== "connected" || before.connectedAt === null) {
        previous = null;
        return;
      }
      if (session?.connectedAt !== before.connectedAt || session.region !== before.region) {
        previous = null;
        session = { region: before.region, connectedAt: before.connectedAt };
        if (samples.current.length) {
          samples.current = [];
          if (liveRef.current) setHistory([]);
        }
      }
      inFlight = true;
      const revision = visibilityRevision;
      try {
        let totals: { up: number; down: number } | null = null;
        if (liveRef.current) {
          if (await useVpnStore.getState().fetchThroughput()) {
            const state = useVpnStore.getState();
            totals = { up: state.bytesUp, down: state.bytesDown };
          }
        } else {
          // Preserve the match's graph without waking store subscribers.
          const stats = await vpnGetThroughput();
          if (stats) totals = { up: stats.bytes_up, down: stats.bytes_down };
        }
        if (cancelled || isMainWindowHidden() || revision !== visibilityRevision || !totals || !showGraph) return;
        // Counter magnitudes cannot identify a reconnect. A new tunnel may
        // already have larger totals, and a slow read may cross the switch.
        const current = useVpnStore.getState();
        if (current.state !== "connected" || current.connectedAt !== before.connectedAt || current.region !== before.region) {
          previous = null;
          return;
        }
        const at = performance.now();
        if (previous && totals.up >= previous.up && totals.down >= previous.down) {
          const seconds = Math.max(1, at - previous.at) / 1000;
          samples.current = [...samples.current, {
            t: Date.now(),
            up: (totals.up - previous.up) / seconds,
            down: (totals.down - previous.down) / seconds,
          }].slice(-MAX_SAMPLES);
          if (liveRef.current) setHistory(samples.current);
        }
        previous = { ...totals, at };
      } catch {
        // A missed reading must not stop sampling or become a zero sample.
      } finally {
        inFlight = false;
      }
    };
    const startSampling = () => {
      void sample();
      timer = window.setInterval(() => void sample(), showGraph ? SAMPLE_INTERVAL_MS : 1000);
    };
    const syncVisibility = () => {
      if (isMainWindowHidden()) {
        if (timer !== undefined) window.clearInterval(timer);
        timer = undefined;
        visibilityRevision += 1;
        // The graph uses evenly spaced samples. Start a new baseline after
        // a hidden period so it never paints the gap as a half-second sample.
        previous = null;
        samples.current = [];
        return;
      }
      if (cancelled || timer !== undefined) return;
      if (showGraph && liveRef.current) setHistory(samples.current);
      startSampling();
    };
    const stopWatchingVisibility = subscribeMainWindowVisibility(syncVisibility);
    if (!isMainWindowHidden()) startSampling();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearInterval(timer);
      stopWatchingVisibility();
    };
  }, [showGraph, shouldSample]);

  useEffect(() => {
    if (!live || isMainWindowHidden()) return;
    setHistory(samples.current);
    // An enabled graph sampled without updating the background UI. With the
    // graph off, the sampler restarts and takes its own immediate reading.
    if (showGraph) void useVpnStore.getState().fetchThroughput();
  }, [live, showGraph]);

  return history;
}
