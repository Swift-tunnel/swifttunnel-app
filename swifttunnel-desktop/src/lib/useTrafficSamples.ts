import { useEffect, useRef, useState } from "react";
import { useVpnStore } from "../stores/vpnStore";
import { vpnGetThroughput } from "./commands";
import { useLiveUpdates } from "./useLiveUpdates";
import { MAX_SAMPLES, SAMPLE_INTERVAL_MS, type DataSample } from "../components/connect/LiveGraph";

/** Own the fast graph updates below the connection controls and relay picker. */
export function useTrafficSamples(showGraph: boolean): DataSample[] {
  const [history, setHistory] = useState<DataSample[]>([]);
  const samples = useRef<DataSample[]>([]);
  const live = useLiveUpdates();
  const liveRef = useRef(live);
  liveRef.current = live;

  useEffect(() => {
    let cancelled = false;
    let inFlight = false;
    let previous: { up: number; down: number; at: number } | null = null;
    let session: { region: string | null; connectedAt: number } | null = null;
    samples.current = [];
    setHistory([]);

    const sample = async () => {
      if (cancelled || inFlight) return;
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
        if (cancelled || !totals || !showGraph) return;
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
    void sample();
    const timer = window.setInterval(() => void sample(), showGraph ? SAMPLE_INTERVAL_MS : 1000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [showGraph]);

  useEffect(() => {
    if (!live) return;
    setHistory(samples.current);
    // Totals must also catch up when the graph is hidden.
    void useVpnStore.getState().fetchThroughput();
  }, [live]);

  return history;
}
