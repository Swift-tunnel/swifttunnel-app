import { useEffect, useState } from "react";
import { reportError } from "./errors";

export const OAUTH_TIMEOUT_MS = 120_000;

/** Each browser sign-in attempt owns its timer and ignores late poll replies. */
export function useOAuthPolling(
  waiting: boolean,
  poll: () => Promise<boolean>,
  cancel: (reason: string) => Promise<void>,
): number {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    setElapsed(0);
    if (!waiting) return;
    const started = performance.now();
    let disposed = false;
    let polling = false;
    const stop = () => { disposed = true; window.clearInterval(timer); };
    const timer = window.setInterval(() => {
      if (disposed) return;
      const duration = Math.max(0, performance.now() - started);
      setElapsed(Math.floor(duration / 1000));
      // A stalled poll must not suspend the sign-in deadline.
      if (duration >= OAUTH_TIMEOUT_MS) {
        stop();
        void cancel("Login timed out. Please try again.").catch((error) => {
          reportError("Failed to cancel browser sign-in", error);
        });
        return;
      }
      if (polling) return;
      polling = true;
      void poll().then((done) => {
        if (!disposed && done) stop();
      }).catch((error) => {
        if (!disposed) reportError("Failed to check browser sign-in", error);
      }).finally(() => { polling = false; });
    }, 1000);
    return stop;
  }, [waiting, poll, cancel]);
  return elapsed;
}
