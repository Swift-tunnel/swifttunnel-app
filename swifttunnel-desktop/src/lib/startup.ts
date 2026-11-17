import type { AppSettings, AuthState, VpnState } from "./types";

/** One piece of startup the launch screen waits for. */
export interface StartupStep {
  label: string;
  done: boolean;
}

/**
 * Where the launch screen stands: how many steps have finished, how full the
 * bar is, and the label of the first step still running (null once all are
 * done). Steps can finish in any order. The bar keeps a sliver before the first
 * one finishes, so it never reads as stalled at nothing.
 */
export function startupProgress(steps: StartupStep[]): {
  done: number;
  fraction: number;
  current: string | null;
} {
  const done = steps.filter((s) => s.done).length;
  const fraction = steps.length === 0 ? 1 : Math.max(0.06, done / steps.length);
  const current = steps.find((s) => !s.done)?.label ?? null;
  return { done, fraction, current };
}

export function shouldAutoReconnectOnLaunch(
  authState: AuthState,
  vpnState: VpnState,
  settings: Pick<AppSettings, "auto_reconnect" | "resume_vpn_on_startup">,
): boolean {
  if (authState !== "logged_in") return false;
  if (vpnState !== "disconnected") return false;
  return settings.auto_reconnect && settings.resume_vpn_on_startup;
}

export function watchStartupRecoveryCompletion(
  subscribe: (complete: () => void) => Promise<() => void>,
  isDone: () => Promise<boolean>,
  onComplete: () => void,
  onSubscribeError: (error: unknown) => void,
): () => void {
  let disposed = false;
  let completed = false;
  let unlisten: (() => void) | undefined;

  const complete = () => {
    if (disposed || completed) return;
    completed = true;
    onComplete();
  };

  void (async () => {
    try {
      const stop = await subscribe(complete);
      if (disposed) {
        stop();
        return;
      }
      unlisten = stop;
    } catch (error) {
      if (!disposed) onSubscribeError(error);
    }

    // Wait until the listener is active before checking. Completion before
    // subscription is then visible in the query, and later completion emits.
    if (disposed || completed) return;
    try {
      if (await isDone()) complete();
    } catch {
      // The event listener and splash timeout still cover a failed query.
    }
  })();

  return () => {
    disposed = true;
    unlisten?.();
  };
}

export function pollUpdateRequirement(
  read: () => Promise<string | null>,
  publish: (message: string | null) => void,
): () => void {
  let stopped = false;
  let timer = window.setTimeout(check, 1500);

  async function check() {
    try {
      const message = await read();
      // A successful null clears the gate. An IPC failure keeps its last state.
      if (!stopped) publish(message);
    } catch {
      // The command may be unavailable or the backend temporarily busy.
    } finally {
      if (!stopped) timer = window.setTimeout(check, 20_000);
    }
  }

  return () => {
    stopped = true;
    window.clearTimeout(timer);
  };
}
