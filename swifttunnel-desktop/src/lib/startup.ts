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
