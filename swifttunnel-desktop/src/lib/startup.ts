import type { AppSettings, AuthState, VpnState } from "./types";

export function shouldAutoReconnectOnLaunch(
  authState: AuthState,
  vpnState: VpnState,
  settings: Pick<AppSettings, "auto_reconnect" | "resume_vpn_on_startup">,
): boolean {
  if (authState !== "logged_in") return false;
  if (vpnState !== "disconnected") return false;
  return settings.auto_reconnect && settings.resume_vpn_on_startup;
}
