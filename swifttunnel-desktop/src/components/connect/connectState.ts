export const GAMES = [
  { id: "roblox", name: "Roblox", icon: "\u{1F3AE}" },
  { id: "valorant", name: "Valorant", icon: "\u{1F3AF}" },
  { id: "fortnite", name: "Fortnite", icon: "\u{1F3D7}️" },
];

export function stateLabel(state: string): string {
  switch (state) {
    case "disconnected":
      return "Ready to connect";
    case "fetching_config":
      return "Resolving relay…";
    case "creating_adapter":
      return "Creating adapter…";
    case "connecting":
      return "Establishing tunnel…";
    case "configuring_split_tunnel":
      return "Configuring split tunnel…";
    case "configuring_routes":
      return "Setting routes…";
    case "connected":
      return "Connected";
    case "disconnecting":
      return "Disconnecting…";
    case "error":
      return "Connection failed";
    default:
      return state;
  }
}

export function isDriverMissing(vpnError: string | null): boolean {
  return (
    !!vpnError &&
    vpnError.toLowerCase().includes("split tunnel driver not available") &&
    vpnError.toLowerCase().includes("windows packet filter driver")
  );
}

/**
 * Match post-install errors that Windows can only resolve with a reboot.
 *
 * The backend emits these strings from `system_install_driver` whenever
 * msiexec returns 1641/3010, or when the post-install self-test fails
 * immediately after a reboot-signaling exit code. Substring-matching keeps
 * us decoupled from structured errors across the Tauri boundary — the
 * invariant is that both source strings begin with "Reboot required to
 * finish driver installation" so a single lowercase substring is enough.
 */
export function isRebootRequired(
  vpnError: string | null,
  driverSetupError: string | null,
): boolean {
  const haystack = `${vpnError ?? ""}\n${driverSetupError ?? ""}`.toLowerCase();
  return haystack.includes("reboot required to finish driver installation");
}

/**
 * Match errors from a pre-3.6.2 WinpkFilter install that another product
 * (ExpressVPN, NordLynx, standalone Wiresock) may have left on the machine.
 * The self-test surfaces these with a specific phrase so the UI can render
 * a "reset driver service" escalation that avoids a full reinstall when a
 * service restart would clear it.
 */
export function isDriverVersionTooOld(vpnError: string | null): boolean {
  return (
    !!vpnError &&
    vpnError
      .toLowerCase()
      .includes("split tunnel driver is older than swifttunnel requires")
  );
}

export function resolveConnectStatus(input: {
  driverSetupState: "idle" | "checking" | "installing" | "installed" | "error";
  driverSetupError: string | null;
  vpnError: string | null;
  vpnState: string;
  /**
   * Set by the store once the user has clicked "Reset driver service" and
   * it failed. When true, this function stops returning `driver_outdated`
   * (which renders the reset button) and falls through to plain text, so
   * the UI surfaces the full remediation message from the backend —
   * typically "Uninstall the other tool's driver, then reinstall
   * SwiftTunnel's driver." — instead of offering the same button that
   * just didn't work. Optional for backward compatibility with callers
   * that don't thread this state through.
   */
  driverResetAttempted?: boolean;
}):
  | { kind: "text"; text: string }
  | { kind: "driver_missing"; text: string }
  | { kind: "reboot_required"; text: string }
  | { kind: "driver_outdated"; text: string } {
  if (input.driverSetupState === "checking") {
    return { kind: "text", text: "Checking split tunnel driver…" };
  }

  if (input.driverSetupState === "installing") {
    return {
      kind: "text",
      text: "Installing required split tunnel driver…",
    };
  }

  if (input.driverSetupState === "installed") {
    return { kind: "text", text: "Driver installed. Click Connect to retry." };
  }

  // Reboot-required takes priority over the driver-missing / outdated paths:
  // if a prior install signaled "reboot to finish" we must NOT redirect the
  // user into another reinstall loop — that's exactly the state the 1.25.2
  // support reports showed (install -> "no driver" -> install -> "no driver",
  // until the user happened to reboot on their own).
  if (isRebootRequired(input.vpnError, input.driverSetupError)) {
    return {
      kind: "reboot_required",
      text: "Reboot required to finish installing the split tunnel driver.",
    };
  }

  if (isDriverVersionTooOld(input.vpnError) && !input.driverResetAttempted) {
    return {
      kind: "driver_outdated",
      text: "Older split tunnel driver detected. Reset driver service",
    };
  }

  if (input.driverSetupState === "error") {
    return {
      kind: "text",
      text: input.driverSetupError || "Driver install failed.",
    };
  }

  if (isDriverMissing(input.vpnError)) {
    return {
      kind: "driver_missing",
      text: "Split tunnel driver not available. Install",
    };
  }

  return { kind: "text", text: input.vpnError || stateLabel(input.vpnState) };
}
