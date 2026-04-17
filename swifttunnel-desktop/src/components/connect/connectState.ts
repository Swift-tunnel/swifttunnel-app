export type GameId = "roblox" | "valorant" | "fortnite";

export const GAMES: { id: GameId; name: string; brandColor: string }[] = [
  { id: "roblox", name: "Roblox", brandColor: "#e2231a" },
  { id: "valorant", name: "Valorant", brandColor: "#ff4655" },
  { id: "fortnite", name: "Fortnite", brandColor: "#8b5cf6" },
];

export function stateLabel(state: string): string {
  switch (state) {
    case "disconnected":
      return "Ready to connect";
    case "fetching_config":
      return "Resolving relay\u2026";
    case "creating_adapter":
      return "Creating adapter\u2026";
    case "connecting":
      return "Establishing tunnel\u2026";
    case "configuring_split_tunnel":
      return "Configuring split tunnel\u2026";
    case "configuring_routes":
      return "Setting routes\u2026";
    case "connected":
      return "Connected";
    case "disconnecting":
      return "Disconnecting\u2026";
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

export function resolveConnectStatus(input: {
  driverSetupState: "idle" | "checking" | "installing" | "installed" | "error";
  driverSetupError: string | null;
  vpnError: string | null;
  vpnState: string;
}):
  | { kind: "text"; text: string }
  | { kind: "driver_missing"; text: string } {
  if (input.driverSetupState === "checking") {
    return { kind: "text", text: "Checking split tunnel driver\u2026" };
  }

  if (input.driverSetupState === "installing") {
    return {
      kind: "text",
      text: "Installing required split tunnel driver\u2026",
    };
  }

  if (input.driverSetupState === "installed") {
    return { kind: "text", text: "Driver installed. Click Connect to retry." };
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
