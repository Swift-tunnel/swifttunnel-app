import { captureConnectionIntent, useVpnStore } from "../stores/vpnStore";
import { useSettingsStore } from "../stores/settingsStore";
import { useServerStore } from "../stores/serverStore";
import { findRegionForVpnRegion } from "./regionMatch";

export async function prepareGameConnection(requested: string | null, onPreparing: () => void) {
  const unchanged = captureConnectionIntent();
  const requireCurrent = (current: () => boolean) => {
    if (!current()) throw new Error("Your connection changed while preparing the game. Try Play again.");
  };
  // Check the native session before reusing a relay. A stale UI snapshot must
  // not let a game launch through a different location.
  const verified = await useVpnStore.getState().fetchState();
  requireCurrent(unchanged);
  if (!verified) {
    throw new Error(useVpnStore.getState().error ?? "Couldn't confirm your current connection. Try Play again.");
  }
  const vpn = useVpnStore.getState();
  if (vpn.state === "connected" && vpn.error) throw new Error(vpn.error);
  const existing = vpn.state === "connected";
  const family = findRegionForVpnRegion(useServerStore.getState().regions, vpn.region)?.id;
  if (existing && (!requested || family === requested)) return;

  onPreparing();
  if (existing) {
    const disconnecting = vpn.disconnect();
    const stillDisconnecting = captureConnectionIntent();
    await disconnecting;
    requireCurrent(stillDisconnecting);
    const stopped = useVpnStore.getState();
    if (stopped.state !== "disconnected" || stopped.splitTunnelActive || stopped.error) {
      throw new Error(stopped.error ?? "Couldn't confirm the previous tunnel disconnected. Retry Disconnect in Connect, then try Play again.");
    }
  }
  const settings = useSettingsStore.getState().settings;
  const presets = settings.selected_game_presets.includes("roblox")
    ? settings.selected_game_presets
    : [...settings.selected_game_presets, "roblox"];
  const connecting = useVpnStore.getState().connect(requested ?? settings.selected_region, presets, requested !== null);
  const stillConnecting = captureConnectionIntent();
  await connecting;
  requireCurrent(stillConnecting);
  const connected = useVpnStore.getState();
  if (connected.state !== "connected" || connected.error) {
    throw new Error(connected.error ?? "Finish connecting in Connect, then try Play again.");
  }
  if (requested && findRegionForVpnRegion(useServerStore.getState().regions, connected.region)?.id !== requested) {
    throw new Error("Couldn't connect to the relay for this location. Check Connect, then try again.");
  }
}
