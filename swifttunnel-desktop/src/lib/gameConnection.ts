import { useVpnStore } from "../stores/vpnStore";
import { useSettingsStore } from "../stores/settingsStore";
import { useServerStore } from "../stores/serverStore";
import { findRegionForVpnRegion } from "./regionMatch";

export async function prepareGameConnection(requested: string | null, onPreparing: () => void) {
  // Check the native session before reusing a relay. A stale UI snapshot must
  // not let a game launch through a different location.
  await useVpnStore.getState().fetchState();
  const vpn = useVpnStore.getState();
  if (vpn.state === "connected" && vpn.error) throw new Error(vpn.error);
  const existing = vpn.state === "connected";
  const family = findRegionForVpnRegion(useServerStore.getState().regions, vpn.region)?.id;
  if (existing && (!requested || family === requested)) return;

  onPreparing();
  if (existing) await vpn.disconnect();
  const settings = useSettingsStore.getState().settings;
  const presets = settings.selected_game_presets.includes("roblox")
    ? settings.selected_game_presets
    : [...settings.selected_game_presets, "roblox"];
  await useVpnStore.getState().connect(requested ?? settings.selected_region, presets, requested !== null);
  const connected = useVpnStore.getState();
  if (connected.state !== "connected") {
    throw new Error(connected.error ?? "Finish connecting in Connect, then try Play again.");
  }
  if (requested && findRegionForVpnRegion(useServerStore.getState().regions, connected.region)?.id !== requested) {
    throw new Error("Couldn't connect to the relay for this location. Check Connect, then try again.");
  }
}
