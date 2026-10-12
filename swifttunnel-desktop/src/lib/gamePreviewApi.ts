// Development-only fixture service. Never calls the native backend, changes
// files, connects a tunnel, or launches a real game.
import type { GamePreferences, RobloxDatacenter, RobloxLibrarySnapshot } from "./types";
const preferences: GamePreferences = { datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false };
const job = "550e8400-e29b-41d4-a716-446655440000";
const library: RobloxLibrarySnapshot = { current: null, warning: null, notify_joins: true, launch_pending: false, entries: [
  { place_id: "10449761463", name: "The Strongest Battlegrounds", job_id: job, last_played: 1791806400, favourite: true, client: "standard", preferences: { ...preferences, fps_cap: 240, datacenter_id: 7 }, icon_url: "https://tr.rbxcdn.com/180DAY-68c92fc62a8753793f7963e146b5197f/256/256/Image/Png/noFilter" },
  { place_id: "17625359962", name: "RIVALS", job_id: job, last_played: 1791720000, favourite: true, client: "standard", preferences: { ...preferences }, icon_url: "https://tr.rbxcdn.com/180DAY-2f7bb0535e48ac3766835b44ded27a74/256/256/Image/Png/noFilter" },
  { place_id: "1818", name: "Crossroads", job_id: job, last_played: 1791633600, favourite: false, client: "standard", preferences: { ...preferences }, icon_url: "https://tr.rbxcdn.com/180DAY-672284ae50f6bece92ce3c92c1ea6067/256/256/Image/Png/noFilter" },
  { place_id: "920587237", name: "Adopt Me!", job_id: null, last_played: 1791547200, favourite: false, client: "standard", preferences: { ...preferences } },
] };
const centers: RobloxDatacenter[] = [
  { id: 7, city: "Mumbai", country: "IN", relay_region: "mumbai", datacenter_ids: [1] },
  { id: 10, city: "Singapore", country: "SG", relay_region: "singapore", datacenter_ids: [2] },
  { id: 8, city: "Tokyo", country: "JP", relay_region: "tokyo", datacenter_ids: [3] },
  { id: 3, city: "Frankfurt am Main", country: "DE", relay_region: "germany", datacenter_ids: [4] },
  { id: 5, city: "London", country: "GB", relay_region: "london", datacenter_ids: [5] },
  { id: 1, city: "Sydney", country: "AU", relay_region: "sydney", datacenter_ids: [6] },
  { id: 3588, city: "Jakarta", country: "ID", relay_region: "jakarta", datacenter_ids: [7] },
  { id: 3594, city: "Tel Aviv", country: "IL", relay_region: "israel", datacenter_ids: [8] },
];
let running = false;
export async function previewInvoke<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  let result: unknown = null;
  const entry = library.entries.find(e => e.place_id === args.placeId && e.client === args.client);
  switch (command) {
    case "games_get_library": result = structuredClone(library); break;
    case "games_refresh_metadata": break;
    case "games_datacenters": result = centers; break;
    case "games_set_favourite": if (entry) entry.favourite = Boolean(args.favourite); break;
    case "games_set_notifications": library.notify_joins = Boolean(args.enabled); break;
    case "games_set_preferences": if (entry) entry.preferences = args.preferences as GamePreferences; break;
    case "games_forget": library.entries = library.entries.filter(e => e !== entry); break;
    case "games_add_favourite": library.entries.push({ place_id: String(args.placeId), name: `Place ${args.placeId}`, client: "standard", job_id: null, favourite: true, last_played: null, preferences: { ...preferences } }); break;
    case "games_launch_plan": {
      const prefs = entry?.preferences ?? preferences;
      const center = centers.find(c => c.id === (args.datacenterId ?? (args.usePreferredRegion ? prefs.datacenter_id : null))) ?? null;
      result = { job_id: args.jobId ?? (center ? job : null), datacenter: center, preferences: prefs, availability: "available", needs_close: prefs.use_tunnel || prefs.fps_cap !== null || prefs.graphics_quality !== null, relay_region: prefs.use_tunnel ? center?.relay_region ?? null : null };
      break;
    }
    case "games_search_servers": result = { servers: Array.from({ length: 3 }, (_,i) => ({ job_id: i ? `${i}50e8400-e29b-41d4-a716-446655440000` : job, datacenter_id: 1, ip: "128.116.47.33", first_seen: "2026-10-12T12:00:00Z", playing: [5,12,15][i], capacity: 15, availability: i === 2 ? "full" : "available" })), next_cursor: null, warning: null }; break;
    case "games_launch": {
      running = true;
      library.current = { place_id: String(args.placeId), job_id: String(args.jobId ?? job), ip: "128.116.47.33", client: "standard", fresh_join: false, observed_at: Date.now() };
      const { useVpnStore } = await import("../stores/vpnStore");
      useVpnStore.setState({ gameRoute: { game_location: "Mumbai", game_server_ip: "128.116.47.33", estimated_path_ms: 26, relay: "mumbai-01", bypassed: false } });
      break;
    }
    case "boost_get_metrics": result = { roblox_running: running, roblox_foreground: false, fps: 0, cpu_usage: 0, ram_usage: 0, ram_total: 0, ping: 0, process_id: null }; break;
    case "boost_close_roblox": running = false; library.current = null; break;
    case "games_scan_imports": result = { sources: [{ source: "Fishstrap", accepted: 2, json: '{"FFlagDebugGraphicsPreferD3D11":"True","DFIntTextureQualityOverride":"0"}', skipped: ["FFlagOldUnsupportedFlag: unsupported or ignored by Roblox"], error: null }], fps_cap: 240, graphics_quality: "Level5" }; break;
    case "games_cleanup": result = { files: 28, bytes: 24 * 1024 * 1024, skipped: 0, partial: false }; break;
    case "games_flags": result = { files_changed: 2, flags_removed: 7, skipped: [], can_undo: true }; break;
    case "system_open_url": break;
    default: throw new Error(`This action is not simulated in the design preview (${command}).`);
  }
  return structuredClone(result) as T;
}
