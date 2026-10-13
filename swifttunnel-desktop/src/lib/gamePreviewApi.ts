// Development-only fixture service. Never calls the native backend, changes
// files, connects a tunnel, or launches a real game.
import type { GamePreferences, RobloxDatacenter, RobloxLibrarySnapshot, LauncherConfig } from "./types";
let launcher:LauncherConfig={matchmaker:{enabled:false,mode:"closest",blocked_datacenters:[],preferred_datacenter:null,skipped_games:[],minimum_free_slots:1,search_limit:40,prepare_tunnel:true,offer_better_server:false},profiles:[],offer_recovery:false};
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
    case "games_launcher_config": result=launcher;break;
    case "games_save_launcher_config":launcher=args.config as LauncherConfig;break;
    case "games_displays":result=[{id:"preview-primary",primary:true,left:0,top:0,width:1920,height:1080},{id:"preview-secondary",primary:false,left:1920,top:0,width:2560,height:1440}];break;
    case "games_startup_target":case "games_suggest_server":result=null;break;
    case "games_dismiss_recovery":library.recovery=null;break;
    case "games_create_shortcut":result="Design preview: no shortcut was created.";break;
    case "games_refresh_metadata": break;
    case "games_datacenters": result = centers; break;
    case "games_set_favourite": if (entry) entry.favourite = Boolean(args.favourite); break;
    case "games_set_notifications": library.notify_joins = Boolean(args.enabled); break;
    case "games_set_preferences": if (entry) entry.preferences = args.preferences as GamePreferences; break;
    case "games_forget": library.entries = library.entries.filter(e => e !== entry); break;
    case "games_add_favourite": library.entries.push({ place_id: String(args.placeId), name: `Place ${args.placeId}`, client: args.client === "vng" ? "vng" : "standard", job_id: null, favourite: true, last_played: null, preferences: { ...preferences } }); break;
    case "games_launch_plan": {
      const prefs = entry?.preferences ?? preferences;
      const center = centers.find(c => c.id === (args.datacenterId ?? (args.usePreferredRegion ? prefs.datacenter_id : null))) ?? null;
      result = { job_id: args.jobId ?? (center ? job : null), datacenter: center, preferences: prefs, availability: "available", needs_close: prefs.use_tunnel || prefs.fps_cap !== null || prefs.graphics_quality !== null, relay_region: prefs.use_tunnel ? center?.relay_region ?? null : null };
      break;
    }
    case "games_search_servers": result = { servers: Array.from({ length: 3 }, (_,i) => ({ job_id: i ? `${i}50e8400-e29b-41d4-a716-446655440000` : job, datacenter_id: 1, ip: "128.116.47.33", first_seen: "2026-10-12T12:00:00Z", playing: [5,12,15][i], capacity: 15, availability: i === 2 ? "full" : "available" })), next_cursor: null, warning: null }; break;
    case "games_launch": {
      running = true;
      library.current = { place_id: String(args.placeId), job_id: String(args.jobId ?? job), ip: "128.116.47.33", client: args.client === "vng" ? "vng" : "standard", fresh_join: false, observed_at: Date.now() };
      const { useVpnStore } = await import("../stores/vpnStore");
      useVpnStore.setState({ gameRoute: { game_location: "Mumbai", game_server_ip: "128.116.47.33", estimated_path_ms: 26, relay: "mumbai-01", bypassed: false } });
      break;
    }
    case "boost_get_metrics": result = { roblox_running: running, roblox_foreground: false, fps: 0, cpu_usage: 0, ram_usage: 0, ram_total: 0, ping: 0, process_id: null }; break;
    case "boost_close_roblox": running = false; library.current = null; break;
    case "games_scan_imports": result = { sources: [{ source: "Fishstrap", accepted: 2, json: '{"FFlagDebugGraphicsPreferD3D11":"True","DFIntTextureQualityOverride":"0"}', skipped: ["FFlagOldUnsupportedFlag: unsupported or ignored by Roblox"], error: null }], fps_cap: 240, graphics_quality: "Level5" }; break;
    case "settings_save": break;
    case "games_flags": result = { files_changed: 2, flags_removed: 7, skipped: [], can_undo: true }; break;
    case "games_save_flags": {
      const { useSettingsStore } = await import("../stores/settingsStore");
      const config = structuredClone(useSettingsStore.getState().settings.config);
      Object.assign(config.roblox_settings, { custom_fflags_enabled: args.enabled, custom_fflags_json: args.json, ultraboost: false });
      result = { applied_config: config, warnings: [] }; break;
    }
    case "games_nvidia_profile": result = { available: true, writable: true, reason: null, settings: [0x1057eb71, 0x00a879cf, 0x10835002, 0x007ba09e].map(id => ({ id, current: id === 0x00a879cf ? 0x60925292 : 0, override_value: null })) }; break;
    case "games_save_nvidia": result = { available: true, writable: true, reason: null, settings: (args.expected as { id:number;current:number|null;override_value:number|null }[]).map(s => { const change=(args.changes as {id:number;value:number|null}[]).find(c=>c.id===s.id); return change?{...s,current:change.value,override_value:change.value}:s; }) }; break;
    case "system_open_url": break;
    default: throw new Error(`This action is not simulated in the design preview (${command}).`);
  }
  return structuredClone(result) as T;
}
