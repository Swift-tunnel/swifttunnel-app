import {
  OPTIMIZATIONS,
  SPEEDUP_OPTIMIZATIONS,
} from "../components/optimization/optimizationCatalog";
import { navItemFor } from "../components/shell/nav";
import type { TabId } from "./types";

export interface SearchEntry {
  id: string;
  tab: TabId;
  /** Game to auto-open in the Games tab (deep-link into Roblox → Optimize). */
  game?: string;
  /** `data-search-anchor` to reveal + flash after navigating. */
  anchor?: string;
  /** If set, selecting dispatches this window event instead of navigating. */
  event?: string;
  label: string;
  /** Where it lives, shown as the row's sub-label. */
  section: string;
  /** Space-joined aliases + real terms for matching. */
  keywords: string;
  /** SVG path for the row icon (borrowed from the destination tab). */
  icon: string;
}

/**
 * Row icons, borrowed from the destination tab.
 *
 * Wrapped in a helper and annotated pure so a build that never reaches the
 * palette can drop them. Without it Rollup keeps eight calls it cannot prove
 * are side-effect free, and they drag the whole nav table and the 33KB
 * optimization catalog into the Lite bundle, which renders neither. The
 * annotation only permits removal where the result goes unused, which in the
 * full app it never does.
 */
const icon = (tab: TabId): string => navItemFor(tab).icon;

const homeIcon = /* @__PURE__ */ icon("home");
const connectIcon = /* @__PURE__ */ icon("connect");
const networkIcon = /* @__PURE__ */ icon("network");
const optimizeIcon = /* @__PURE__ */ icon("optimization");
const gamesIcon = /* @__PURE__ */ icon("games");
const ingameIcon = /* @__PURE__ */ icon("ingame");
const repairIcon = /* @__PURE__ */ icon("repair");
const settingsIcon = /* @__PURE__ */ icon("settings");

// ── Top-level tabs ──
const TABS: SearchEntry[] = [
  {
    id: "tab-home",
    tab: "home",
    label: "Home",
    section: "Go to page",
    icon: homeIcon,
    keywords: "home dashboard summary overview welcome start landing",
  },
  {
    id: "tab-connect",
    tab: "connect",
    label: "Connect",
    section: "Go to page",
    icon: connectIcon,
    keywords:
      "connect tunnel relay region server bypass country ban partial full route assist vpn adapter latency",
  },
  {
    id: "tab-network",
    tab: "network",
    label: "Diagnostics",
    section: "Go to page",
    icon: networkIcon,
    keywords:
      "diagnostics diagnosis speed test ping stability route health packet loss network bufferbloat",
  },
  {
    id: "tab-optimization",
    tab: "optimization",
    label: "Optimize",
    section: "Go to page",
    icon: optimizeIcon,
    keywords: "optimize boost fps performance tweaks windows latency ram",
  },
  {
    id: "tab-games",
    tab: "games",
    label: "Games",
    section: "Go to page",
    icon: gamesIcon,
    keywords: "games library roblox per-game tuning graphics boost",
  },
  {
    id: "tab-ingame",
    tab: "ingame",
    label: "In-Game",
    section: "Go to page",
    icon: ingameIcon,
    keywords: "in game overlay hud fps counter cpu ram network monitor",
  },
  {
    id: "tab-repair",
    tab: "repair",
    label: "Repair",
    section: "Go to page",
    icon: repairIcon,
    keywords:
      "repair fix internet recovery driver reset adapter binding support winsock no internet",
  },
  {
    id: "tab-settings",
    tab: "settings",
    label: "Settings",
    section: "Go to page",
    icon: settingsIcon,
    keywords:
      "settings account login logout update preferences hotkeys language discord support version sign out",
  },
];

// ── Roblox boost settings (Games → Roblox → Optimize) ──
const BOOST_SETTINGS: { anchor: string; label: string; keywords: string }[] = [
  {
    anchor: "unlock_fps",
    label: "Unlock FPS",
    keywords: "unlock fps uncap framerate 60 cap target fps limit",
  },
  {
    anchor: "ultraboost",
    label: "Ultraboost",
    keywords:
      "ultraboost ultra boost ffs fps flags fastflags fast flags fflags fflag curated roblox fps boost graphics",
  },
  {
    anchor: "custom_fflags",
    label: "Custom FFlag Import",
    keywords: "custom fflags fflag flags json import advanced client flags",
  },
  {
    anchor: "window_resolution",
    label: "Window resolution",
    keywords: "resolution window size width height dimensions",
  },
  {
    anchor: "launch_fullscreen",
    label: "Launch Fullscreen",
    keywords: "fullscreen full screen borderless launch",
  },
  {
    anchor: "country_ban",
    label: "Bypass Country Ban",
    keywords:
      "country ban full bypass egypt blocked platform banned unblock roblox",
  },
  {
    anchor: "high_priority",
    label: "High Priority Mode",
    keywords: "high priority process cpu fps boost priority",
  },
  {
    anchor: "timer_resolution",
    label: "Timer Resolution",
    keywords: "timer resolution frame pacing 0.5ms 1ms precision",
  },
  {
    anchor: "mmcss",
    label: "MMCSS Gaming Profile",
    keywords: "mmcss scheduling threads frame times gaming profile",
  },
  {
    anchor: "game_mode",
    label: "Windows Game Mode",
    keywords: "game mode windows gamemode resource",
  },
  {
    anchor: "disable_nagle",
    label: "Disable Nagle's Algorithm",
    keywords: "nagle algorithm latency ping packets tcp delay",
  },
  {
    anchor: "network_throttling",
    label: "Disable Network Throttling",
    keywords: "network throttling bandwidth multimedia",
  },
  {
    anchor: "gpu_binding",
    label: "High-Performance GPU Binding",
    keywords: "gpu binding high performance graphics card dedicated",
  },
  {
    anchor: "performance_cores",
    label: "Prefer Performance Cores",
    keywords: "performance cores p-cores hybrid cpu scheduling",
  },
  {
    anchor: "unbind_cpu0",
    label: "Unbind CPU0",
    keywords: "unbind cpu0 core 0 affinity",
  },
];

const BOOST: SearchEntry[] = BOOST_SETTINGS.map((s) => ({
  id: `boost-${s.anchor}`,
  tab: "games",
  game: "roblox",
  anchor: s.anchor,
  label: s.label,
  section: "Roblox · Optimize",
  icon: gamesIcon,
  keywords: s.keywords,
}));

// Extra plain-English aliases for Optimize cards whose shorthand isn't in the
// name/description. Everything else matches on name + description already.
const OPT_ALIASES: Record<string, string> = {
  game_bar_dvr_disable: "gamebar game bar dvr game dvr capture recording xbox",
  game_mode_enable: "gamemode game mode",
  mouse_acceleration_disable: "mouse accel acceleration aim raw input pointer",
  visual_effects_performance: "animations visual effects snappy",
  hags_enable: "hags hardware accelerated gpu scheduling",
  vbs_disable: "vbs memory integrity hvci virtualization security",
  cpu_mitigations_disable: "spectre meltdown mitigations cpu security",
  core_parking_disable: "core parking unpark cores",
  power_throttling_disable: "power throttling",
  sysmain_pause: "sysmain superfetch prefetch",
  smartscreen_disable: "smartscreen defender reputation",
  onedrive_disable: "onedrive sync cloud",
};

const OPTS: SearchEntry[] = OPTIMIZATIONS.map((def) => ({
  id: `opt-${def.id}`,
  tab: "optimization",
  anchor: def.id,
  label: def.name,
  section: "Optimize",
  icon: optimizeIcon,
  keywords: `${def.name} ${def.description} ${def.category} ${
    OPT_ALIASES[def.id] ?? ""
  }`,
}));

// Actions that aren't a plain page, dispatch an event or deep-link to a control.
const ACTIONS: SearchEntry[] = [
  {
    id: "action-language",
    tab: "settings",
    event: "toggle-language-menu",
    label: "Language",
    section: "Translate the whole app",
    icon: settingsIcon,
    keywords:
      "language translate translation translator localize localization change language app language idioma langue sprache lingua 语言 traducir traduire español french spanish arabic vietnamese portuguese russian japanese",
  },
  {
    id: "action-updates",
    tab: "settings",
    anchor: "updates",
    label: "Check for updates",
    section: "Settings · Updates",
    icon: settingsIcon,
    keywords:
      "update updates check for updates new version upgrade changelog release channel stable live latest version download install patch auto update",
  },
  {
    id: "action-account",
    tab: "settings",
    label: "Account",
    section: "Settings",
    icon: settingsIcon,
    keywords:
      "account profile login log out logout sign out sign in email user subscription license activate reset password",
  },
  {
    id: "action-support",
    tab: "repair",
    label: "Contact support",
    section: "Repair · Support",
    icon: repairIcon,
    keywords:
      "support help discord contact support community server ticket report bug stuck issue problem chat",
  },
];

// ── In-Game overlay controls ──
const OVERLAY: SearchEntry[] = (
  [
    {
      anchor: "overlay_enabled",
      label: "In-Game Overlay",
      keywords:
        "overlay hud in game enable turn on off stats bar show hide display",
    },
    {
      anchor: "overlay_enabled",
      label: "Overlay hotkey",
      keywords:
        "hotkey shortcut keybind key bind toggle overlay shift f1 press key",
    },
    {
      anchor: "overlay_metrics",
      label: "Overlay metrics",
      keywords:
        "metrics fps counter ping latency cpu gpu ram memory usage clock time netspeed download upload counters which stats",
    },
    {
      anchor: "overlay_style",
      label: "Overlay style and size",
      keywords:
        "style size display compact detailed minimal text size scale bigger smaller font layout",
    },
    {
      anchor: "overlay_style",
      label: "Overlay accent color",
      keywords: "accent color colour theme highlight overlay green white",
    },
    {
      anchor: "overlay_position",
      label: "Overlay position",
      keywords:
        "position place move drag corner top bottom left right center custom spot reset snap",
    },
    {
      anchor: "overlay_preview",
      label: "Overlay preview",
      keywords: "preview what it looks like sample example overlay look",
    },
    {
      anchor: "auto_ram_clean",
      label: "Auto-clean RAM on game launch",
      keywords:
        "ram clean memory free clear boost on launch automatic auto clean standby",
    },
    {
      anchor: "auto_ram_clean",
      label: "Monitor FPS and keep a session chart",
      keywords: "fps chart graph session history monitor record track",
    },
    {
      anchor: "auto_ram_clean",
      label: "Show max FPS after playing",
      keywords: "max fps peak highest notification after game session summary",
    },
  ] as const
).map((s, i) => ({
  id: `ov-${s.anchor}-${i}`,
  tab: "ingame" as const,
  anchor: s.anchor,
  label: s.label,
  section: "In-Game · Overlay",
  icon: ingameIcon,
  keywords: s.keywords,
}));

// ── Settings rows ──
const SETTINGS_ROWS: SearchEntry[] = (
  [
    {
      anchor: "run_on_startup",
      label: "Run on startup",
      keywords:
        "run on startup launch at boot windows sign in autostart auto start open on login",
    },
    {
      anchor: "minimize_to_tray",
      label: "Close to tray",
      keywords:
        "close to tray minimize tray background x button quit exit keep running system tray hide window",
    },
    {
      anchor: "auto_reconnect",
      label: "Auto-reconnect tunnel",
      keywords:
        "auto reconnect automatically reconnect tunnel after restart resume connection",
    },
    {
      anchor: "discord_rpc",
      label: "Discord Rich Presence",
      keywords:
        "discord rich presence rpc status profile show playing activity",
    },
    {
      anchor: "route_assist",
      label: "Route Assist",
      keywords:
        // "route assist" kept as an alias: it was the old name, and users who
        // learned it from Discord or older builds should still find the toggle.
        "route assist region placement server region join matchmaking gamejoin teleport singapore relay tunnel join traffic",
    },
    {
      anchor: "auto_update",
      label: "Auto update",
      keywords:
        "auto update automatic updates check on startup background update",
    },
    {
      anchor: "uninstall",
      label: "Uninstall SwiftTunnel",
      keywords:
        "uninstall remove delete app revert system changes clean removal get rid",
    },
  ] as const
).map((s) => ({
  id: `set-${s.anchor}`,
  tab: "settings" as const,
  anchor: s.anchor,
  label: s.label,
  section: "Settings",
  icon: settingsIcon,
  keywords: s.keywords,
}));

// ── Repair + Diagnostics ──
// The Repair entry carries the symptom vocabulary on purpose: users search what
// broke ("no wifi", "no internet"), not the name of the tool that fixes it.
const TOOLS: SearchEntry[] = [
  {
    id: "tool-repair-run",
    tab: "repair",
    anchor: "repair_run",
    label: "Run Repair",
    section: "Repair",
    icon: repairIcon,
    keywords:
      "repair fix reset one click no internet no wifi wifi not working internet not working cant connect broken adapter binding winsock dns flush driver stuck disconnected slow after uninstall network gone",
  },
  {
    id: "tool-driver-reinstall",
    tab: "repair",
    anchor: "driver_reinstall",
    label: "Reinstall network driver",
    section: "Repair · Advanced",
    icon: repairIcon,
    keywords:
      "reinstall driver network driver force reinstall ndis filter adapter driver corrupt repair driver",
  },
  {
    id: "test-stability",
    tab: "network",
    anchor: "test_stability",
    label: "Stability test",
    section: "Diagnostics",
    icon: networkIcon,
    keywords:
      "stability test ping jitter packet loss spikes lag test connection quality latency check",
  },
  {
    id: "test-speed",
    tab: "network",
    anchor: "test_speed",
    label: "Speed test",
    section: "Diagnostics",
    icon: networkIcon,
    keywords:
      "speed test download upload mbps bandwidth internet speed how fast",
  },
  {
    id: "test-bufferbloat",
    tab: "network",
    anchor: "test_bufferbloat",
    label: "Bufferbloat test",
    section: "Diagnostics",
    icon: networkIcon,
    keywords:
      "bufferbloat buffer bloat latency under load ping while downloading queue congestion",
  },
  {
    id: "action-region",
    tab: "connect",
    label: "Change region",
    section: "Connect",
    icon: connectIcon,
    keywords:
      "region server location change switch relay node singapore mumbai india japan tokyo germany europe us east america nearest ping",
  },
];

const SPEEDUP: SearchEntry[] = SPEEDUP_OPTIMIZATIONS.map((def) => ({
  id: `su-${def.id}`,
  tab: "optimization",
  anchor: def.id,
  label: def.name,
  section: `Speed Up · ${def.category}`,
  icon: optimizeIcon,
  keywords: `${def.name} ${def.description} ${def.category} speed up razer`,
}));

const ALL_ENTRIES: SearchEntry[] = [
  ...TABS,
  ...ACTIONS,
  ...TOOLS,
  ...OVERLAY,
  ...SETTINGS_ROWS,
  ...BOOST,
  ...OPTS,
  ...SPEEDUP,
];

/**
 * Everything this build can navigate to.
 *
 * Not filtered for Lite any more: Lite has no command palette, so this
 * whole module is dropped from that bundle rather than trimmed for it.
 */
export const SEARCH_ENTRIES: SearchEntry[] = ALL_ENTRIES;

/** Rank entries for a query. Empty query → the page list (tabs). */
export function searchEntries(query: string): SearchEntry[] {
  const q = query.trim().toLowerCase();
  if (!q) return TABS;

  const words = q.split(/\s+/).filter(Boolean);
  const scored: { entry: SearchEntry; score: number }[] = [];

  for (const entry of SEARCH_ENTRIES) {
    const label = entry.label.toLowerCase();
    const keywords = entry.keywords.toLowerCase();
    let score = 0;

    if (label === q) score = 100;
    else if (label.startsWith(q)) score = 82;
    else if (label.includes(q)) score = 64;
    else if (keywords.includes(q)) score = 46;
    else if (words.every((w) => label.includes(w) || keywords.includes(w))) {
      score = 28;
    }

    if (score > 0) scored.push({ entry, score });
  }

  scored.sort(
    (a, b) => b.score - a.score || a.entry.label.length - b.entry.label.length,
  );
  return scored.slice(0, 40).map((s) => s.entry);
}
