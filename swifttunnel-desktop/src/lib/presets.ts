// Shareable SwiftTunnel presets.
//
// A preset captures *everything the user configured except tunneling*, Roblox
// settings, the overlay, network/system optimization toggles, the applied
// optimization catalog items and selected game presets, as a compact,
// copy-pasteable code. Tunneling (region, relay, adapter, auto-routing) lives on
// `AppSettings`, never inside `Config`, so it is naturally excluded.
//
// The wire format is plain, readable JSON (a legacy `SWT1.` base64 token is still
// accepted on import). Imports are strictly re-validated field-by-field so a
// pasted config can only ever contain known settings clamped to safe ranges.

import type { AppSettings, Config, OverlayMetric } from "./types";
import { DEFAULT_SETTINGS } from "./settings";

export const PRESET_PREFIX = "SWT1.";
export const PRESET_VERSION = 1;

/**
 * The machine-portable slice of system_optimization. We deliberately drop
 * `cpu_cores`, `set_cpu_affinity` and `previous_power_plan`, those are specific
 * to the sender's hardware / revert-state and must never overwrite the importer.
 */
export type PortableSystem = Pick<
  Config["system_optimization"],
  | "set_high_priority"
  | "disable_fullscreen_optimization"
  | "clear_standby_memory"
  | "disable_game_bar"
  | "power_plan"
  | "timer_resolution_1ms"
  | "mmcss_gaming_profile"
  | "game_mode_enabled"
  | "auto_ram_clean"
>;

export interface PresetConfig {
  roblox_settings: Config["roblox_settings"];
  overlay: Config["overlay"];
  network_settings: Config["network_settings"];
  system_optimization: PortableSystem;
  profile: Config["profile"];
  auto_start_with_roblox: boolean;
  show_overlay: boolean;
}

export interface SwiftTunnelPreset {
  v: number;
  name: string;
  created: string;
  config: PresetConfig;
  /** Applied optimization catalog ids (Game Boost + Speed Up). */
  optimizations: string[];
  /** Selected game presets (game selection, not tunneling). */
  game_presets: string[];
}

function portableSystem(so: Config["system_optimization"]): PortableSystem {
  return {
    set_high_priority: so.set_high_priority,
    disable_fullscreen_optimization: so.disable_fullscreen_optimization,
    clear_standby_memory: so.clear_standby_memory,
    disable_game_bar: so.disable_game_bar,
    power_plan: so.power_plan,
    timer_resolution_1ms: so.timer_resolution_1ms,
    mmcss_gaming_profile: so.mmcss_gaming_profile,
    game_mode_enabled: so.game_mode_enabled,
    auto_ram_clean: so.auto_ram_clean,
  };
}

/** Snapshot the current config (minus tunneling) into a shareable preset. */
export function buildPreset(
  name: string,
  settings: AppSettings,
  activeOptimizationIds: string[],
): SwiftTunnelPreset {
  const c = settings.config;
  return {
    v: PRESET_VERSION,
    name: name.trim() || "SwiftTunnel Preset",
    created: new Date().toISOString(),
    config: {
      roblox_settings: c.roblox_settings,
      overlay: c.overlay,
      network_settings: c.network_settings,
      system_optimization: portableSystem(c.system_optimization),
      profile: c.profile,
      auto_start_with_roblox: c.auto_start_with_roblox,
      show_overlay: c.show_overlay,
    },
    optimizations: [...new Set(activeOptimizationIds)].sort(),
    game_presets: [...settings.selected_game_presets],
  };
}

// ── UTF-8 safe base64 (works in the webview and in jsdom/node tests) ──

function fromBase64(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/**
 * A preset is shared as plain, readable JSON, anyone can see it's just their
 * settings, never a token or account data. The legacy `SWT1.<base64>` token is
 * still accepted on import for anything shared before this change.
 */
export function encodePreset(preset: SwiftTunnelPreset): string {
  return JSON.stringify(preset, null, 2);
}

// ── Import guardrails ─────────────────────────────────────────────────────────
// Everything below re-validates untrusted, pasted input. The only path into the
// app is `sanitizePreset`, which rebuilds a preset from scratch: it copies *only*
// known keys, coerces each to the right type, clamps numbers, checks enums, and
// drops anything unexpected. A hostile or random paste therefore can't inject
// unknown fields, out-of-range values, or anything beyond plain settings.

const GRAPHICS_QUALITIES = [
  "Automatic", "Manual", "Level1", "Level2", "Level3", "Level4",
  "Level5", "Level6", "Level7", "Level8", "Level9", "Level10",
] as const;
const POWER_PLANS = ["Balanced", "HighPerformance", "Ultimate", "SwiftTunnel"] as const;
const PROFILES = ["LowEnd", "Balanced", "HighEnd", "Custom"] as const;
const OVERLAY_SIZES = ["small", "medium", "large"] as const;
const OVERLAY_STYLES = ["straight", "layered"] as const;
const OVERLAY_POSITIONS = [
  "top-left", "top-center", "top-right",
  "center-left", "center", "center-right",
  "bottom-left", "bottom-center", "bottom-right",
] as const;
const OVERLAY_METRICS = [
  "fps", "time", "playtime", "ping", "battery", "upload", "download",
  "cpu", "cpu_temp", "gpu", "gpu_temp", "ram", "disk",
] as const;

function asBool(v: unknown, fb: boolean): boolean {
  return typeof v === "boolean" ? v : fb;
}
function asNum(v: unknown, min: number, max: number, fb: number): number {
  return typeof v === "number" && Number.isFinite(v)
    ? Math.min(max, Math.max(min, Math.round(v)))
    : fb;
}
function asEnum<T extends string>(v: unknown, allowed: readonly T[], fb: T): T {
  return typeof v === "string" && (allowed as readonly string[]).includes(v)
    ? (v as T)
    : fb;
}
function asStr(v: unknown, maxLen: number, fb: string): string {
  return typeof v === "string" ? v.slice(0, maxLen) : fb;
}
function asStrArray(v: unknown, cap: number): string[] {
  if (!Array.isArray(v)) return [];
  return [
    ...new Set(v.filter((x): x is string => typeof x === "string")),
  ].slice(0, cap);
}

function obj(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function sanitizePreset(parsed: unknown): SwiftTunnelPreset {
  const p = obj(parsed);
  if (!p || typeof p.v !== "number") {
    throw new Error("This doesn't look like a SwiftTunnel config.");
  }
  if (p.v > PRESET_VERSION) {
    throw new Error("This config was made in a newer version of SwiftTunnel.");
  }

  const c = obj(p.config);
  const r = obj(c?.roblox_settings);
  const o = obj(c?.overlay);
  const n = obj(c?.network_settings);
  const so = obj(c?.system_optimization);
  if (!c || !r || !o || !n || !so || !Array.isArray(p.optimizations)) {
    throw new Error(
      "This config is missing required data or isn't a SwiftTunnel config.",
    );
  }

  const D = DEFAULT_SETTINGS.config;

  // Never write un-parseable FastFlags text to Roblox, disable it if invalid.
  let customEnabled = asBool(
    r.custom_fflags_enabled,
    D.roblox_settings.custom_fflags_enabled,
  );
  const customJson = asStr(
    r.custom_fflags_json,
    20000,
    D.roblox_settings.custom_fflags_json,
  );
  if (customEnabled) {
    try {
      const j = JSON.parse(customJson) as unknown;
      if (!j || typeof j !== "object") throw new Error("not an object");
    } catch {
      customEnabled = false;
    }
  }

  const metrics: OverlayMetric[] = Array.isArray(o.metrics)
    ? [
        ...new Set(
          o.metrics.filter(
            (m): m is OverlayMetric =>
              typeof m === "string" &&
              (OVERLAY_METRICS as readonly string[]).includes(m),
          ),
        ),
      ]
    : [...D.overlay.metrics];

  const color =
    typeof o.color === "string" && /^#[0-9a-fA-F]{3,8}$/.test(o.color)
      ? o.color
      : D.overlay.color;

  return {
    v: PRESET_VERSION,
    name: asStr(p.name, 60, "").trim() || "Imported preset",
    created:
      typeof p.created === "string"
        ? p.created.slice(0, 40)
        : new Date().toISOString(),
    config: {
      roblox_settings: {
        graphics_quality: asEnum(
          r.graphics_quality,
          GRAPHICS_QUALITIES,
          D.roblox_settings.graphics_quality,
        ),
        unlock_fps: asBool(r.unlock_fps, D.roblox_settings.unlock_fps),
        target_fps: asNum(r.target_fps, 1, 99999, D.roblox_settings.target_fps),
        window_width: asNum(
          r.window_width,
          100,
          15360,
          D.roblox_settings.window_width,
        ),
        window_height: asNum(
          r.window_height,
          100,
          8640,
          D.roblox_settings.window_height,
        ),
        window_fullscreen: asBool(
          r.window_fullscreen,
          D.roblox_settings.window_fullscreen,
        ),
        ultraboost: asBool(r.ultraboost, D.roblox_settings.ultraboost),
        custom_fflags_enabled: customEnabled,
        custom_fflags_json: customJson,
      },
      overlay: {
        enabled: asBool(o.enabled, D.overlay.enabled),
        metrics,
        size: asEnum(o.size, OVERLAY_SIZES, D.overlay.size),
        style: asEnum(o.style, OVERLAY_STYLES, D.overlay.style),
        color,
        position: asEnum(o.position, OVERLAY_POSITIONS, D.overlay.position),
        custom_x:
          typeof o.custom_x === "number" && Number.isFinite(o.custom_x)
            ? asNum(o.custom_x, -20000, 20000, 0)
            : null,
        custom_y:
          typeof o.custom_y === "number" && Number.isFinite(o.custom_y)
            ? asNum(o.custom_y, -20000, 20000, 0)
            : null,
        hotkey: asStr(o.hotkey, 40, D.overlay.hotkey),
        monitor_fps_chart: asBool(
          o.monitor_fps_chart,
          D.overlay.monitor_fps_chart,
        ),
        show_max_fps_message: asBool(
          o.show_max_fps_message,
          D.overlay.show_max_fps_message,
        ),
      },
      network_settings: {
        enable_network_boost: asBool(
          n.enable_network_boost,
          D.network_settings.enable_network_boost,
        ),
        disable_nagle: asBool(
          n.disable_nagle,
          D.network_settings.disable_nagle,
        ),
        disable_network_throttling: asBool(
          n.disable_network_throttling,
          D.network_settings.disable_network_throttling,
        ),
        firewall_fix: asBool(n.firewall_fix, D.network_settings.firewall_fix),
      },
      system_optimization: {
        set_high_priority: asBool(
          so.set_high_priority,
          D.system_optimization.set_high_priority,
        ),
        disable_fullscreen_optimization: asBool(
          so.disable_fullscreen_optimization,
          D.system_optimization.disable_fullscreen_optimization,
        ),
        clear_standby_memory: asBool(
          so.clear_standby_memory,
          D.system_optimization.clear_standby_memory,
        ),
        disable_game_bar: asBool(
          so.disable_game_bar,
          D.system_optimization.disable_game_bar,
        ),
        power_plan: asEnum(
          so.power_plan,
          POWER_PLANS,
          D.system_optimization.power_plan,
        ),
        timer_resolution_1ms: asBool(
          so.timer_resolution_1ms,
          D.system_optimization.timer_resolution_1ms,
        ),
        mmcss_gaming_profile: asBool(
          so.mmcss_gaming_profile,
          D.system_optimization.mmcss_gaming_profile,
        ),
        game_mode_enabled: asBool(
          so.game_mode_enabled,
          D.system_optimization.game_mode_enabled,
        ),
        auto_ram_clean: asBool(
          so.auto_ram_clean,
          D.system_optimization.auto_ram_clean,
        ),
      },
      profile: asEnum(c.profile, PROFILES, D.profile),
      auto_start_with_roblox: asBool(
        c.auto_start_with_roblox,
        D.auto_start_with_roblox,
      ),
      show_overlay: asBool(c.show_overlay, D.show_overlay),
    },
    optimizations: asStrArray(p.optimizations, 200),
    game_presets: asStrArray(p.game_presets, 100),
  };
}

/**
 * Parse a shared config. Prefers readable JSON (tolerant of any header text
 * wrapped around it) and falls back to the legacy `SWT1.<base64>` token.
 * Throws a user-facing message on anything malformed.
 */
export function decodePreset(code: string): SwiftTunnelPreset {
  const trimmed = (code ?? "").trim();
  if (!trimmed) throw new Error("Paste a config first.");

  let json: string | null = null;
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start !== -1 && end > start) {
    json = trimmed.slice(start, end + 1);
  } else {
    const match = trimmed.match(/SWT1\.[A-Za-z0-9+/=]+/);
    const body = match ? match[0].slice(PRESET_PREFIX.length) : trimmed;
    try {
      json = fromBase64(body.replace(/\s+/g, ""));
    } catch {
      json = null;
    }
  }
  if (json === null) {
    throw new Error("This doesn't look like a SwiftTunnel config.");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("This config is corrupted and couldn't be read.");
  }

  return sanitizePreset(parsed);
}

/**
 * Merge a preset's config over the importer's current config. Machine-specific
 * fields absent from the preset (cpu cores, affinity, previous power plan) are
 * preserved from `current`, and object spreads keep any fields newer builds add.
 */
export function mergePresetIntoConfig(
  current: Config,
  preset: SwiftTunnelPreset,
): Config {
  return {
    ...current,
    profile: preset.config.profile,
    roblox_settings: {
      ...current.roblox_settings,
      ...preset.config.roblox_settings,
    },
    overlay: { ...current.overlay, ...preset.config.overlay },
    network_settings: {
      ...current.network_settings,
      ...preset.config.network_settings,
    },
    auto_start_with_roblox: preset.config.auto_start_with_roblox,
    show_overlay: preset.config.show_overlay,
    system_optimization: {
      ...current.system_optimization,
      ...preset.config.system_optimization,
    },
  };
}

/** Filename-safe slug for a downloaded preset .txt. */
export function presetFileName(name: string): string {
  const slug =
    name
      .trim()
      .replace(/[^a-z0-9]+/gi, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 48) || "preset";
  return `SwiftTunnel-Preset-${slug}.txt`;
}

/** Human-shareable .txt body: a friendly header + the readable config. */
export function presetFileContents(preset: SwiftTunnelPreset): string {
  return [
    `SwiftTunnel config, "${preset.name}"`,
    `Created ${preset.created}`,
    "It only contains game/optimization settings, no account, login or region data.",
    "Import it in SwiftTunnel → Home → Import config (paste this whole file).",
    "",
    encodePreset(preset),
    "",
  ].join("\n");
}
