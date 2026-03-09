import type {
  Config,
  OptimizationProfile,
  StandbyPurgeResult,
} from "../../lib/types";

export const PROFILES: {
  id: OptimizationProfile;
  name: string;
  desc: string;
  icon: string;
}[] = [
  {
    id: "LowEnd",
    name: "Performance",
    desc: "Max FPS, lowest quality",
    icon: "\u26A1",
  },
  {
    id: "Balanced",
    name: "Balanced",
    desc: "Good FPS, decent visuals",
    icon: "\u2696\uFE0F",
  },
  {
    id: "HighEnd",
    name: "Quality",
    desc: "Best visuals, stable perf",
    icon: "\u2728",
  },
];

export function getPresetConfig(
  profile: OptimizationProfile,
  current: Config,
): Config {
  const base: Config = {
    ...current,
    profile,
  };
  switch (profile) {
    case "LowEnd":
      return {
        ...base,
        system_optimization: {
          ...current.system_optimization,
          set_high_priority: true,
          timer_resolution_1ms: true,
          mmcss_gaming_profile: true,
          game_mode_enabled: true,
          clear_standby_memory: true,
          disable_game_bar: true,
          disable_fullscreen_optimization: true,
          power_plan: "Ultimate",
        },
        roblox_settings: {
          ...current.roblox_settings,
          graphics_quality: "Level1",
          unlock_fps: true,
          target_fps: 360,
          ultraboost: true,
        },
        network_settings: {
          ...current.network_settings,
          disable_nagle: true,
          disable_network_throttling: true,
          gaming_qos: true,
        },
      };
    case "Balanced":
      return {
        ...base,
        system_optimization: {
          ...current.system_optimization,
          set_high_priority: true,
          timer_resolution_1ms: true,
          mmcss_gaming_profile: true,
          game_mode_enabled: true,
          clear_standby_memory: true,
          disable_game_bar: true,
          disable_fullscreen_optimization: true,
          power_plan: "HighPerformance",
        },
        roblox_settings: {
          ...current.roblox_settings,
          graphics_quality: "Manual",
          unlock_fps: true,
          target_fps: 144,
          ultraboost: false,
        },
        network_settings: {
          ...current.network_settings,
          disable_nagle: true,
          disable_network_throttling: true,
          gaming_qos: true,
        },
      };
    case "HighEnd":
      return {
        ...base,
        system_optimization: {
          ...current.system_optimization,
          set_high_priority: true,
          timer_resolution_1ms: true,
          mmcss_gaming_profile: true,
          game_mode_enabled: true,
          clear_standby_memory: false,
          disable_game_bar: false,
          disable_fullscreen_optimization: true,
          power_plan: "HighPerformance",
        },
        roblox_settings: {
          ...current.roblox_settings,
          graphics_quality: "Level8",
          unlock_fps: true,
          target_fps: 60,
          ultraboost: false,
        },
        network_settings: {
          ...current.network_settings,
          disable_nagle: true,
          disable_network_throttling: true,
          gaming_qos: true,
        },
      };
    default:
      return base;
  }
}

export function configsEqual(a: Config, b: Config): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function robloxSettingsChanged(a: Config, b: Config): boolean {
  return JSON.stringify(a.roblox_settings) !== JSON.stringify(b.roblox_settings);
}

export function validateWindowDimension(
  label: "Width" | "Height",
  value: number,
  min: number,
  max: number,
): string | null {
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    return `${label} must be a whole number.`;
  }
  if (value < min || value > max) {
    return `${label} must be between ${min} and ${max}.`;
  }
  if (value % 2 !== 0) {
    return `${label} must be an even number.`;
  }
  return null;
}

export function parseWindowDimensionInput(
  value: string,
  fallback: number,
): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function countActive(...flags: boolean[]): number {
  return flags.filter(Boolean).length;
}

export function formatGbFromMb(mb: number): string {
  if (!Number.isFinite(mb) || mb <= 0) return "0.0";
  return (mb / 1024).toFixed(1);
}

export function formatDeltaMb(delta: number): string {
  if (!Number.isFinite(delta)) return "0 MB";
  const sign = delta >= 0 ? "+" : "-";
  return `${sign}${Math.abs(Math.round(delta))} MB`;
}

export function deepCleanLabel(standby: StandbyPurgeResult): string {
  if (standby.success) return "Success";
  const reason = standby.skipped_reason ? ` (${standby.skipped_reason})` : "";
  if (!standby.attempted) return `Skipped${reason}`;
  return `Failed${reason}`;
}

export function memColor(percent: number): string {
  if (percent > 85) return "#f05a5a";
  if (percent > 65) return "#f5b428";
  return "#28d296";
}
