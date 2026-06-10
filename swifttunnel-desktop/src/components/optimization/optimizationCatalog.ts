// Catalog of system optimizations surfaced in the Optimization tab.
//
// Each `id` maps 1:1 to a backend tweak in `swifttunnel-core/src/optimizations.rs`
// (`optimization_apply` / `optimization_revert`). The `changes` strings are the
// human-readable "what changed" detail shown in each card's dropdown; keep them
// faithful to the real registry/service edits so users can trust them.
//
// Tweaks are grouped by TIER (difficulty/trade-off), Hone-style:
//   Beginner     — safe, reversible, no real downside.
//   Intermediate — trade a little comfort/feature for more performance.
// `category` is shown as a small chip on each row.

export type OptSafety = "safe" | "low" | "caution";

export type OptCategory = "System" | "Performance" | "Input" | "Privacy";

export type OptTier = "Beginner" | "Intermediate";

/** Render order + blurb for the grouped tier sections in the Optimization tab. */
export const TIER_ORDER: OptTier[] = ["Beginner", "Intermediate"];

export const TIER_DESCRIPTION: Record<OptTier, string> = {
  Beginner: "Safe, fully reversible tweaks anyone can use — small, reliable gains.",
  Intermediate:
    "Trade a little comfort or a feature you may not use for more performance.",
};

/** Kept for any external references; tab now groups by tier. */
export const CATEGORY_ORDER: OptCategory[] = [
  "System",
  "Performance",
  "Input",
  "Privacy",
];

export interface OptimizationDef {
  id: string;
  name: string;
  description: string;
  tier: OptTier;
  category: OptCategory;
  /** Kept as data for the backend; surfaced as a small chip. */
  safety: OptSafety;
  requiresAdmin: boolean;
  requiresReboot: boolean;
  /** Exact, reversible changes this optimization makes. */
  changes: string[];
}

export const OPTIMIZATIONS: OptimizationDef[] = [
  // ── Beginner ─────────────────────────────────────────────────────────────
  {
    id: "mouse_acceleration_disable",
    name: "Disable Mouse Acceleration",
    description:
      "Restores 1:1 linear mouse movement by turning off Enhance Pointer Precision.",
    tier: "Beginner",
    category: "Input",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\Control Panel\\Mouse → MouseSpeed = 0",
      "HKCU\\Control Panel\\Mouse → MouseThreshold1 = 0",
      "HKCU\\Control Panel\\Mouse → MouseThreshold2 = 0",
    ],
  },
  {
    id: "visual_effects_performance",
    name: "Visual Effects: Best Performance",
    description:
      "Sets Windows visual effects to Best Performance, disabling animations for a snappier desktop.",
    tier: "Beginner",
    category: "System",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\...\\Explorer\\VisualEffects → VisualFXSetting = 2 (Best Performance)",
    ],
  },
  {
    id: "transparency_disable",
    name: "Disable Transparency Effects",
    description:
      "Turns off desktop transparency to reduce composition overhead.",
    tier: "Beginner",
    category: "System",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: ["HKCU\\...\\Themes\\Personalize → EnableTransparency = 0"],
  },
  {
    id: "background_apps_disable",
    name: "Disable Background Apps",
    description:
      "Stops Microsoft Store apps from running in the background to free CPU and RAM.",
    tier: "Beginner",
    category: "System",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\...\\BackgroundAccessApplications → GlobalUserDisabled = 1",
      "HKCU\\...\\BackgroundAccessApplications → BackgroundAppGlobalToggle = 0",
    ],
  },
  {
    id: "menu_show_delay_fast",
    name: "Snappier Menus (0ms delay)",
    description:
      "Removes the 400ms submenu open delay so menus appear instantly.",
    tier: "Beginner",
    category: "System",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: ["HKCU\\Control Panel\\Desktop → MenuShowDelay = 0 (default 400)"],
  },
  {
    id: "telemetry_tasks_disable",
    name: "Reduce Windows Telemetry",
    description:
      "Sets the Windows diagnostic data level to the minimum via Group Policy.",
    tier: "Beginner",
    category: "Privacy",
    safety: "low",
    requiresAdmin: true,
    requiresReboot: false,
    changes: ["HKLM\\...\\DataCollection → AllowTelemetry = 0"],
  },
  {
    id: "diagtrack_disable",
    name: "Disable Telemetry Service",
    description:
      "Stops the Connected User Experiences and Telemetry (DiagTrack) service to cut background data collection.",
    tier: "Beginner",
    category: "Privacy",
    safety: "low",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "Service DiagTrack → stopped and set to Disabled (re-enabled on revert)",
    ],
  },

  // ── Intermediate ─────────────────────────────────────────────────────────
  {
    id: "game_bar_dvr_disable",
    name: "Disable Game Bar / DVR Capture",
    description:
      "Disables Windows Game DVR background capture, which can cost 2–5% FPS. Does not uninstall Game Bar.",
    tier: "Intermediate",
    category: "Performance",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\...\\GameDVR → AppCaptureEnabled = 0",
      "HKCU\\...\\GameDVR → AudioCaptureEnabled = 0",
      "HKCU\\System\\GameConfigStore → GameDVR_Enabled = 0",
      "HKCU\\Software\\Microsoft\\GameBar → ShowStartupPanel = 0",
    ],
  },
  {
    id: "power_throttling_disable",
    name: "Disable Power Throttling",
    description:
      "Prevents Windows from throttling background-capable workloads while gaming.",
    tier: "Intermediate",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: ["HKLM\\...\\Power\\PowerThrottling → PowerThrottlingOff = 1"],
  },
  {
    id: "core_parking_disable",
    name: "Disable Core Parking (on AC)",
    description:
      "Keeps all CPU cores unparked while plugged in, avoiding wake-up stutter.",
    tier: "Intermediate",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: ["Active power plan → SUB_PROCESSOR / CPMINCORES (AC) = 100%"],
  },
  {
    id: "sysmain_pause",
    name: "Pause SysMain (Superfetch)",
    description:
      "Stops and disables SysMain until reverted. Useful when prefetching causes disk spikes.",
    tier: "Intermediate",
    category: "System",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "Service SysMain → stopped and set to Disabled (re-enabled on revert)",
    ],
  },
  {
    id: "hags_enable",
    name: "Hardware-Accelerated GPU Scheduling",
    description:
      "Offloads GPU scheduling to the graphics card. Can reduce latency; may regress on older GPUs.",
    tier: "Intermediate",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: true,
    changes: ["HKLM\\...\\GraphicsDrivers → HwSchMode = 2"],
  },
  {
    id: "xbox_services_disable",
    name: "Disable Xbox Services",
    description:
      "Frees the four Xbox background services. Turn off if you use Game Pass or the Xbox app.",
    tier: "Intermediate",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "Service XblAuthManager → Disabled (restored on revert)",
      "Service XblGameSave → Disabled (restored on revert)",
      "Service XboxGipSvc → Disabled (restored on revert)",
      "Service XboxNetApiSvc → Disabled (restored on revert)",
    ],
  },
];
