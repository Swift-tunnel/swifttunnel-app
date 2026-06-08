// Catalog of system optimizations surfaced in the Optimization tab.
//
// UI-first: these definitions drive the cards today and become the contract the
// backend implements later. Each `id` will map 1:1 to a future
// `optimization_apply` / `optimization_revert` Tauri command. The `changes`
// strings are the human-readable "what changed" detail shown in each card's
// dropdown; keep them faithful to the real registry/service edits so users can
// trust them.

export type OptSafety = "safe" | "low" | "caution";

export type OptCategory = "System" | "Performance" | "Input" | "Privacy";

/** Render order for the grouped sections in the Optimization tab. */
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
  category: OptCategory;
  /** Kept as data for the future backend; no longer shown as a UI tag. */
  safety: OptSafety;
  requiresAdmin: boolean;
  requiresReboot: boolean;
  /** Exact, reversible changes this optimization makes. */
  changes: string[];
}

export const OPTIMIZATIONS: OptimizationDef[] = [
  // ── Tier 1: safe, per-user (no UAC) ──────────────────────────────────────
  {
    id: "mouse_acceleration_disable",
    name: "Disable Mouse Acceleration",
    description:
      "Restores 1:1 linear mouse movement by turning off Enhance Pointer Precision.",
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
    category: "System",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\...\\Themes\\Personalize → EnableTransparency = 0",
    ],
  },
  {
    id: "background_apps_disable",
    name: "Disable Background Apps",
    description:
      "Stops Microsoft Store apps from running in the background to free CPU and RAM.",
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
    id: "game_bar_dvr_disable",
    name: "Disable Game Bar / DVR Capture",
    description:
      "Disables Windows Game DVR background capture, which can cost 2–5% FPS. Does not uninstall Game Bar.",
    category: "System",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\...\\GameDVR → AppCaptureEnabled = 0",
      "HKCU\\System\\GameConfigStore → GameDVR_Enabled = 0",
      "HKCU\\Software\\Microsoft\\GameBar → ShowStartupPanel = 0",
    ],
  },

  // ── Tier 2: higher value, needs admin ────────────────────────────────────
  {
    id: "power_throttling_disable",
    name: "Disable Power Throttling",
    description:
      "Prevents Windows from throttling background-capable workloads while gaming.",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\...\\Power\\PowerThrottling → PowerThrottlingOff = 1",
    ],
  },
  {
    id: "core_parking_disable",
    name: "Disable Core Parking (on AC)",
    description:
      "Keeps all CPU cores unparked while plugged in, avoiding wake-up stutter.",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "Active power plan → SUB_PROCESSOR / CPMINCORES (AC) = 100%",
    ],
  },
  {
    id: "sysmain_pause",
    name: "Pause SysMain (Superfetch)",
    description:
      "Stops and disables SysMain until reverted. Useful when prefetching causes disk spikes.",
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
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: true,
    changes: [
      "HKLM\\...\\GraphicsDrivers → HwSchMode = 2",
    ],
  },
  {
    id: "telemetry_tasks_disable",
    name: "Reduce Windows Telemetry",
    description:
      "Sets the Windows diagnostic data level to the minimum via Group Policy.",
    category: "Privacy",
    safety: "low",
    requiresAdmin: true,
    requiresReboot: false,
    changes: ["HKLM\\...\\DataCollection → AllowTelemetry = 0"],
  },
];

