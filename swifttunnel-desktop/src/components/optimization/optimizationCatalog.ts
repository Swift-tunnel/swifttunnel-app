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
//   Expert       — system-wide changes for users who know the trade-off.
// `category` is shown as a small chip on each card.

export type OptSafety = "safe" | "low" | "caution";

export type OptCategory = "System" | "Performance" | "Input" | "Privacy";

export type OptTier = "Beginner" | "Intermediate" | "Expert" | "Advanced";

/** Render order + blurb for the grouped tier sections in the Optimization tab. */
export const TIER_ORDER: OptTier[] = [
  "Beginner",
  "Intermediate",
  "Expert",
  "Advanced",
];

export const TIER_DESCRIPTION: Record<OptTier, string> = {
  Beginner: "Safe, fully reversible tweaks anyone can use — small, reliable gains.",
  Intermediate:
    "Trade a little comfort or a feature you may not use for more performance.",
  Expert:
    "System-wide changes for users who know exactly what they're trading. All reversible.",
  Advanced:
    "Experimental and risky — these can unlock serious performance but lower security or break features. Only if you understand the trade-off. Still fully reversible.",
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
    id: "game_mode_enable",
    name: "Enable Windows Game Mode",
    description:
      "Tells Windows to prioritize the foreground game for CPU/GPU scheduling and hold back background work while you play.",
    tier: "Beginner",
    category: "Performance",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\Software\\Microsoft\\GameBar → AutoGameModeEnabled = 1",
      "HKCU\\Software\\Microsoft\\GameBar → AllowAutoGameMode = 1",
    ],
  },
  {
    id: "widgets_disable",
    name: "Disable Widgets / News & Interests",
    description:
      "Turns off the Windows 11 Widgets board (News & Interests), which runs a background process that uses real CPU, RAM, and network. Harmless on Windows 10.",
    tier: "Beginner",
    category: "Performance",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\...\\Dsh → AllowNewsAndInterests = 0",
      "HKCU\\...\\Explorer\\Advanced → TaskbarDa = 0 (hide the button)",
    ],
  },
  {
    id: "startup_delay_disable",
    name: "Remove Startup App Delay",
    description:
      "Removes the artificial delay Windows adds before launching your startup apps, so the desktop is usable sooner after boot.",
    tier: "Beginner",
    category: "System",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: ["HKCU\\...\\Explorer\\Serialize → StartupDelayInMSec = 0"],
  },
  {
    id: "action_center_disable",
    name: "Disable Action Center",
    description:
      "Hides the notification center panel and its taskbar icon, trimming a little background work. Notifications themselves are unaffected.",
    tier: "Beginner",
    category: "System",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer → DisableNotificationCenter = 1",
    ],
  },
  {
    id: "live_tiles_disable",
    name: "Disable Live Tiles",
    description:
      "Stops Start Menu Live Tiles from fetching and animating in the background (Windows 10). Harmless on Windows 11.",
    tier: "Beginner",
    category: "System",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: ["HKCU\\...\\PushNotifications → NoTileApplicationNotification = 1"],
  },
  {
    id: "fax_service_disable",
    name: "Disable Fax Service",
    description:
      "Stops and disables the Windows Fax service, which almost no one uses, freeing a background service. Re-enabled on revert.",
    tier: "Beginner",
    category: "System",
    safety: "low",
    requiresAdmin: true,
    requiresReboot: false,
    changes: ["Service Fax → stopped and set to Disabled (re-enabled on revert)"],
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
    id: "foreground_boost_priority",
    name: "Foreground App Priority Boost",
    description:
      "Tunes the Windows scheduler to favor the app you're focused on (your game) with shorter, foreground-boosted time slices. System-wide.",
    tier: "Intermediate",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\...\\PriorityControl → Win32PrioritySeparation = 38 (0x26, default 2)",
    ],
  },
  {
    id: "windowed_games_optimizations_enable",
    name: "Optimizations for Windowed Games",
    description:
      "Enables the Windows 11 low-latency present path for borderless/windowed games — lower input latency without true fullscreen.",
    tier: "Intermediate",
    category: "Performance",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      'HKCU\\...\\DirectX\\UserGpuPreferences → DirectXUserGlobalSettings = "SwapEffectUpgradeEnable=1;"',
    ],
  },
  {
    id: "windows_ads_suggestions_disable",
    name: "Disable Windows Ads & Suggestions",
    description:
      "Turns off Start Menu suggestions, lock-screen tips/ads, and silent app installs — Windows stops fetching that content in the background.",
    tier: "Intermediate",
    category: "Privacy",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\...\\ContentDeliveryManager → SystemPaneSuggestionsEnabled = 0",
      "HKCU\\...\\ContentDeliveryManager → SubscribedContent-338388/338389/310093Enabled = 0",
      "HKCU\\...\\ContentDeliveryManager → SilentInstalledAppsEnabled = 0",
    ],
  },
  {
    id: "search_web_suggestions_disable",
    name: "Disable Web Search in Start",
    description:
      "Makes Start search local-only — no Bing web results or highlights, so it stops hitting the network and returns your apps/files faster.",
    tier: "Intermediate",
    category: "System",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer → DisableSearchBoxSuggestions = 1",
      "HKCU\\...\\SearchSettings → IsDynamicSearchBoxEnabled = 0",
    ],
  },
  {
    id: "error_reporting_disable",
    name: "Disable Windows Error Reporting",
    description:
      "Stops and disables the Windows Error Reporting service so crash data isn't collected or uploaded in the background. Re-enabled on revert.",
    tier: "Intermediate",
    category: "System",
    safety: "low",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "Service WerSvc → stopped and set to Disabled (re-enabled on revert)",
    ],
  },
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
  {
    id: "sticky_keys_disable",
    name: "Disable Sticky Keys Popups",
    description:
      "Stops the Sticky/Toggle/Filter Keys prompts from hijacking your game when you tap Shift five times.",
    tier: "Beginner",
    category: "Input",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: [
      "HKCU\\Control Panel\\Accessibility\\StickyKeys → Flags = 506",
      "HKCU\\Control Panel\\Accessibility\\ToggleKeys → Flags = 58",
      "HKCU\\Control Panel\\Accessibility\\Keyboard Response → Flags = 122",
    ],
  },
  {
    id: "explorer_compact_mode",
    name: "Explorer Compact Mode",
    description:
      "Reduces the space between files and folders in File Explorer so you see more at once (Windows 11).",
    tier: "Beginner",
    category: "System",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: false,
    changes: ["HKCU\\...\\Explorer\\Advanced → UseCompactMode = 1"],
  },
  {
    id: "shortcut_suffix_disable",
    name: 'Disable "- Shortcut" Suffix',
    description:
      "New shortcuts stop getting the '- Shortcut' text appended, keeping names clean. Applies after sign-out.",
    tier: "Beginner",
    category: "System",
    safety: "safe",
    requiresAdmin: false,
    requiresReboot: true,
    changes: ["HKCU\\...\\Explorer → link = 00 00 00 00 (binary)"],
  },
  {
    id: "classic_context_menu_enable",
    name: "Classic Right-Click Menu (Win 11)",
    description:
      "Brings back the full Windows 10 right-click menu without the extra 'Show more options' step. Applies after restart.",
    tier: "Intermediate",
    category: "System",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: true,
    changes: [
      "HKCU\\Software\\Classes\\CLSID\\{86ca1aa0-...}\\InprocServer32 → (default) = \"\" (key removed on revert)",
    ],
  },
  {
    id: "storage_sense_disable",
    name: "Disable Storage Sense",
    description:
      "Turns off Windows' automatic background disk cleanup so it never kicks in mid-game. Manual cleanup still works.",
    tier: "Intermediate",
    category: "System",
    safety: "low",
    requiresAdmin: false,
    requiresReboot: false,
    changes: ["HKCU\\...\\StorageSense\\Parameters\\StoragePolicy → 01 = 0"],
  },

  // ── Expert ───────────────────────────────────────────────────────────────
  {
    id: "vbs_disable",
    name: "Disable VBS / Memory Integrity",
    description:
      "Turns off Virtualization-Based Security and HVCI (Memory Integrity), which run the OS under a hypervisor and can cost 5–15% FPS in games. Lowers security; reverts on toggle off.",
    tier: "Expert",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: true,
    changes: [
      "HKLM\\...\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity → Enabled = 0",
      "HKLM\\...\\DeviceGuard → EnableVirtualizationBasedSecurity = 0",
    ],
  },
  {
    id: "onedrive_disable",
    name: "Disable OneDrive Sync",
    description:
      "Disables OneDrive file sync via policy so it can't churn disk/network/CPU in the background while you game. Re-enabled on revert.",
    tier: "Expert",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive → DisableFileSyncNGSC = 1",
    ],
  },
  {
    id: "windows_auto_updates_disable",
    name: "Disable Automatic Windows Updates",
    description:
      "Stops Windows downloading/installing updates automatically so they never interrupt a game or reboot you mid-session. You can still update manually. Re-enabled on revert.",
    tier: "Expert",
    category: "System",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU → NoAutoUpdate = 1",
    ],
  },
  {
    id: "browser_hardware_accel_disable",
    name: "Disable Browser GPU Acceleration",
    description:
      "Stops Chrome and Edge from using the GPU, freeing graphics power for your game when a browser is open alongside it. Reverts on toggle off.",
    tier: "Expert",
    category: "Performance",
    safety: "low",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\SOFTWARE\\Policies\\Google\\Chrome → HardwareAccelerationModeEnabled = 0",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge → HardwareAccelerationModeEnabled = 0",
    ],
  },
  {
    id: "notifications_disable",
    name: "Disable Notifications",
    description:
      "Turns off toast notifications system-wide for your user — no popups, sounds, or banners until reverted.",
    tier: "Expert",
    category: "System",
    safety: "caution",
    requiresAdmin: false,
    requiresReboot: false,
    changes: ["HKCU\\...\\PushNotifications → ToastEnabled = 0"],
  },
  {
    id: "lock_screen_disable",
    name: "Disable Lock Screen",
    description:
      "Skips the lock screen so boot and wake land straight on the sign-in prompt.",
    tier: "Expert",
    category: "System",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: ["HKLM\\...\\Policies\\...\\Personalization → NoLockScreen = 1"],
  },
  {
    id: "lock_screen_blur_disable",
    name: "Disable Sign-in Blur",
    description:
      "Removes the acrylic blur behind the sign-in screen — lighter on weak GPUs at logon.",
    tier: "Expert",
    category: "System",
    safety: "low",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\...\\Policies\\Microsoft\\Windows\\System → DisableAcrylicBackgroundOnLogon = 1",
    ],
  },

  // ── Advanced ─────────────────────────────────────────────────────────────
  {
    id: "cpu_mitigations_disable",
    name: "Disable CPU Security Mitigations",
    description:
      "Turns off Spectre/Meltdown and related CPU exploit mitigations, which cost real CPU performance. Significant security trade-off — reverts on toggle off.",
    tier: "Advanced",
    category: "Performance",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: true,
    changes: [
      "HKLM\\...\\Memory Management → FeatureSettingsOverride = 1",
      "HKLM\\...\\Memory Management → FeatureSettingsOverrideMask = 3",
    ],
  },
  {
    id: "smartscreen_disable",
    name: "Disable Windows SmartScreen",
    description:
      "Turns off the SmartScreen reputation check on app launches and downloads — no lookup overhead or prompts. Lowers protection; reverts on toggle off.",
    tier: "Advanced",
    category: "Privacy",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System → EnableSmartScreen = 0",
    ],
  },
  {
    id: "driver_updates_disable",
    name: "Disable Windows Driver Updates",
    description:
      "Stops Windows Update from installing or overwriting your device drivers, so it can't swap a good GPU/audio driver for a generic one. Re-enabled on revert.",
    tier: "Advanced",
    category: "System",
    safety: "caution",
    requiresAdmin: true,
    requiresReboot: false,
    changes: [
      "HKLM\\...\\WindowsUpdate → ExcludeWUDriversInQualityUpdate = 1",
      "HKLM\\...\\DriverSearching → SearchOrderConfig = 0",
    ],
  },
];
