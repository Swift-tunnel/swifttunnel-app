import { useEffect, useState, useCallback, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import { useToastStore } from "../../stores/toastStore";
import { boostCloseRoblox, boostGetMetrics } from "../../lib/commands";
import { normalizeNetworkBoostConfig } from "../../lib/settings";
import {
  Toggle,
  SectionHeader,
  Tooltip,
  InfoIcon,
  Button,
  Row,
  Slider,
  ErrorBanner,
  Dialog,
} from "../ui";
import {
  PROFILES,
  configsEqual,
  getPresetConfig,
  parseWindowDimensionInput,
  robloxSettingsChanged,
  validateWindowDimension,
} from "./boostConfig";
import type {
  Config,
  GameProcessPerformanceSettings,
  NetworkConfig,
  OptimizationProfile,
  RobloxSettingsConfig,
  SystemOptimizationConfig,
} from "../../lib/types";

const MIN_WINDOW_WIDTH = 800;
const MAX_WINDOW_WIDTH = 3840;
const MIN_WINDOW_HEIGHT = 600;
const MAX_WINDOW_HEIGHT = 2160;
const CUSTOM_FFLAG_ALLOWLIST: Record<string, string> = {
  FFlagHandleAltEnterFullscreenManually: "False",
  FFlagDebugGraphicsPreferD3D11: "True",
  FFlagDebugGraphicsPreferVulkan: "False",
  FFlagDebugGraphicsPreferOpenGL: "False",
  FIntDebugForceMSAASamples: "1",
  DFFlagTextureQualityOverrideEnabled: "True",
  DFIntTextureQualityOverride: "0",
  DFFlagDisableDPIScale: "False",
  DFIntDebugFRMQualityLevelOverride: "1",
  FFlagDebugSkyGray: "True",
  FIntFRMMinGrassDistance: "0",
  FIntFRMMaxGrassDistance: "0",
  FIntGrassMovementReducedMotionFactor: "0",
  DFFlagDebugPauseVoxelizer: "True",
  DFIntCSGLevelOfDetailSwitchingDistance: "0",
  DFIntCSGLevelOfDetailSwitchingDistanceL12: "0",
  DFIntCSGLevelOfDetailSwitchingDistanceL23: "0",
  DFIntCSGLevelOfDetailSwitchingDistanceL34: "0",
};

function customFflagExpectsBoolean(key: string, defaultValue: string) {
  return (
    defaultValue.toLowerCase() === "true" ||
    defaultValue.toLowerCase() === "false" ||
    key.startsWith("FFlag") ||
    key.startsWith("DFFlag")
  );
}

function validateCustomFflags(enabled: boolean, raw: string): string | null {
  if (!enabled) return null;
  if (raw.trim().length === 0) {
    return "Paste a JSON object before applying custom FFlags.";
  }
  if (raw.length > 8192) return "Custom FFlags must be under 8 KB.";

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return "Custom FFlags must be valid JSON.";
  }

  if (
    parsed === null ||
    Array.isArray(parsed) ||
    typeof parsed !== "object"
  ) {
    return "Custom FFlags must be a JSON object.";
  }

  const entries = Object.entries(parsed);
  if (entries.length === 0) {
    return "Custom FFlags must include at least one allowlisted key.";
  }

  for (const [key, value] of entries) {
    const defaultValue = CUSTOM_FFLAG_ALLOWLIST[key];
    if (defaultValue === undefined) {
      return `${key} is not in Roblox's FFlag allowlist.`;
    }

    if (customFflagExpectsBoolean(key, defaultValue)) {
      if (typeof value === "boolean") continue;
      if (
        typeof value === "string" &&
        ["true", "false"].includes(value.trim().toLowerCase())
      ) {
        continue;
      }
      return `${key} must be true or false.`;
    }

    const integer =
      typeof value === "number"
        ? value
        : typeof value === "string" && value.trim() !== ""
          ? Number(value.trim())
          : Number.NaN;
    if (!Number.isInteger(integer)) {
      return `${key} must be an integer.`;
    }
    if (integer < -1_000_000 || integer > 1_000_000) {
      return `${key} is outside the allowed integer range.`;
    }
  }

  return null;
}

export function BoostTab() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);

  const boost = useBoostStore();
  const addToast = useToastStore((s) => s.addToast);

  const [networkApplying, setNetworkApplying] = useState(false);

  const savedConfig = settings.config;
  const [draft, setDraft] = useState<Config>(savedConfig);

  useEffect(() => {
    setDraft(savedConfig);
  }, [savedConfig]);

  const savedGPP = settings.game_process_performance;
  const [draftGPP, setDraftGPP] =
    useState<GameProcessPerformanceSettings>(savedGPP);
  const savedCountryBan = settings.enable_country_ban;
  const [draftCountryBan, setDraftCountryBan] = useState(savedCountryBan);
  const savedPartialBan = settings.enable_partial_country_ban;
  const [draftPartialBan, setDraftPartialBan] = useState(savedPartialBan);
  const savedRouteAssist = settings.enable_api_tunneling;
  const [fullBanDialogOpen, setFullBanDialogOpen] = useState(false);
  const [fullBanChecking, setFullBanChecking] = useState(false);
  const [fullBanClosing, setFullBanClosing] = useState(false);

  useEffect(() => {
    setDraftGPP(savedGPP);
  }, [savedGPP]);

  useEffect(() => {
    setDraftCountryBan(savedCountryBan);
  }, [savedCountryBan]);

  useEffect(() => {
    setDraftPartialBan(savedPartialBan);
  }, [savedPartialBan]);

  // The two bypass modes route gameplay UDP opposite ways - only one at a time.
  const chooseFullBan = (v: boolean) => {
    if (robloxControlsLocked) return;
    setDraftCountryBan(v);
    if (v) setDraftPartialBan(false);
  };
  const enableFullBanDraft = useCallback(() => {
    setDraftCountryBan(true);
    setDraftPartialBan(false);
  }, []);
  const requestFullBan = useCallback(
    async (v: boolean) => {
      if (!v) {
        chooseFullBan(false);
        return;
      }

      setFullBanChecking(true);
      try {
        const metrics = await boostGetMetrics();
        if (metrics.roblox_running) {
          setFullBanDialogOpen(true);
          return;
        }
        enableFullBanDraft();
      } catch {
        addToast({
          type: "warning",
          message: "Close Roblox before enabling Full Country Ban",
        });
        setFullBanDialogOpen(true);
      } finally {
        setFullBanChecking(false);
      }
    },
    [addToast, enableFullBanDraft],
  );
  const confirmRobloxClosedForFullBan = useCallback(async () => {
    setFullBanChecking(true);
    try {
      const metrics = await boostGetMetrics();
      if (metrics.roblox_running) {
        addToast({ type: "warning", message: "Roblox is still running" });
        return;
      }
      enableFullBanDraft();
      setFullBanDialogOpen(false);
    } catch {
      addToast({
        type: "warning",
        message: "Could not verify Roblox is closed",
      });
    } finally {
      setFullBanChecking(false);
    }
  }, [addToast, enableFullBanDraft]);
  const closeRobloxAndEnableFullBan = useCallback(async () => {
    setFullBanClosing(true);
    try {
      await boostCloseRoblox();
      await boost.fetchMetrics();
      enableFullBanDraft();
      setFullBanDialogOpen(false);
      addToast({
        type: "success",
        message: "Roblox closed. Apply Full Country Ban to save it.",
      });
    } catch {
      addToast({ type: "error", message: "Could not close Roblox" });
    } finally {
      setFullBanClosing(false);
    }
  }, [addToast, boost, enableFullBanDraft]);
  const choosePartialBan = (v: boolean) => {
    if (robloxControlsLocked) return;
    setDraftPartialBan(v);
    if (v) setDraftCountryBan(false);
  };

  useEffect(() => {
    let canceled = false;
    void boost.syncEffectiveConfig().then((appliedConfig) => {
      if (canceled || !appliedConfig) return;
      if (
        !configsEqual(
          appliedConfig,
          useSettingsStore.getState().settings.config,
        )
      ) {
        updateSettings({ config: appliedConfig });
        void useSettingsStore.getState().save();
      }
      setDraft(appliedConfig);
    });
    return () => {
      canceled = true;
    };
  }, [boost.syncEffectiveConfig, updateSettings]);

  const hasConfigChanges = !configsEqual(draft, savedConfig);
  const hasGPPChanges = JSON.stringify(draftGPP) !== JSON.stringify(savedGPP);
  const partialBypassWillDisableRouteAssist =
    draftPartialBan && savedRouteAssist;
  const hasCountryBanChange =
    draftCountryBan !== savedCountryBan ||
    draftPartialBan !== savedPartialBan ||
    partialBypassWillDisableRouteAssist;
  const hasChanges = hasConfigChanges || hasGPPChanges || hasCountryBanChange;
  const hasRobloxChanges = robloxSettingsChanged(draft, savedConfig);
  const [isRestarting, setIsRestarting] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const robloxControlsLocked =
    isRestarting || isApplying || fullBanChecking || fullBanClosing;
  const windowWidthError = validateWindowDimension(
    "Width",
    draft.roblox_settings.window_width,
    MIN_WINDOW_WIDTH,
    MAX_WINDOW_WIDTH,
  );
  const windowHeightError = validateWindowDimension(
    "Height",
    draft.roblox_settings.window_height,
    MIN_WINDOW_HEIGHT,
    MAX_WINDOW_HEIGHT,
  );
  const windowValidationError = windowWidthError ?? windowHeightError;
  const customFflagError = validateCustomFflags(
    draft.roblox_settings.custom_fflags_enabled,
    draft.roblox_settings.custom_fflags_json,
  );
  const fflagModeError =
    draft.roblox_settings.ultraboost &&
    draft.roblox_settings.custom_fflags_enabled
      ? "Choose either Ultraboost or Custom FFlag Import, not both."
      : null;
  const validationError =
    windowValidationError ?? fflagModeError ?? customFflagError;

  useEffect(() => {
    const id = setInterval(boost.fetchMetrics, 2000);
    return () => clearInterval(id);
  }, [boost.fetchMetrics]);

  useEffect(() => {
    void boost.fetchSystemMemory();
  }, [boost.fetchSystemMemory]);

  useEffect(() => {
    const intervalMs = boost.isCleaningRam ? 250 : 1000;
    const id = setInterval(() => {
      void boost.fetchSystemMemory();
    }, intervalMs);
    return () => clearInterval(id);
  }, [boost.fetchSystemMemory, boost.isCleaningRam]);

  const applyChanges = useCallback(async () => {
    if (validationError || isApplying || isRestarting) return;
    setIsApplying(true);
    try {
      let appliedConfig = draft;
      if (hasConfigChanges) {
        appliedConfig = await boost.updateConfig(JSON.stringify(draft));
      }
      updateSettings({
        config: appliedConfig,
        game_process_performance: draftGPP,
        enable_country_ban: draftCountryBan,
        enable_partial_country_ban: draftPartialBan,
        enable_api_tunneling: draftPartialBan ? false : savedRouteAssist,
      });
      setDraft(appliedConfig);
      await saveSettings();
      const currentWarning = useBoostStore.getState().warning;
      if (currentWarning) {
        addToast({ type: "warning", message: "Boost applied with warnings" });
      } else {
        addToast({ type: "success", message: "Boost settings applied" });
      }
    } finally {
      setIsApplying(false);
    }
  }, [
    draft,
    draftGPP,
    draftCountryBan,
    draftPartialBan,
    savedRouteAssist,
    hasConfigChanges,
    saveSettings,
    updateSettings,
    boost,
    validationError,
    isApplying,
    isRestarting,
    addToast,
  ]);

  const restartAndApply = useCallback(async () => {
    if (validationError || isRestarting || isApplying) return;
    setIsRestarting(true);
    try {
      let appliedConfig = draft;
      if (hasConfigChanges) {
        appliedConfig = await boost.updateConfig(JSON.stringify(draft));
      }
      updateSettings({
        config: appliedConfig,
        game_process_performance: draftGPP,
        enable_country_ban: draftCountryBan,
        enable_partial_country_ban: draftPartialBan,
        enable_api_tunneling: draftPartialBan ? false : savedRouteAssist,
      });
      setDraft(appliedConfig);
      await saveSettings();
      await boost.restartRoblox();
    } finally {
      setIsRestarting(false);
    }
  }, [
    draft,
    draftGPP,
    draftCountryBan,
    draftPartialBan,
    savedRouteAssist,
    hasConfigChanges,
    saveSettings,
    updateSettings,
    boost,
    validationError,
    isRestarting,
    isApplying,
  ]);

  const discardChanges = useCallback(() => {
    setDraft(savedConfig);
    setDraftGPP(savedGPP);
    setDraftCountryBan(savedCountryBan);
    setDraftPartialBan(savedPartialBan);
  }, [savedConfig, savedGPP, savedCountryBan, savedPartialBan]);

  function selectProfile(id: OptimizationProfile) {
    setDraft(getPresetConfig(id, draft));
  }

  function updateSysOpt(p: Partial<SystemOptimizationConfig>) {
    setDraft((prev) => ({
      ...prev,
      profile: "Custom",
      system_optimization: { ...prev.system_optimization, ...p },
    }));
  }

  const applyNetworkOpt = useCallback(
    async (p: Partial<NetworkConfig>) => {
      const nextDraft = {
        ...draft,
        profile: "Custom" as const,
        network_settings: normalizeNetworkBoostConfig({
          ...draft.network_settings,
          ...p,
        }),
      };
      setNetworkApplying(true);
      try {
        const appliedConfig = await boost.updateConfig(
          JSON.stringify(nextDraft),
        );
        updateSettings({
          config: appliedConfig,
          game_process_performance: draftGPP,
        });
        setDraft(appliedConfig);
        saveSettings();

        const currentWarning = useBoostStore.getState().warning;
        if (currentWarning) {
          addToast({
            type: "warning",
            message: "Network boost could not fully apply",
          });
        } else {
          addToast({ type: "success", message: "Network boost updated" });
        }
      } finally {
        setNetworkApplying(false);
      }
    },
    [addToast, boost, draft, draftGPP, saveSettings, updateSettings],
  );

  function updateRblxOpt(p: Partial<RobloxSettingsConfig>) {
    if (robloxControlsLocked) return;
    setDraft((prev) => ({
      ...prev,
      profile: "Custom",
      roblox_settings: { ...prev.roblox_settings, ...p },
    }));
  }

  function updateGPP(p: Partial<GameProcessPerformanceSettings>) {
    setDraftGPP((prev) => ({ ...prev, ...p }));
  }

  const systemBoostFlags = [
    draft.system_optimization.set_high_priority,
    draft.system_optimization.timer_resolution_1ms,
    draft.system_optimization.mmcss_gaming_profile,
    draft.system_optimization.game_mode_enabled,
  ];
  const sysCount = systemBoostFlags.filter(Boolean).length;
  const netCount = [
    draft.network_settings.disable_nagle,
    draft.network_settings.disable_network_throttling,
  ].filter(Boolean).length;
  const rblxCount = [
    draft.roblox_settings.unlock_fps,
    draft.roblox_settings.ultraboost,
    draft.roblox_settings.custom_fflags_enabled,
    draft.roblox_settings.window_fullscreen,
  ].filter(Boolean).length;
  const countryBanCount = [draftCountryBan, draftPartialBan].filter(
    Boolean,
  ).length;
  const schedCount = [
    draftGPP.high_performance_gpu_binding,
    draftGPP.prefer_performance_cores,
    draftGPP.unbind_cpu0,
  ].filter(Boolean).length;

  return (
    <div className="flex w-full flex-col gap-4 pb-24">
      {boost.error && <ErrorBanner tone="error">{boost.error}</ErrorBanner>}

      {boost.warning && (
        <ErrorBanner tone="warning">{boost.warning}</ErrorBanner>
      )}

      {/* ── Profile Selector ── */}
      <section>
        <SectionHeader
          label="Profile"
          description="Choose a preset or customize individual settings below"
          tag={draft.profile === "Custom" ? "Custom" : undefined}
        />
        <div
          className="grid gap-1 rounded-[var(--radius-card)] surface-card p-1"
          style={{
            gridTemplateColumns: `repeat(${PROFILES.length}, minmax(0, 1fr))`,
          }}
        >
          {PROFILES.map((p) => {
            const sel = draft.profile === p.id;
            return (
              <button
                key={p.id}
                onClick={() => selectProfile(p.id)}
                className="rounded-[7px] px-3 py-2 text-left transition-all duration-100"
                style={{
                  background: sel
                    ? "linear-gradient(180deg, #ffffff 0%, #ececec 100%)"
                    : "transparent",
                  color: sel ? "#0a0a0a" : "var(--color-text-secondary)",
                  boxShadow: sel
                    ? "inset 0 1px 0 rgba(255,255,255,0.9), 0 1px 2px rgba(0,0,0,0.4)"
                    : "none",
                }}
                onMouseEnter={(e) => {
                  if (!sel)
                    e.currentTarget.style.backgroundColor =
                      "var(--color-bg-hover)";
                }}
                onMouseLeave={(e) => {
                  if (!sel)
                    e.currentTarget.style.backgroundColor = "transparent";
                }}
              >
                <div
                  className="text-[12.5px] font-semibold"
                  style={{ letterSpacing: "-0.005em" }}
                >
                  {p.name}
                </div>
                <div
                  className="mt-0.5 text-[10.5px] leading-tight"
                  style={{
                    color: sel ? "rgba(0,0,0,0.65)" : "var(--color-text-muted)",
                  }}
                >
                  {p.desc}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* ── Roblox ── */}
      <Section title="Roblox" tag={`${rblxCount} / 4 on`}>
        <SettingRow
          title="Unlock FPS"
          desc="Remove 60 FPS cap"
          enabled={draft.roblox_settings.unlock_fps}
          onChange={(v) => updateRblxOpt({ unlock_fps: v })}
          disabled={robloxControlsLocked}
        />
        {draft.roblox_settings.unlock_fps && (
          <FpsSlider
            value={draft.roblox_settings.target_fps}
            onChange={(v) => updateRblxOpt({ target_fps: v })}
            disabled={robloxControlsLocked}
          />
        )}
        <SettingRow
          title="Ultraboost"
          desc="Curated FPS-focused Roblox FFlags"
          enabled={draft.roblox_settings.ultraboost}
          onChange={(v) =>
            updateRblxOpt(
              v
                ? { ultraboost: true, custom_fflags_enabled: false }
                : { ultraboost: false },
            )
          }
          disabled={robloxControlsLocked}
        />
        <CustomFflagsRow
          enabled={draft.roblox_settings.custom_fflags_enabled}
          json={draft.roblox_settings.custom_fflags_json}
          error={customFflagError}
          disabled={robloxControlsLocked}
          onEnabledChange={(v) =>
            updateRblxOpt(
              v
                ? { custom_fflags_enabled: true, ultraboost: false }
                : { custom_fflags_enabled: false },
            )
          }
          onJsonChange={(v) => updateRblxOpt({ custom_fflags_json: v })}
        />
        <ResolutionRow
          width={draft.roblox_settings.window_width}
          height={draft.roblox_settings.window_height}
          onWidthChange={(w) =>
            updateRblxOpt({
              window_width: parseWindowDimensionInput(
                String(w),
                MIN_WINDOW_WIDTH,
              ),
            })
          }
          onHeightChange={(h) =>
            updateRblxOpt({
              window_height: parseWindowDimensionInput(
                String(h),
                MIN_WINDOW_HEIGHT,
              ),
            })
          }
          error={windowValidationError}
          disabled={robloxControlsLocked}
        />
        <SettingRow
          title="Launch Fullscreen"
          desc="Set Roblox fullscreen default"
          enabled={draft.roblox_settings.window_fullscreen}
          onChange={(v) => updateRblxOpt({ window_fullscreen: v })}
          disabled={robloxControlsLocked}
        />
      </Section>

      {/* ── System + Network side-by-side ── */}
      <Section title="Country Ban" tag={`${countryBanCount} / 2 on`}>
        <SettingRow
          title="Bypass Country Ban"
          desc="Use when the whole Roblox platform is blocked"
          tooltip="Full bypass: DPI evasion plus relaying all Roblox traffic through the selected SwiftTunnel relay. Turns off Partial Ban."
          enabled={draftCountryBan}
          onChange={(v) => void requestFullBan(v)}
          disabled={robloxControlsLocked}
        />
        <SettingRow
          title="Bypass Partial Ban"
          desc="Use when only specific Roblox games are blocked"
          tooltip="Relays the Roblox discovery and join path while gameplay stays direct. Turns off Country Ban."
          enabled={draftPartialBan}
          onChange={choosePartialBan}
          disabled={robloxControlsLocked}
        />
      </Section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section
          title="System"
          tag={`${sysCount} / ${systemBoostFlags.length} on`}
        >
          <SettingRow
            title="High Priority Mode"
            desc="Boost game process priority (+5-15 FPS)"
            enabled={draft.system_optimization.set_high_priority}
            onChange={(v) => updateSysOpt({ set_high_priority: v })}
          />
          <SettingRow
            title="0.5ms Timer Resolution"
            desc="Max precision frame pacing"
            tooltip="Reduces the Windows timer interrupt interval to 0.5ms for more precise frame pacing. Slightly increases CPU usage."
            enabled={draft.system_optimization.timer_resolution_1ms}
            onChange={(v) => updateSysOpt({ timer_resolution_1ms: v })}
          />
          <SettingRow
            title="MMCSS Gaming Profile"
            desc="Better thread scheduling, stable frame times"
            tooltip="Multimedia Class Scheduler Service — prioritizes game threads for CPU time."
            enabled={draft.system_optimization.mmcss_gaming_profile}
            onChange={(v) => updateSysOpt({ mmcss_gaming_profile: v })}
          />
          <SettingRow
            title="Windows Game Mode"
            desc="System resource prioritization"
            enabled={draft.system_optimization.game_mode_enabled}
            onChange={(v) => updateSysOpt({ game_mode_enabled: v })}
          />
        </Section>

        <Section title="Network" tag={`${netCount} / 2 on`}>
          <SettingRow
            title="Disable Nagle's Algorithm"
            desc="Faster packet delivery (-5-15ms)"
            tooltip="Nagle batches small packets to reduce overhead. Disabling sends immediately — better for real-time games."
            enabled={draft.network_settings.disable_nagle}
            onChange={(v) => void applyNetworkOpt({ disable_nagle: v })}
            disabled={networkApplying}
          />
          <SettingRow
            title="Disable Network Throttling"
            desc="Full bandwidth while gaming"
            tooltip="Windows throttles network I/O when multimedia is playing. Disabling prevents sudden bandwidth drops."
            enabled={draft.network_settings.disable_network_throttling}
            onChange={(v) =>
              void applyNetworkOpt({ disable_network_throttling: v })
            }
            disabled={networkApplying}
          />
        </Section>
      </div>

      {/* ── Process Scheduling ── */}
      <Section title="Process Scheduling" tag={`${schedCount} / 3 on`}>
        <SettingRow
          title="High-Performance GPU Binding"
          desc="Bind target games to the high-performance GPU while connected"
          enabled={draftGPP.high_performance_gpu_binding}
          onChange={(v) => updateGPP({ high_performance_gpu_binding: v })}
        />
        <SettingRow
          title="Prefer Performance Cores"
          desc="Steer target games to P-cores on hybrid CPUs"
          enabled={draftGPP.prefer_performance_cores}
          onChange={(v) => updateGPP({ prefer_performance_cores: v })}
        />
        <SettingRow
          title="Unbind CPU0"
          desc="Exclude logical CPU 0 when enough cores are available"
          enabled={draftGPP.unbind_cpu0}
          onChange={(v) => updateGPP({ unbind_cpu0: v })}
        />
      </Section>

      {/* ── Sticky Apply Bar ── */}
      <AnimatePresence>
        {hasChanges && (
          <motion.div
            initial={{ opacity: 0, y: 28 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 28 }}
            transition={{ type: "spring", damping: 24, stiffness: 280 }}
            className="fixed z-40"
            style={{
              left: `calc(var(--spacing-sidebar) + var(--spacing-content))`,
              right: "var(--spacing-content)",
              bottom: "12px",
            }}
          >
            <div className="flex w-full items-center justify-between rounded-[var(--radius-card)] surface-elevated px-4 py-2.5">
              <span className="text-[12px] font-medium text-text-secondary">
                {validationError
                  ? validationError
                  : hasRobloxChanges && boost.robloxRunning
                    ? "Roblox must restart for changes to apply"
                    : "Unsaved changes"}
              </span>
              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={discardChanges}
                  disabled={isRestarting || isApplying}
                >
                  Discard
                </Button>
                {hasRobloxChanges && boost.robloxRunning ? (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => {
                      void restartAndApply().catch(() => {});
                    }}
                    disabled={isRestarting || Boolean(validationError)}
                    loading={isRestarting}
                  >
                    Restart & Apply
                  </Button>
                ) : (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={applyChanges}
                    disabled={
                      isRestarting || isApplying || Boolean(validationError)
                    }
                    loading={isApplying}
                  >
                    Apply
                  </Button>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      <Dialog
        open={fullBanDialogOpen}
        onClose={() => {
          if (!fullBanChecking && !fullBanClosing) setFullBanDialogOpen(false);
        }}
        title="Close Roblox first"
        description="Full Country Ban must start before Roblox opens."
      >
        <div className="flex flex-col gap-4">
          <p className="text-[12px] leading-relaxed text-text-secondary">
            Close Roblox completely, then enable Full Country Ban and click
            Apply. This keeps login, verification, and game traffic on the
            selected SwiftTunnel relay from the first connection.
          </p>
          <p className="text-[11px] leading-relaxed text-text-muted">
            If Roblox is stuck in the background, SwiftTunnel can close it for
            you.
          </p>
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setFullBanDialogOpen(false)}
              disabled={fullBanChecking || fullBanClosing}
            >
              Cancel
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void confirmRobloxClosedForFullBan()}
              disabled={fullBanChecking || fullBanClosing}
              loading={fullBanChecking}
            >
              I closed Roblox
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => void closeRobloxAndEnableFullBan()}
              disabled={fullBanChecking || fullBanClosing}
              loading={fullBanClosing}
            >
              Close Roblox & Enable
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}

// ── Sub-components ──

function Section({
  title,
  tag,
  children,
}: {
  title: string;
  tag?: string;
  children: ReactNode;
}) {
  return (
    <section>
      <SectionHeader label={title} tag={tag} />
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card divide-y divide-[color:var(--color-border-subtle)]">
        {children}
      </div>
    </section>
  );
}

function SettingRow({
  title,
  desc,
  tooltip,
  enabled,
  onChange,
  disabled,
}: {
  title: string;
  desc: string;
  tooltip?: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <Row
      label={title}
      desc={desc}
      tooltip={
        tooltip && (
          <Tooltip content={tooltip}>
            <span className="inline-flex">
              <InfoIcon />
            </span>
          </Tooltip>
        )
      }
    >
      <Toggle
        enabled={enabled}
        onChange={onChange}
        disabled={disabled}
        ariaLabel={title}
      />
    </Row>
  );
}

function CustomFflagsRow({
  enabled,
  json,
  error,
  disabled,
  onEnabledChange,
  onJsonChange,
}: {
  enabled: boolean;
  json: string;
  error: string | null;
  disabled?: boolean;
  onEnabledChange: (v: boolean) => void;
  onJsonChange: (v: string) => void;
}) {
  return (
    <div className="px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-medium text-text-primary">
              Custom FFlag Import
            </span>
            <span
              className="rounded-[3px] px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.1em]"
              style={{
                backgroundColor: "var(--color-bg-elevated)",
                color: "var(--color-text-muted)",
                border: "1px solid var(--color-border-subtle)",
              }}
            >
              JSON
            </span>
            <Tooltip content="Only Roblox's allowlisted FFlags are accepted. Unknown keys are rejected.">
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          </div>
          <p className="mt-0.5 text-[11px] text-text-muted">
            Import custom values for allowlisted Roblox client flags.
          </p>
        </div>
        <Toggle
          enabled={enabled}
          onChange={onEnabledChange}
          disabled={disabled}
          ariaLabel="Custom FFlag Import"
        />
      </div>
      {enabled && (
        <div className="mt-3 flex flex-col gap-2">
          <textarea
            value={json}
            onChange={(e) => onJsonChange(e.target.value)}
            disabled={disabled}
            spellCheck={false}
            placeholder={`{\n  "FFlagDebugSkyGray": true,\n  "DFIntTextureQualityOverride": 0\n}`}
            className="boost-input min-h-[118px] resize-y rounded-[4px] px-3 py-2 font-mono text-[11px] leading-relaxed outline-none transition-colors"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              border: `1px solid ${
                error
                  ? "var(--color-status-error-soft-40)"
                  : "var(--color-border-default)"
              }`,
              color: "var(--color-text-primary)",
            }}
          />
          <p
            className="text-[10.5px] leading-relaxed"
            style={{
              color: error
                ? "var(--color-status-error)"
                : "var(--color-text-muted)",
            }}
          >
            {error ??
              "Accepted keys are limited to Roblox's local client FFlag allowlist."}
          </p>
        </div>
      )}
    </div>
  );
}

function FpsSlider({
  value,
  onChange,
  disabled,
}: {
  value: number;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  // Slider range: 30–1010. The last notch (1010) is the "uncapped" position.
  const UNCAP_POS = 1010;
  const isUncapped = value >= 9999;
  const sliderValue = isUncapped
    ? UNCAP_POS
    : Math.max(30, Math.min(value, 1000));
  const [inputText, setInputText] = useState(isUncapped ? "" : String(value));
  const [inputFocused, setInputFocused] = useState(false);

  useEffect(() => {
    if (!inputFocused) {
      setInputText(isUncapped ? "" : String(value));
    }
  }, [value, isUncapped, inputFocused]);

  function commitInput(raw: string) {
    const v = Number.parseInt(raw, 10);
    if (!Number.isFinite(v) || v < 30) {
      setInputText(isUncapped ? "" : String(value));
      return;
    }
    onChange(Math.min(v, 99999));
  }

  function handleSlider(v: number) {
    if (v >= UNCAP_POS) onChange(99999);
    else onChange(Math.min(v, 1000));
  }

  return (
    <div className="px-4 py-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-baseline gap-2">
          <span className="text-[11px] text-text-muted">Target FPS</span>
          {isUncapped && (
            <span
              className="rounded-[3px] px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.1em]"
              style={{
                backgroundColor: "var(--color-accent-primary-soft-15)",
                color: "var(--color-accent-secondary)",
              }}
            >
              Uncapped
            </span>
          )}
        </div>
        <input
          type="number"
          min={30}
          max={99999}
          value={inputText}
          placeholder="MAX"
          disabled={disabled}
          onFocus={() => setInputFocused(true)}
          onChange={(e) => {
            setInputText(e.target.value);
            const v = Number.parseInt(e.target.value, 10);
            if (Number.isFinite(v) && v >= 30 && v <= 99999) onChange(v);
          }}
          onBlur={(e) => {
            setInputFocused(false);
            commitInput(e.target.value);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
          }}
          className="boost-input w-[78px] rounded-[4px] px-2 py-1 text-right font-mono text-[12px] font-semibold outline-none transition-colors"
          style={{
            backgroundColor: "var(--color-bg-elevated)",
            border: "1px solid var(--color-border-default)",
            color: isUncapped
              ? "var(--color-accent-secondary)"
              : "var(--color-text-primary)",
          }}
        />
      </div>
      <Slider
        ariaLabel="Target FPS slider"
        min={30}
        max={UNCAP_POS}
        step={10}
        value={sliderValue}
        onChange={handleSlider}
        disabled={disabled}
      />
      <div className="mt-1.5 flex justify-between font-mono text-[9.5px] text-text-dimmed">
        <span>30</span>
        <span>120</span>
        <span>240</span>
        <span>360</span>
        <span
          style={{
            color:
              !isUncapped && value >= 1000
                ? "var(--color-text-primary)"
                : undefined,
          }}
        >
          1000
        </span>
        <span
          style={{
            color: isUncapped ? "var(--color-accent-secondary)" : undefined,
            fontWeight: isUncapped ? 700 : undefined,
          }}
        >
          MAX
        </span>
      </div>
    </div>
  );
}

function ResolutionRow({
  width,
  height,
  onWidthChange,
  onHeightChange,
  error,
  disabled,
}: {
  width: number;
  height: number;
  onWidthChange: (v: number) => void;
  onHeightChange: (v: number) => void;
  error: string | null;
  disabled?: boolean;
}) {
  return (
    <div className="px-4 py-3">
      <div className="mb-0.5 text-[13px] font-medium text-text-primary">
        Window resolution
      </div>
      <div className="mb-2.5 text-[11px] text-text-muted">
        Sets Roblox launch window size in pixels.
      </div>
      <div className="flex items-center gap-2">
        <label className="flex flex-1 flex-col gap-1">
          <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
            Width
          </span>
          <input
            type="number"
            min={MIN_WINDOW_WIDTH}
            max={MAX_WINDOW_WIDTH}
            step={2}
            value={width}
            disabled={disabled}
            onChange={(e) =>
              onWidthChange(
                parseWindowDimensionInput(e.target.value, MIN_WINDOW_WIDTH),
              )
            }
            className="boost-input rounded-[4px] px-3 py-1.5 font-mono text-[13px] outline-none transition-colors"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              border: "1px solid var(--color-border-default)",
              color: "var(--color-text-primary)",
            }}
          />
        </label>
        <span className="mt-4 text-[11px] text-text-dimmed">×</span>
        <label className="flex flex-1 flex-col gap-1">
          <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
            Height
          </span>
          <input
            type="number"
            min={MIN_WINDOW_HEIGHT}
            max={MAX_WINDOW_HEIGHT}
            step={2}
            value={height}
            disabled={disabled}
            onChange={(e) =>
              onHeightChange(
                parseWindowDimensionInput(e.target.value, MIN_WINDOW_HEIGHT),
              )
            }
            className="boost-input rounded-[4px] px-3 py-1.5 font-mono text-[13px] outline-none transition-colors"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              border: "1px solid var(--color-border-default)",
              color: "var(--color-text-primary)",
            }}
          />
        </label>
      </div>
      {error && <p className="mt-2 text-[11px] text-status-error">{error}</p>}
    </div>
  );
}
