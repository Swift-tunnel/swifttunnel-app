import { useEffect, useState, useCallback, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import { useToastStore } from "../../stores/toastStore";
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
} from "../ui";
import {
  PROFILES,
  configsEqual,
  getPresetConfig,
  nextPowerPlanForSwiftTunnelToggle,
  parseWindowDimensionInput,
  previousNonSwiftTunnelPowerPlan,
  rememberedPowerPlanForSwiftTunnel,
  robloxSettingsChanged,
  validateWindowDimension,
} from "./boostConfig";
import type {
  Config,
  GameProcessPerformanceSettings,
  NetworkConfig,
  OptimizationProfile,
  PowerPlan,
  RobloxSettingsConfig,
  SystemOptimizationConfig,
} from "../../lib/types";

const MIN_WINDOW_WIDTH = 800;
const MAX_WINDOW_WIDTH = 3840;
const MIN_WINDOW_HEIGHT = 600;
const MAX_WINDOW_HEIGHT = 2160;

export function BoostTab() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);

  const boost = useBoostStore();
  const addToast = useToastStore((s) => s.addToast);

  const [networkApplying, setNetworkApplying] = useState(false);

  const savedConfig = settings.config;
  const [draft, setDraft] = useState<Config>(savedConfig);
  const [previousPowerPlan, setPreviousPowerPlan] = useState<PowerPlan>(() =>
    rememberedPowerPlanForSwiftTunnel(
      savedConfig.system_optimization.power_plan,
      savedConfig.system_optimization.previous_power_plan,
    ),
  );

  useEffect(() => {
    setDraft(savedConfig);
  }, [savedConfig]);

  useEffect(() => {
    const savedPowerPlan = savedConfig.system_optimization.power_plan;
    if (savedPowerPlan !== "SwiftTunnel") {
      setPreviousPowerPlan(savedPowerPlan);
    } else if (savedConfig.system_optimization.previous_power_plan) {
      setPreviousPowerPlan(
        previousNonSwiftTunnelPowerPlan(
          savedConfig.system_optimization.previous_power_plan,
        ),
      );
    }
  }, [
    savedConfig.system_optimization.power_plan,
    savedConfig.system_optimization.previous_power_plan,
  ]);

  const savedGPP = settings.game_process_performance;
  const [draftGPP, setDraftGPP] =
    useState<GameProcessPerformanceSettings>(savedGPP);
  const savedCountryBan = settings.enable_country_ban;
  const [draftCountryBan, setDraftCountryBan] = useState(savedCountryBan);

  useEffect(() => {
    setDraftGPP(savedGPP);
  }, [savedGPP]);

  useEffect(() => {
    setDraftCountryBan(savedCountryBan);
  }, [savedCountryBan]);

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
  const hasCountryBanChange = draftCountryBan !== savedCountryBan;
  const hasChanges = hasConfigChanges || hasGPPChanges || hasCountryBanChange;
  const hasRobloxChanges = robloxSettingsChanged(draft, savedConfig);
  const [isRestarting, setIsRestarting] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
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
    if (windowValidationError) return;
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
      });
      setDraft(appliedConfig);
      saveSettings();
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
    hasConfigChanges,
    saveSettings,
    updateSettings,
    boost,
    windowValidationError,
    addToast,
  ]);

  const restartAndApply = useCallback(async () => {
    if (windowValidationError) return;
    setIsRestarting(true);
    try {
      let appliedConfig = draft;
      if (hasConfigChanges) {
        appliedConfig = await boost.updateConfig(JSON.stringify(draft));
      }
      await boost.restartRoblox();
      updateSettings({
        config: appliedConfig,
        game_process_performance: draftGPP,
        enable_country_ban: draftCountryBan,
      });
      setDraft(appliedConfig);
      saveSettings();
    } finally {
      setIsRestarting(false);
    }
  }, [
    draft,
    draftGPP,
    draftCountryBan,
    hasConfigChanges,
    saveSettings,
    updateSettings,
    boost,
    windowValidationError,
  ]);

  const discardChanges = useCallback(() => {
    setDraft(savedConfig);
    setDraftGPP(savedGPP);
    setDraftCountryBan(savedCountryBan);
  }, [savedConfig, savedGPP, savedCountryBan]);

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

  function updateSwiftTunnelPowerPlan(enabled: boolean) {
    const currentPowerPlan = draft.system_optimization.power_plan;
    const rememberedPowerPlan = previousNonSwiftTunnelPowerPlan(
      enabled && currentPowerPlan !== "SwiftTunnel"
        ? currentPowerPlan
        : previousPowerPlan,
    );
    if (enabled && currentPowerPlan !== "SwiftTunnel") {
      setPreviousPowerPlan(rememberedPowerPlan);
    }
    const nextPowerPlan = nextPowerPlanForSwiftTunnelToggle(
      enabled,
      rememberedPowerPlan,
    );
    updateSysOpt({
      power_plan: nextPowerPlan,
      previous_power_plan: rememberedPowerPlan,
    });
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
    draft.system_optimization.power_plan === "SwiftTunnel",
  ];
  const sysCount = systemBoostFlags.filter(Boolean).length;
  const netCount = [
    draft.network_settings.disable_nagle,
    draft.network_settings.disable_network_throttling,
  ].filter(Boolean).length;
  const rblxCount = [
    draft.roblox_settings.unlock_fps,
    draft.roblox_settings.ultraboost,
    draftCountryBan,
    draft.roblox_settings.window_fullscreen,
  ].filter(Boolean).length;
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
        />
        {draft.roblox_settings.unlock_fps && (
          <FpsSlider
            value={draft.roblox_settings.target_fps}
            onChange={(v) => updateRblxOpt({ target_fps: v })}
          />
        )}
        <SettingRow
          title="Ultraboost"
          desc="Curated FPS-focused Roblox FFlags"
          enabled={draft.roblox_settings.ultraboost}
          onChange={(v) => updateRblxOpt({ ultraboost: v })}
        />
        <SettingRow
          title="Bypass Country Bans"
          desc="Local DPI bypass for Roblox website/login and app"
          tooltip="Starts SwiftTunnel's scoped GoodbyeDPI helper for Roblox hostnames. It works without connecting the VPN and does not route traffic through relays."
          enabled={draftCountryBan}
          onChange={setDraftCountryBan}
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
        />
        <SettingRow
          title="Launch Fullscreen"
          desc="Set Roblox fullscreen default"
          enabled={draft.roblox_settings.window_fullscreen}
          onChange={(v) => updateRblxOpt({ window_fullscreen: v })}
        />
      </Section>

      {/* ── System + Network side-by-side ── */}
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
          <SettingRow
            title="SwiftTunnel Power Plan"
            desc="Custom low-latency Windows power profile"
            tooltip="Imports and activates SwiftTunnel's optimized power plan while boosts are enabled. Your previous power plan is restored when boosts are disabled."
            enabled={draft.system_optimization.power_plan === "SwiftTunnel"}
            onChange={updateSwiftTunnelPowerPlan}
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
                {windowValidationError
                  ? windowValidationError
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
                    disabled={isRestarting || Boolean(windowValidationError)}
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
                      isRestarting || isApplying || Boolean(windowValidationError)
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

function FpsSlider({
  value,
  onChange,
}: {
  value: number;
  onChange: (v: number) => void;
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
}: {
  width: number;
  height: number;
  onWidthChange: (v: number) => void;
  onHeightChange: (v: number) => void;
  error: string | null;
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
