import { useEffect, useState, useCallback, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import { useToastStore } from "../../stores/toastStore";
import { systemRestartAsAdmin } from "../../lib/commands";
import { notify } from "../../lib/notifications";
import {
  Toggle,
  SectionHeader,
  Tooltip,
  InfoIcon,
  Button,
  Row,
  Chip,
  Spinner,
  Slider,
  ErrorBanner,
} from "../ui";
import {
  PROFILES,
  configsEqual,
  deepCleanLabel,
  formatDeltaMb,
  formatGbFromMb,
  getPresetConfig,
  memColor,
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
  SystemMemorySnapshot,
  RamCleanResultResponse,
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

  const [restartAdminState, setRestartAdminState] = useState<
    "idle" | "restarting" | "error"
  >("idle");
  const [restartAdminError, setRestartAdminError] = useState<string | null>(null);
  const [networkApplying, setNetworkApplying] = useState(false);

  const savedConfig = settings.config;
  const [draft, setDraft] = useState<Config>(savedConfig);

  useEffect(() => {
    setDraft(savedConfig);
  }, [savedConfig]);

  const savedGPP = settings.game_process_performance;
  const [draftGPP, setDraftGPP] = useState<GameProcessPerformanceSettings>(savedGPP);

  useEffect(() => {
    setDraftGPP(savedGPP);
  }, [savedGPP]);

  useEffect(() => {
    let canceled = false;
    void boost.syncEffectiveConfig().then((appliedConfig) => {
      if (canceled || !appliedConfig) return;
      if (!configsEqual(appliedConfig, useSettingsStore.getState().settings.config)) {
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
  const hasChanges = hasConfigChanges || hasGPPChanges;
  const hasRobloxChanges = robloxSettingsChanged(draft, savedConfig);
  const [isRestarting, setIsRestarting] = useState(false);
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
    let appliedConfig = draft;
    if (hasConfigChanges) {
      appliedConfig = await boost.updateConfig(JSON.stringify(draft));
    }
    updateSettings({
      config: appliedConfig,
      game_process_performance: draftGPP,
    });
    setDraft(appliedConfig);
    saveSettings();
    const currentWarning = useBoostStore.getState().warning;
    if (currentWarning) {
      addToast({ type: "warning", message: "Boost applied with warnings" });
    } else {
      addToast({ type: "success", message: "Boost settings applied" });
    }
  }, [
    draft,
    draftGPP,
    hasConfigChanges,
    saveSettings,
    updateSettings,
    boost,
    windowValidationError,
    addToast,
  ]);

  const restartAsAdmin = useCallback(async () => {
    try {
      setRestartAdminState("restarting");
      setRestartAdminError(null);
      await systemRestartAsAdmin();
    } catch (e) {
      setRestartAdminState("error");
      setRestartAdminError(String(e));
      await notify("Restart canceled", "Could not restart as Administrator.");
    }
  }, []);

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
      });
      setDraft(appliedConfig);
      saveSettings();
    } finally {
      setIsRestarting(false);
    }
  }, [
    draft,
    draftGPP,
    hasConfigChanges,
    saveSettings,
    updateSettings,
    boost,
    windowValidationError,
  ]);

  const discardChanges = useCallback(() => {
    setDraft(savedConfig);
    setDraftGPP(savedGPP);
  }, [savedConfig, savedGPP]);

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
        network_settings: { ...draft.network_settings, ...p },
      };
      setNetworkApplying(true);
      try {
        const appliedConfig = await boost.updateConfig(JSON.stringify(nextDraft));
        updateSettings({
          config: appliedConfig,
          game_process_performance: draftGPP,
        });
        setDraft(appliedConfig);
        saveSettings();

        const currentWarning = useBoostStore.getState().warning;
        if (currentWarning) {
          addToast({ type: "warning", message: "Network boost could not fully apply" });
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

  const sysCount = [
    draft.system_optimization.set_high_priority,
    draft.system_optimization.timer_resolution_1ms,
    draft.system_optimization.mmcss_gaming_profile,
    draft.system_optimization.game_mode_enabled,
  ].filter(Boolean).length;
  const netCount = [
    draft.network_settings.disable_nagle,
    draft.network_settings.disable_network_throttling,
    draft.network_settings.gaming_qos,
  ].filter(Boolean).length;
  const rblxCount = [
    draft.roblox_settings.unlock_fps,
    draft.roblox_settings.ultraboost,
    draft.roblox_settings.window_fullscreen,
  ].filter(Boolean).length;
  const schedCount = [
    draftGPP.high_performance_gpu_binding,
    draftGPP.prefer_performance_cores,
    draftGPP.unbind_cpu0,
  ].filter(Boolean).length;

  return (
    <div className="flex w-full flex-col gap-5 pb-24">
      {boost.error && (
        <ErrorBanner tone="error">{boost.error}</ErrorBanner>
      )}

      {boost.warning && (
        <ErrorBanner tone="warning">{boost.warning}</ErrorBanner>
      )}

      <RamCleanerCard
        systemMem={boost.systemMem}
        isCleaning={boost.isCleaningRam}
        stage={boost.ramCleanStage}
        trimmedCount={boost.ramCleanTrimmedCount}
        currentProcess={boost.ramCleanCurrentProcess}
        result={boost.ramCleanResult}
        isAdmin={boost.isAdmin}
        restartState={restartAdminState}
        restartError={restartAdminError}
        onRestartAsAdmin={() => void restartAsAdmin()}
        onClean={() => void boost.cleanRam()}
      />

      {/* ── Profile Selector ── */}
      <section>
        <SectionHeader
          label="Profile"
          description="Choose a preset or customize individual settings below"
          tag={draft.profile === "Custom" ? "Custom" : undefined}
        />
        <div
          className="grid gap-1 rounded-[var(--radius-card)] p-1"
          style={{
            gridTemplateColumns: `repeat(${PROFILES.length}, minmax(0, 1fr))`,
            backgroundColor: "var(--color-bg-card)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          {PROFILES.map((p) => {
            const sel = draft.profile === p.id;
            return (
              <button
                key={p.id}
                onClick={() => selectProfile(p.id)}
                className="rounded-[5px] px-3 py-2 text-left transition-colors"
                style={{
                  backgroundColor: sel
                    ? "var(--color-accent-primary)"
                    : "transparent",
                  color: sel ? "#000000" : "var(--color-text-secondary)",
                }}
              >
                <div className="text-[12.5px] font-semibold">{p.name}</div>
                <div
                  className="mt-0.5 text-[10.5px]"
                  style={{
                    color: sel ? "rgba(0,0,0,0.7)" : "var(--color-text-muted)",
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
      <Section
        title="Roblox"
        tag={`${rblxCount} / 3 on`}
      >
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
          desc="All allowlisted performance FFlags (+20-40% FPS)"
          enabled={draft.roblox_settings.ultraboost}
          onChange={(v) => updateRblxOpt({ ultraboost: v })}
        />
        <ResolutionRow
          width={draft.roblox_settings.window_width}
          height={draft.roblox_settings.window_height}
          onWidthChange={(w) =>
            updateRblxOpt({
              window_width: parseWindowDimensionInput(String(w), MIN_WINDOW_WIDTH),
            })
          }
          onHeightChange={(h) =>
            updateRblxOpt({
              window_height: parseWindowDimensionInput(String(h), MIN_WINDOW_HEIGHT),
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
        <Section title="System" tag={`${sysCount} / 4 on`}>
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

        <Section title="Network" tag={`${netCount} / 3 on`}>
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
            onChange={(v) => void applyNetworkOpt({ disable_network_throttling: v })}
            disabled={networkApplying}
          />
          <SettingRow
            title="Gaming QoS"
            desc="Prioritize game UDP (-5-20ms)"
            tooltip="QoS marks game UDP packets as high priority so routers handle them before downloads / streaming."
            enabled={draft.network_settings.gaming_qos}
            onChange={(v) => void applyNetworkOpt({ gaming_qos: v })}
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
            <div
              className="flex w-full items-center justify-between rounded-[var(--radius-card)] px-4 py-2.5"
              style={{
                backgroundColor: "var(--color-bg-elevated)",
                border: "1px solid var(--color-border-default)",
              }}
            >
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
                  disabled={isRestarting}
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
                    disabled={isRestarting || Boolean(windowValidationError)}
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
      <div
        className="overflow-hidden rounded-[var(--radius-card)]"
        style={{
          backgroundColor: "var(--color-bg-card)",
          border: "1px solid var(--color-border-subtle)",
        }}
      >
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
              onWidthChange(parseWindowDimensionInput(e.target.value, MIN_WINDOW_WIDTH))
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
              onHeightChange(parseWindowDimensionInput(e.target.value, MIN_WINDOW_HEIGHT))
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

function RamCleanerCard({
  systemMem,
  isCleaning,
  stage,
  trimmedCount,
  currentProcess,
  result,
  isAdmin,
  restartState,
  restartError,
  onRestartAsAdmin,
  onClean,
}: {
  systemMem: SystemMemorySnapshot | null;
  isCleaning: boolean;
  stage: string | null;
  trimmedCount: number;
  currentProcess: string | null;
  result: RamCleanResultResponse | null;
  isAdmin: boolean;
  restartState: "idle" | "restarting" | "error";
  restartError: string | null;
  onRestartAsAdmin: () => void;
  onClean: () => void;
}) {
  const totalMb = systemMem?.total_mb ?? 0;
  const usedMb = systemMem?.used_mb ?? 0;
  const availableMb = systemMem?.available_mb ?? 0;
  const percent =
    totalMb > 0 ? Math.max(0, Math.min(100, (usedMb / totalMb) * 100)) : 0;
  const color = memColor(percent);
  const showBottom = isCleaning || !isAdmin || result;

  const stateLabel = isCleaning
    ? "Cleaning"
    : percent >= 85
      ? "High usage"
      : percent >= 70
        ? "Elevated"
        : percent > 0
          ? "Healthy"
          : "—";
  const heroLabel = isCleaning ? "Reclaiming" : "System Memory";
  const showLive = !isCleaning && percent >= 85;

  return (
    <section className="flex flex-col gap-4">
      {/* ── Hero ── */}
      <div className="flex items-start justify-between gap-6 pt-1">
        <div className="min-w-0 flex-1">
          <div className="text-[10.5px] font-semibold uppercase tracking-[0.12em] text-text-muted">
            {heroLabel}
          </div>
          <div className="mt-2.5 flex items-center gap-2.5">
            <span
              className="text-[22px] font-semibold leading-none tracking-[-0.015em]"
              style={{ color: "var(--color-text-primary)" }}
            >
              {stateLabel}
            </span>
            {totalMb > 0 && (
              <span className="font-mono text-[13px] text-text-muted">
                {formatGbFromMb(usedMb)} / {formatGbFromMb(totalMb)} GB
              </span>
            )}
          </div>
          <div className="mt-3 flex items-baseline gap-4">
            {totalMb > 0 ? (
              <div className="flex items-baseline gap-1.5">
                <span
                  className="font-mono text-[34px] font-medium leading-none tabular-nums"
                  style={{ color: "var(--color-text-primary)" }}
                >
                  {percent.toFixed(0)}
                </span>
                <span className="text-[13px] text-text-muted">%</span>
              </div>
            ) : (
              <span className="text-[13px] text-text-muted">—</span>
            )}
            {showLive && (
              <div className="flex items-center gap-1.5">
                <span
                  className="relative h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: color }}
                >
                  <span
                    className="absolute inset-0 animate-ping rounded-full opacity-60"
                    style={{ backgroundColor: color }}
                  />
                </span>
                <span
                  className="text-[10.5px] font-semibold uppercase tracking-[0.12em]"
                  style={{ color }}
                >
                  Live
                </span>
              </div>
            )}
          </div>
        </div>
        <Button
          variant="primary"
          size="lg"
          onClick={onClean}
          disabled={isCleaning}
          loading={isCleaning}
        >
          {isCleaning ? "Cleaning" : "Clean RAM"}
        </Button>
      </div>

      {/* ── Memory detail card ── */}
      <div
        className="overflow-hidden rounded-[var(--radius-card)]"
        style={{
          backgroundColor: "var(--color-bg-card)",
          border: "1px solid var(--color-border-subtle)",
        }}
      >
        <div
          className="mx-4 mt-4 mb-2 h-1.5 overflow-hidden rounded-full"
          style={{ backgroundColor: "rgba(255,255,255,0.05)" }}
        >
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{ width: `${percent}%`, backgroundColor: color }}
          />
        </div>

        <div className="flex gap-5 px-4 pb-4 text-[11px]">
          <MemStat label="Used" value={`${formatGbFromMb(usedMb)} GB`} />
          <MemStat label="Total" value={`${formatGbFromMb(totalMb)} GB`} />
          <MemStat
            label="Available"
            value={`${formatGbFromMb(availableMb)} GB`}
            valueColor={color}
            bold
          />
          {systemMem?.standby_mb != null && (
            <MemStat
              label="Standby"
              value={`${formatGbFromMb(systemMem.standby_mb)} GB`}
            />
          )}
        </div>

      {showBottom && (
        <div
          className="space-y-2 border-t px-4 py-3"
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          {isCleaning && (
            <div className="flex items-center gap-2 text-[11.5px] text-text-muted">
              <Spinner size={10} color="var(--color-accent-primary)" />
              <span>
                {stage === "flushing_modified"
                  ? "Flushing modified pages…"
                  : stage === "standby_purge"
                    ? "Purging standby list…"
                    : stage
                      ? stage
                      : "Cleaning…"}
                {trimmedCount > 0 ? ` · Trimmed: ${trimmedCount}` : ""}
                {currentProcess ? ` · ${currentProcess}` : ""}
              </span>
            </div>
          )}
          {!isAdmin && (
            <div className="text-[11.5px] text-text-muted">
              Deep clean requires Administrator.{" "}
              <button
                type="button"
                onClick={onRestartAsAdmin}
                disabled={restartState === "restarting"}
                className="font-semibold text-accent-secondary hover:underline disabled:opacity-60"
              >
                {restartState === "restarting"
                  ? "Restarting…"
                  : "Restart as Admin"}
              </button>
              {restartState === "error" && restartError && (
                <div className="mt-1 text-[11px] text-status-error">
                  {restartError}
                </div>
              )}
            </div>
          )}
          {result && (
            <div
              className="rounded-[5px] px-3 py-2 text-[11px] text-text-muted"
              style={{ backgroundColor: "var(--color-bg-elevated)" }}
            >
              <div className="flex flex-wrap gap-x-5 gap-y-1">
                <ResultPill label="Freed" value={formatDeltaMb(result.freed_mb)} />
                {result.standby_freed_mb != null && (
                  <ResultPill
                    label="Standby"
                    value={formatDeltaMb(result.standby_freed_mb)}
                  />
                )}
                {result.modified_freed_mb != null && (
                  <ResultPill
                    label="Modified"
                    value={formatDeltaMb(result.modified_freed_mb)}
                  />
                )}
                <ResultPill label="Trimmed" value={String(result.trimmed_count)} />
                <ResultPill
                  label="Deep clean"
                  value={deepCleanLabel(result.standby_purge)}
                />
              </div>
              {result.warnings.length > 0 && (
                <div className="mt-1.5 text-[10.5px] text-status-warning">
                  <Chip tone="warning" size="xs">
                    {result.warnings.length} warning
                    {result.warnings.length !== 1 ? "s" : ""}
                  </Chip>
                </div>
              )}
            </div>
          )}
        </div>
      )}
      </div>
    </section>
  );
}

function MemStat({
  label,
  value,
  valueColor,
  bold,
}: {
  label: string;
  value: string;
  valueColor?: string;
  bold?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <span
        className={`font-mono text-[12px] ${bold ? "font-semibold" : ""}`}
        style={{ color: valueColor || "var(--color-text-primary)" }}
      >
        {value}
      </span>
    </div>
  );
}

function ResultPill({ label, value }: { label: string; value: string }) {
  return (
    <span>
      {label}{" "}
      <span className="font-mono font-medium text-text-primary">{value}</span>
    </span>
  );
}
