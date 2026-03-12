import { useEffect, useState, useCallback, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import { useToastStore } from "../../stores/toastStore";
import { systemRestartAsAdmin } from "../../lib/commands";
import { notify } from "../../lib/notifications";
import { Toggle } from "../common/Toggle";
import { Tooltip, InfoIcon } from "../common/Tooltip";
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
  const [restartAdminError, setRestartAdminError] = useState<string | null>(
    null,
  );

  // Draft config — local buffer until user hits Apply
  const savedConfig = settings.config;
  const [draft, setDraft] = useState<Config>(savedConfig);

  useEffect(() => {
    setDraft(savedConfig);
  }, [savedConfig]);

  const savedGameProcessPerformance = settings.game_process_performance;
  const [draftGameProcessPerformance, setDraftGameProcessPerformance] =
    useState<GameProcessPerformanceSettings>(savedGameProcessPerformance);

  useEffect(() => {
    setDraftGameProcessPerformance(savedGameProcessPerformance);
  }, [savedGameProcessPerformance]);

  const hasConfigChanges = !configsEqual(draft, savedConfig);
  const hasGameProcessPerformanceChanges =
    JSON.stringify(draftGameProcessPerformance) !==
    JSON.stringify(savedGameProcessPerformance);
  const hasChanges = hasConfigChanges || hasGameProcessPerformanceChanges;
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
    updateSettings({
      config: draft,
      game_process_performance: draftGameProcessPerformance,
    });
    saveSettings();
    if (hasConfigChanges) {
      await boost.updateConfig(JSON.stringify(draft));
    }
    addToast({ type: "success", message: "Boost settings applied" });
  }, [
    draft,
    draftGameProcessPerformance,
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
      const message = String(e);
      setRestartAdminState("error");
      setRestartAdminError(message);
      await notify("Restart canceled", "Could not restart as Administrator.");
    }
  }, []);

  const restartAndApply = useCallback(async () => {
    if (windowValidationError) return;
    setIsRestarting(true);
    try {
      updateSettings({
        config: draft,
        game_process_performance: draftGameProcessPerformance,
      });
      saveSettings();
      if (hasConfigChanges) {
        await boost.updateConfig(JSON.stringify(draft));
      }
      await boost.restartRoblox();
    } finally {
      setIsRestarting(false);
    }
  }, [
    draft,
    draftGameProcessPerformance,
    hasConfigChanges,
    saveSettings,
    updateSettings,
    boost,
    windowValidationError,
  ]);

  const discardChanges = useCallback(() => {
    setDraft(savedConfig);
    setDraftGameProcessPerformance(savedGameProcessPerformance);
  }, [savedConfig, savedGameProcessPerformance]);

  function selectProfile(id: OptimizationProfile) {
    setDraft(getPresetConfig(id, draft));
  }

  function updateSysOpt(partial: Partial<SystemOptimizationConfig>) {
    setDraft((prev) => ({
      ...prev,
      profile: "Custom",
      system_optimization: { ...prev.system_optimization, ...partial },
    }));
  }

  function updateNetOpt(partial: Partial<NetworkConfig>) {
    setDraft((prev) => ({
      ...prev,
      profile: "Custom",
      network_settings: { ...prev.network_settings, ...partial },
    }));
  }

  function updateRblxOpt(partial: Partial<RobloxSettingsConfig>) {
    setDraft((prev) => ({
      ...prev,
      profile: "Custom",
      roblox_settings: { ...prev.roblox_settings, ...partial },
    }));
  }

  function updateGameProcessPerformance(
    partial: Partial<GameProcessPerformanceSettings>,
  ) {
    setDraftGameProcessPerformance((prev) => ({ ...prev, ...partial }));
  }

  return (
    <div className="mx-auto flex max-w-[660px] flex-col gap-4 pb-16">
      {boost.error && (
        <div
          className="rounded-lg px-4 py-2 text-xs"
          style={{
            backgroundColor: "var(--color-status-error-soft-10)",
            color: "var(--color-status-error)",
            border: "1px solid var(--color-status-error-soft-20)",
          }}
        >
          {boost.error}
        </div>
      )}

      {/* ── RAM Cleaner ── */}
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
      <div>
        <SectionHeader title="Profile" />
        <div className="flex gap-1 rounded-[var(--radius-card)] border border-border-subtle bg-bg-card p-1">
          {PROFILES.map((p) => {
            const sel = draft.profile === p.id;
            return (
              <button
                key={p.id}
                onClick={() => selectProfile(p.id)}
                className="flex-1 rounded-lg px-3 py-2.5 text-center text-[13px] font-medium transition-colors"
                style={{
                  backgroundColor: sel
                    ? "var(--color-accent-primary)"
                    : "transparent",
                  color: sel ? "#fff" : "var(--color-text-muted)",
                }}
              >
                {p.name}
              </button>
            );
          })}
        </div>
        {draft.profile === "Custom" && (
          <p className="mt-2 text-[11px] text-text-dimmed">
            Custom — individual settings below
          </p>
        )}
      </div>

      {/* ── Roblox ── */}
      <Section title="Roblox">
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
          desc="All allowlisted performance FFlags for max FPS (+20-40%)"
          enabled={draft.roblox_settings.ultraboost}
          onChange={(v) => updateRblxOpt({ ultraboost: v })}
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

      {/* ── System ── */}
      <Section title="System">
        <SettingRow
          title="High Priority Mode"
          desc="Boost game process priority for +5-15 FPS"
          enabled={draft.system_optimization.set_high_priority}
          onChange={(v) => updateSysOpt({ set_high_priority: v })}
        />
        <SettingRow
          title="0.5ms Timer Resolution"
          desc="Max precision frame pacing for smoother frames"
          tooltip="Reduces the Windows timer interrupt interval to 0.5ms for more precise frame pacing and input polling. Slightly increases CPU usage."
          enabled={draft.system_optimization.timer_resolution_1ms}
          onChange={(v) => updateSysOpt({ timer_resolution_1ms: v })}
        />
        <SettingRow
          title="MMCSS Gaming Profile"
          desc="Better thread scheduling for stable frame times"
          tooltip="Multimedia Class Scheduler Service — tells Windows to give game threads higher priority for CPU time, reducing stutters from background tasks."
          enabled={draft.system_optimization.mmcss_gaming_profile}
          onChange={(v) => updateSysOpt({ mmcss_gaming_profile: v })}
        />
        <SettingRow
          title="Windows Game Mode"
          desc="System resource prioritization for consistent perf"
          enabled={draft.system_optimization.game_mode_enabled}
          onChange={(v) => updateSysOpt({ game_mode_enabled: v })}
        />
      </Section>

      {/* ── Process Scheduling ── */}
      <Section title="Process Scheduling">
        <SettingRow
          title="High-Performance GPU Binding"
          desc="Bind target game executables to high-performance GPU while connected"
          enabled={draftGameProcessPerformance.high_performance_gpu_binding}
          onChange={(v) =>
            updateGameProcessPerformance({ high_performance_gpu_binding: v })
          }
        />
        <SettingRow
          title="Prefer Performance Cores"
          desc="Use CPU Sets to steer target games to P-cores on hybrid CPUs"
          enabled={draftGameProcessPerformance.prefer_performance_cores}
          onChange={(v) =>
            updateGameProcessPerformance({ prefer_performance_cores: v })
          }
        />
        <SettingRow
          title="Unbind CPU0"
          desc="Exclude logical CPU 0 for target games when enough cores are available"
          enabled={draftGameProcessPerformance.unbind_cpu0}
          onChange={(v) => updateGameProcessPerformance({ unbind_cpu0: v })}
        />
      </Section>

      {/* ── Network ── */}
      <Section title="Network">
        <SettingRow
          title="Disable Nagle's Algorithm"
          desc="Faster packet delivery (-5-15ms)"
          tooltip="Nagle's algorithm batches small packets together to reduce overhead. Disabling it sends packets immediately, reducing latency for real-time games."
          enabled={draft.network_settings.disable_nagle}
          onChange={(v) => updateNetOpt({ disable_nagle: v })}
        />
        <SettingRow
          title="Disable Network Throttling"
          desc="Full bandwidth for games, less lag spikes"
          tooltip="Windows throttles network I/O when multimedia is playing. Disabling this prevents sudden bandwidth drops during gaming."
          enabled={draft.network_settings.disable_network_throttling}
          onChange={(v) => updateNetOpt({ disable_network_throttling: v })}
        />
        <SettingRow
          title="Gaming QoS"
          desc="Prioritize Roblox + tunnel UDP (-5-20ms)"
          tooltip="Quality of Service — marks game UDP packets as high priority so routers and Windows handle them before other traffic like downloads or streaming."
          enabled={draft.network_settings.gaming_qos}
          onChange={(v) => updateNetOpt({ gaming_qos: v })}
        />
      </Section>

      {/* ── Sticky Apply Bar ── */}
      <AnimatePresence>
        {hasChanges && (
          <motion.div
            initial={{ opacity: 0, y: 32 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 32 }}
            transition={{ type: "spring", damping: 22, stiffness: 300 }}
            className="fixed bottom-0 left-[var(--spacing-sidebar)] right-0 z-40 px-6 pb-4"
          >
            <div className="mx-auto flex max-w-[660px] items-center justify-between rounded-[var(--radius-card)] border border-border-subtle bg-bg-card px-5 py-3 shadow-lg backdrop-blur-xl">
              <span className="text-xs font-medium text-text-secondary">
                {windowValidationError
                  ? windowValidationError
                  : hasRobloxChanges && boost.robloxRunning
                    ? "Roblox must restart for changes to apply"
                    : "Unsaved changes"}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={discardChanges}
                  disabled={isRestarting}
                  className="rounded-[var(--radius-button)] border border-border-subtle px-4 py-2 text-xs font-medium text-text-secondary transition-colors hover:bg-bg-hover disabled:opacity-50"
                >
                  Discard
                </button>
                {hasRobloxChanges && boost.robloxRunning ? (
                  <button
                    onClick={() => void restartAndApply()}
                    disabled={isRestarting || Boolean(windowValidationError)}
                    className="rounded-[var(--radius-button)] px-5 py-2 text-xs font-semibold text-white transition-opacity disabled:opacity-50"
                    style={{
                      backgroundColor: "var(--color-accent-primary)",
                    }}
                  >
                    {isRestarting ? "Restarting\u2026" : "Restart & Apply"}
                  </button>
                ) : (
                  <button
                    onClick={applyChanges}
                    disabled={isRestarting || Boolean(windowValidationError)}
                    className="rounded-[var(--radius-button)] px-5 py-2 text-xs font-semibold text-white transition-opacity disabled:opacity-50"
                    style={{
                      backgroundColor: "var(--color-accent-primary)",
                    }}
                  >
                    Apply
                  </button>
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

function SectionHeader({ title }: { title: string }) {
  return (
    <div className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-text-dimmed">
      {title}
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <SectionHeader title={title} />
      <div className="overflow-hidden rounded-[var(--radius-card)] border border-border-subtle bg-bg-card">
        <div className="divide-y divide-border-subtle">{children}</div>
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
}: {
  title: string;
  desc: string;
  tooltip?: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3">
      <div className="flex min-w-0 flex-col gap-0.5 pr-4">
        <span className="flex items-center gap-1.5 text-sm font-medium text-text-primary">
          {title}
          {tooltip && (
            <Tooltip content={tooltip}>
              <InfoIcon />
            </Tooltip>
          )}
        </span>
        <span className="text-xs text-text-muted">{desc}</span>
      </div>
      <Toggle enabled={enabled} onChange={onChange} />
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

  return (
    <div className="overflow-hidden rounded-[var(--radius-card)] border border-border-subtle bg-bg-card">
      <div className="flex items-center justify-between px-5 pt-5 pb-4">
        <div>
          <div className="text-sm font-semibold text-text-primary">
            RAM Cleaner
          </div>
          <div className="mt-0.5 text-xs text-text-muted">
            Frees memory by trimming background apps
          </div>
        </div>
        <button
          onClick={onClean}
          disabled={isCleaning}
          className="shrink-0 rounded-[var(--radius-button)] px-5 py-2 text-xs font-semibold text-white transition-opacity disabled:opacity-60"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        >
          {isCleaning ? "Cleaning\u2026" : "Clean RAM"}
        </button>
      </div>

      {/* Memory bar */}
      <div className="mx-5 mb-2 h-2 overflow-hidden rounded-full bg-[rgba(255,255,255,0.06)]">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${percent}%`, backgroundColor: color }}
        />
      </div>

      {/* Stats */}
      <div className="flex gap-6 px-5 pb-4 text-xs">
        <div className="flex flex-col gap-0.5">
          <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
            Used
          </span>
          <span className="font-mono text-text-primary">
            {formatGbFromMb(usedMb)} GB
          </span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
            Total
          </span>
          <span className="font-mono text-text-primary">
            {formatGbFromMb(totalMb)} GB
          </span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
            Available
          </span>
          <span className="font-mono font-semibold" style={{ color }}>
            {formatGbFromMb(availableMb)} GB
          </span>
        </div>
        {systemMem?.standby_mb != null && (
          <div className="flex flex-col gap-0.5">
            <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
              Standby
            </span>
            <span className="font-mono text-text-primary">
              {formatGbFromMb(systemMem.standby_mb)} GB
            </span>
          </div>
        )}
      </div>

      {/* Bottom: progress / admin / result */}
      {showBottom && (
        <div className="space-y-2 border-t border-border-subtle px-5 py-3">
          {isCleaning && (
            <div className="flex items-center gap-2 text-xs text-text-muted">
              <div
                className="h-1.5 w-1.5 animate-pulse rounded-full"
                style={{ backgroundColor: "var(--color-accent-primary)" }}
              />
              <span>
                {stage === "flushing_modified"
                  ? "Flushing modified pages\u2026"
                  : stage === "standby_purge"
                    ? "Purging standby list\u2026"
                    : stage
                      ? `${stage}`
                      : "Cleaning\u2026"}
                {trimmedCount > 0 ? ` \u00B7 Trimmed: ${trimmedCount}` : ""}
                {currentProcess ? ` \u00B7 ${currentProcess}` : ""}
              </span>
            </div>
          )}

          {!isAdmin && (
            <div className="text-xs text-text-muted">
              Deep clean requires Administrator.{" "}
              <button
                type="button"
                onClick={onRestartAsAdmin}
                disabled={restartState === "restarting"}
                className="rounded px-1.5 py-0.5 font-semibold text-accent-secondary hover:underline disabled:opacity-60"
              >
                {restartState === "restarting"
                  ? "Restarting\u2026"
                  : "Restart as Admin"}
              </button>
              {restartState === "error" && restartError && (
                <div className="mt-1 text-xs text-status-error">
                  {restartError}
                </div>
              )}
            </div>
          )}

          {result && (
            <div
              className="rounded-lg px-3 py-2.5 text-xs text-text-muted"
              style={{ backgroundColor: "var(--color-bg-elevated)" }}
            >
              <div className="flex flex-wrap gap-x-5 gap-y-1">
                <span>
                  Freed{" "}
                  <span className="font-mono font-medium text-text-primary">
                    {formatDeltaMb(result.freed_mb)}
                  </span>
                </span>
                {result.standby_freed_mb != null && (
                  <span>
                    Standby{" "}
                    <span className="font-mono font-medium text-text-primary">
                      {formatDeltaMb(result.standby_freed_mb)}
                    </span>
                  </span>
                )}
                {result.modified_freed_mb != null && (
                  <span>
                    Modified{" "}
                    <span className="font-mono font-medium text-text-primary">
                      {formatDeltaMb(result.modified_freed_mb)}
                    </span>
                  </span>
                )}
                <span>
                  Trimmed{" "}
                  <span className="font-mono font-medium text-text-primary">
                    {result.trimmed_count}
                  </span>
                </span>
                <span>
                  Deep clean{" "}
                  <span className="font-mono font-medium text-text-primary">
                    {deepCleanLabel(result.standby_purge)}
                  </span>
                </span>
              </div>
              {result.warnings.length > 0 && (
                <div className="mt-1.5 text-[11px] text-status-warning">
                  Warnings: {result.warnings.length}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FpsSlider({
  value,
  onChange,
}: {
  value: number;
  onChange: (v: number) => void;
}) {
  const isUncapped = value >= 99999;
  const sliderValue = isUncapped ? 1000 : Math.min(value, 1000);
  const sliderPercent = ((sliderValue - 30) / (1000 - 30)) * 100;

  const [inputText, setInputText] = useState(isUncapped ? "" : String(value));

  useEffect(() => {
    setInputText(isUncapped ? "" : String(value));
  }, [value, isUncapped]);

  function commitInput(raw: string) {
    const v = Number.parseInt(raw, 10);
    if (Number.isFinite(v) && v >= 30) {
      onChange(Math.min(v, 9999));
    }
  }

  return (
    <div className="px-4 py-3">
      <div className="mb-2.5 flex items-center justify-between">
        <span className="text-xs text-text-muted">Target FPS</span>
        <div className="flex items-center gap-1.5">
          <input
            type="number"
            min={30}
            max={9999}
            value={inputText}
            placeholder="MAX"
            disabled={isUncapped}
            onChange={(e) => {
              setInputText(e.target.value);
              const v = Number.parseInt(e.target.value, 10);
              if (Number.isFinite(v) && v >= 30 && v <= 9999) {
                onChange(v);
              }
            }}
            onBlur={(e) => commitInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") commitInput(e.currentTarget.value);
            }}
            className="boost-input w-[72px] rounded-md border border-border-subtle bg-bg-elevated px-2 py-1 text-right font-mono text-sm font-semibold text-text-primary outline-none transition-colors focus:border-accent-primary disabled:opacity-40"
          />
          <button
            type="button"
            onClick={() => onChange(isUncapped ? 240 : 99999)}
            className="rounded-md px-2 py-1 text-[10px] font-bold tracking-wide transition-all"
            style={{
              backgroundColor: isUncapped
                ? "var(--color-accent-primary)"
                : "var(--color-bg-elevated)",
              color: isUncapped ? "#fff" : "var(--color-text-muted)",
            }}
          >
            MAX
          </button>
        </div>
      </div>
      <input
        type="range"
        aria-label="Target FPS slider"
        min={30}
        max={1000}
        step={10}
        value={sliderValue}
        disabled={isUncapped}
        onChange={(e) => onChange(Number(e.target.value))}
        className="boost-slider w-full disabled:opacity-30"
        style={{
          background: isUncapped
            ? "rgba(255,255,255,0.06)"
            : `linear-gradient(to right, var(--color-accent-primary) 0%, var(--color-accent-primary) ${sliderPercent}%, rgba(255,255,255,0.06) ${sliderPercent}%, rgba(255,255,255,0.06) 100%)`,
        }}
      />
      <div className="mt-1.5 flex justify-between text-[10px] text-text-dimmed">
        <span>30</span>
        <span>120</span>
        <span>240</span>
        <span>360</span>
        <span>1000</span>
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
      <div className="mb-1 text-sm font-medium text-text-primary">
        Window Resolution
      </div>
      <p className="mb-3 text-xs text-text-muted">
        Sets Roblox launch window size in pixels.
      </p>
      <div className="flex items-center gap-2">
        <label className="flex flex-1 flex-col gap-1">
          <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
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
            className="boost-input rounded-lg border border-border-subtle bg-bg-elevated px-3 py-2 text-sm text-text-primary outline-none transition-colors focus:border-accent-primary"
          />
        </label>
        <span className="mt-4 text-xs text-text-dimmed">{"\u00D7"}</span>
        <label className="flex flex-1 flex-col gap-1">
          <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
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
            className="boost-input rounded-lg border border-border-subtle bg-bg-elevated px-3 py-2 text-sm text-text-primary outline-none transition-colors focus:border-accent-primary"
          />
        </label>
      </div>
      {error && <p className="mt-2 text-xs text-status-error">{error}</p>}
    </div>
  );
}
