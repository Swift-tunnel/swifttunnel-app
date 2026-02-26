import { useEffect, useState, useCallback, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import { systemRestartAsAdmin } from "../../lib/commands";
import { notify } from "../../lib/notifications";
import { Toggle } from "../common/Toggle";
import type {
  Config,
  GameProcessPerformanceSettings,
  SystemOptimizationConfig,
  NetworkConfig,
  RobloxSettingsConfig,
  OptimizationProfile,
  SystemMemorySnapshot,
  RamCleanResultResponse,
} from "../../lib/types";

// ── Profile presets ──

const PROFILES: {
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

const MIN_WINDOW_WIDTH = 800;
const MAX_WINDOW_WIDTH = 3840;
const MIN_WINDOW_HEIGHT = 600;
const MAX_WINDOW_HEIGHT = 2160;

function getPresetConfig(profile: OptimizationProfile, current: Config): Config {
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
          optimize_mtu: true,
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
          optimize_mtu: false,
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
          optimize_mtu: false,
          gaming_qos: true,
        },
      };
    default:
      return base;
  }
}

// ── Helpers ──

function configsEqual(a: Config, b: Config): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function robloxSettingsChanged(a: Config, b: Config): boolean {
  return JSON.stringify(a.roblox_settings) !== JSON.stringify(b.roblox_settings);
}

function validateWindowDimension(
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

function countActive(...flags: boolean[]): number {
  return flags.filter(Boolean).length;
}

function formatGbFromMb(mb: number): string {
  if (!Number.isFinite(mb) || mb <= 0) return "0.0";
  return (mb / 1024).toFixed(1);
}

function formatDeltaMb(delta: number): string {
  if (!Number.isFinite(delta)) return "0 MB";
  const sign = delta >= 0 ? "+" : "-";
  return `${sign}${Math.abs(Math.round(delta))} MB`;
}

function deepCleanLabel(standby: {
  attempted: boolean;
  success: boolean;
  skipped_reason: string | null;
}): string {
  if (standby.success) return "Success";
  const reason = standby.skipped_reason ? ` (${standby.skipped_reason})` : "";
  if (!standby.attempted) return `Skipped${reason}`;
  return `Failed${reason}`;
}

function memColor(percent: number): string {
  if (percent > 85) return "#f05a5a";
  if (percent > 65) return "#f5b428";
  return "#28d296";
}

// ── SVG helpers ──

function polarToCartesian(cx: number, cy: number, r: number, deg: number) {
  const rad = ((deg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function arcPath(
  cx: number,
  cy: number,
  r: number,
  startDeg: number,
  endDeg: number,
): string {
  const s = polarToCartesian(cx, cy, r, startDeg);
  const e = polarToCartesian(cx, cy, r, endDeg);
  const large = endDeg - startDeg > 180 ? 1 : 0;
  return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
}

// ── Component ──

export function BoostTab() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);

  const boost = useBoostStore();

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

  const applyChanges = useCallback(() => {
    if (windowValidationError) {
      return;
    }
    updateSettings({
      config: draft,
      game_process_performance: draftGameProcessPerformance,
    });
    saveSettings();
    if (hasConfigChanges) {
      void boost.updateConfig(JSON.stringify(draft));
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
    if (windowValidationError) {
      return;
    }
    setIsRestarting(true);
    updateSettings({
      config: draft,
      game_process_performance: draftGameProcessPerformance,
    });
    saveSettings();
    if (hasConfigChanges) {
      void boost.updateConfig(JSON.stringify(draft));
    }
    await boost.restartRoblox();
    setIsRestarting(false);
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

  // Active counts per section
  const robloxActive = countActive(
    draft.roblox_settings.unlock_fps,
    draft.roblox_settings.ultraboost,
    draft.roblox_settings.window_fullscreen,
  );
  const systemActive = countActive(
    draft.system_optimization.set_high_priority,
    draft.system_optimization.timer_resolution_1ms,
    draft.system_optimization.mmcss_gaming_profile,
    draft.system_optimization.game_mode_enabled,
  );
  const processActive = countActive(
    draftGameProcessPerformance.high_performance_gpu_binding,
    draftGameProcessPerformance.prefer_performance_cores,
    draftGameProcessPerformance.unbind_cpu0,
  );
  const networkActive = countActive(
    draft.network_settings.disable_nagle,
    draft.network_settings.disable_network_throttling,
    draft.network_settings.optimize_mtu,
    draft.network_settings.gaming_qos,
  );

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
      <RamCleanerHero
        systemMem={boost.systemMem}
        isCleaning={boost.isCleaningRam}
        stage={boost.ramCleanStage}
        trimmedCount={boost.ramCleanTrimmedCount}
        currentProcess={boost.ramCleanCurrentProcess}
        result={boost.ramCleanResult}
        startSnapshot={boost.ramCleanStartSnapshot}
        doneSnapshot={boost.ramCleanDoneSnapshot}
        isAdmin={boost.isAdmin}
        restartState={restartAdminState}
        restartError={restartAdminError}
        onRestartAsAdmin={() => void restartAsAdmin()}
        onClean={() => void boost.cleanRam()}
      />

      {/* ── Profile Selector ── */}
      <div>
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-text-dimmed">
          Profile
        </div>
        <div className="flex gap-1 rounded-xl border border-border-subtle bg-bg-card p-1">
          {PROFILES.map((p) => {
            const sel = draft.profile === p.id;
            return (
              <button
                key={p.id}
                onClick={() => selectProfile(p.id)}
                className="flex-1 rounded-lg px-3 py-2.5 text-center text-[13px] font-medium transition-all duration-200"
                style={{
                  background: sel
                    ? "linear-gradient(145deg, var(--color-accent-primary), var(--color-accent-cyan))"
                    : "transparent",
                  color: sel ? "#fff" : "var(--color-text-muted)",
                  boxShadow: sel
                    ? "0 2px 10px rgba(60,130,246,0.25)"
                    : "none",
                }}
              >
                {p.icon} {p.name}
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
      <OptGroup title="Roblox" active={robloxActive} total={3} accent="#82dc3c">
        <OptRow
          title="Unlock FPS"
          desc="Remove 60 FPS cap"
          impact="Uncapped FPS"
          enabled={draft.roblox_settings.unlock_fps}
          onChange={(v) => updateRblxOpt({ unlock_fps: v })}
        />

        {draft.roblox_settings.unlock_fps && (
          <FpsSlider
            value={draft.roblox_settings.target_fps}
            onChange={(v) => updateRblxOpt({ target_fps: v })}
          />
        )}

        <OptRow
          title="Ultraboost"
          desc="All allowlisted performance FFlags for max FPS"
          impact="+20-40% FPS"
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

        <OptRow
          title="Launch Fullscreen"
          desc="Set Roblox fullscreen default"
          impact="Display mode"
          enabled={draft.roblox_settings.window_fullscreen}
          onChange={(v) => updateRblxOpt({ window_fullscreen: v })}
        />
      </OptGroup>

      {/* ── System ── */}
      <OptGroup
        title="System"
        active={systemActive}
        total={4}
        accent="#3c82f6"
      >
        <OptRow
          title="High Priority Mode"
          desc="Boost game process priority"
          impact="+5-15 FPS"
          enabled={draft.system_optimization.set_high_priority}
          onChange={(v) => updateSysOpt({ set_high_priority: v })}
        />
        <OptRow
          title="0.5ms Timer Resolution"
          desc="Max precision frame pacing"
          impact="Smoother frames"
          enabled={draft.system_optimization.timer_resolution_1ms}
          onChange={(v) => updateSysOpt({ timer_resolution_1ms: v })}
        />
        <OptRow
          title="MMCSS Gaming Profile"
          desc="Better thread scheduling"
          impact="Stable frame times"
          enabled={draft.system_optimization.mmcss_gaming_profile}
          onChange={(v) => updateSysOpt({ mmcss_gaming_profile: v })}
        />
        <OptRow
          title="Windows Game Mode"
          desc="System resource prioritization"
          impact="Consistent perf"
          enabled={draft.system_optimization.game_mode_enabled}
          onChange={(v) => updateSysOpt({ game_mode_enabled: v })}
        />
      </OptGroup>

      {/* ── Process Scheduling ── */}
      <OptGroup
        title="Process Scheduling"
        active={processActive}
        total={3}
        accent="#9664ff"
      >
        <OptRow
          title="High-Performance GPU Binding"
          desc="Bind target game executables to high-performance GPU while connected"
          impact="Stability"
          enabled={draftGameProcessPerformance.high_performance_gpu_binding}
          onChange={(v) =>
            updateGameProcessPerformance({ high_performance_gpu_binding: v })
          }
        />
        <OptRow
          title="Prefer Performance Cores"
          desc="Use CPU Sets to steer target games to P-cores on hybrid CPUs"
          impact="Frame Time"
          enabled={draftGameProcessPerformance.prefer_performance_cores}
          onChange={(v) =>
            updateGameProcessPerformance({ prefer_performance_cores: v })
          }
        />
        <OptRow
          title="Unbind CPU0"
          desc="Exclude logical CPU 0 for target games when enough cores are available"
          impact="Stability"
          enabled={draftGameProcessPerformance.unbind_cpu0}
          onChange={(v) => updateGameProcessPerformance({ unbind_cpu0: v })}
        />
      </OptGroup>

      {/* ── Network ── */}
      <OptGroup
        title="Network"
        active={networkActive}
        total={4}
        accent="#3898ff"
      >
        <OptRow
          title="Disable Nagle's Algorithm"
          desc="Faster packet delivery"
          impact="-5-15ms"
          enabled={draft.network_settings.disable_nagle}
          onChange={(v) => updateNetOpt({ disable_nagle: v })}
        />
        <OptRow
          title="Disable Network Throttling"
          desc="Full bandwidth for games"
          impact="Less lag spikes"
          enabled={draft.network_settings.disable_network_throttling}
          onChange={(v) => updateNetOpt({ disable_network_throttling: v })}
        />
        <OptRow
          title="Optimize MTU"
          desc="Find best packet size"
          impact="Less fragmentation"
          risk="Low Risk"
          enabled={draft.network_settings.optimize_mtu}
          onChange={(v) => updateNetOpt({ optimize_mtu: v })}
        />
        <OptRow
          title="Gaming QoS"
          desc="Prioritize Roblox + tunnel UDP"
          impact="-5-20ms"
          enabled={draft.network_settings.gaming_qos}
          onChange={(v) => updateNetOpt({ gaming_qos: v })}
        />
      </OptGroup>

      {/* ── Sticky Apply Bar ── */}
      <AnimatePresence>
        {hasChanges && (
          <motion.div
            initial={{ opacity: 0, y: 32 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 32 }}
            transition={{ type: "spring", damping: 22, stiffness: 300 }}
            className="fixed bottom-0 left-[var(--spacing-sidebar)] right-0 z-40 px-6 py-4"
            style={{
              background:
                "linear-gradient(to top, rgba(10, 10, 14, 0.97) 60%, rgba(10, 10, 14, 0.0))",
            }}
          >
            <div
              className="mx-auto flex max-w-[660px] items-center justify-between rounded-xl border px-5 py-3"
              style={{
                backgroundColor: "rgba(30, 30, 40, 0.95)",
                borderColor: "rgba(60, 130, 246, 0.25)",
                boxShadow:
                  "0 0 20px rgba(60, 130, 246, 0.12), 0 4px 24px rgba(0, 0, 0, 0.4)",
                backdropFilter: "blur(20px)",
                WebkitBackdropFilter: "blur(20px)",
              }}
            >
              <div className="flex items-center gap-2.5">
                <motion.div
                  animate={{ scale: [1, 1.3, 1] }}
                  transition={{
                    repeat: Number.POSITIVE_INFINITY,
                    duration: 2,
                    ease: "easeInOut",
                  }}
                  className="h-2 w-2 rounded-full"
                  style={{
                    backgroundColor: windowValidationError
                      ? "var(--color-status-error)"
                      : "var(--color-accent-primary)",
                    boxShadow: windowValidationError
                      ? "0 0 8px rgba(240, 90, 90, 0.5)"
                      : "0 0 8px rgba(60, 130, 246, 0.5)",
                  }}
                />
                <span className="text-xs font-medium text-text-secondary">
                  {windowValidationError
                    ? windowValidationError
                    : hasRobloxChanges && boost.robloxRunning
                      ? "Roblox must restart for changes to apply"
                      : "Unsaved changes"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={discardChanges}
                  disabled={isRestarting}
                  className="rounded-lg border border-border-subtle px-4 py-2 text-xs font-medium text-text-secondary transition-all hover:border-border-hover hover:bg-bg-hover hover:text-text-primary disabled:opacity-50"
                >
                  Discard
                </button>
                {hasRobloxChanges && boost.robloxRunning ? (
                  <motion.button
                    whileHover={{ scale: 1.03 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={() => void restartAndApply()}
                    disabled={isRestarting || Boolean(windowValidationError)}
                    className="rounded-lg px-6 py-2 text-xs font-bold text-white transition-all disabled:opacity-50"
                    style={{
                      background:
                        "linear-gradient(145deg, #3c82f6, #60a5ff)",
                      boxShadow:
                        "0 2px 12px rgba(60, 130, 246, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1)",
                    }}
                  >
                    {isRestarting ? "Restarting\u2026" : "Restart & Apply"}
                  </motion.button>
                ) : (
                  <motion.button
                    whileHover={{ scale: 1.03 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={applyChanges}
                    disabled={isRestarting || Boolean(windowValidationError)}
                    className="rounded-lg px-6 py-2 text-xs font-bold text-white transition-all disabled:opacity-50"
                    style={{
                      background:
                        "linear-gradient(145deg, #3c82f6, #60a5ff)",
                      boxShadow:
                        "0 2px 12px rgba(60, 130, 246, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1)",
                    }}
                  >
                    Apply
                  </motion.button>
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

function MemoryGauge({ percent }: { percent: number }) {
  const cx = 48;
  const cy = 44;
  const r = 32;
  const sw = 5.5;
  const startAngle = 225;
  const totalSweep = 270;
  const endAngle = startAngle + totalSweep;
  const filledSweep = Math.max(0.5, (percent / 100) * totalSweep);
  const filledEnd = startAngle + filledSweep;
  const color = memColor(percent);

  const bgArc = arcPath(cx, cy, r, startAngle, endAngle);
  const fillArc = arcPath(cx, cy, r, startAngle, filledEnd);

  return (
    <svg
      width="96"
      height="76"
      viewBox="0 0 96 76"
      className="shrink-0"
      aria-label={`Memory usage: ${Math.round(percent)}%`}
    >
      <defs>
        <filter id="gauge-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      {/* Background track */}
      <path
        d={bgArc}
        fill="none"
        stroke="rgba(255,255,255,0.05)"
        strokeWidth={sw}
        strokeLinecap="round"
      />
      {/* Filled arc */}
      <path
        d={fillArc}
        fill="none"
        stroke={color}
        strokeWidth={sw}
        strokeLinecap="round"
        filter="url(#gauge-glow)"
        style={{ transition: "stroke 0.4s ease, d 0.5s ease-out" }}
      />
      {/* Percentage text */}
      <text
        x={cx}
        y={cy + 1}
        textAnchor="middle"
        dominantBaseline="central"
        fill="var(--color-text-primary)"
        fontSize="18"
        fontWeight="700"
        fontFamily="'Cascadia Mono', Consolas, 'Courier New', monospace"
      >
        {Math.round(percent)}
      </text>
      <text
        x={cx}
        y={cy + 16}
        textAnchor="middle"
        dominantBaseline="central"
        fill="var(--color-text-dimmed)"
        fontSize="9"
        fontWeight="500"
      >
        %
      </text>
    </svg>
  );
}

function RamCleanerHero({
  systemMem,
  isCleaning,
  stage,
  trimmedCount,
  currentProcess,
  result,
  startSnapshot,
  doneSnapshot,
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
  startSnapshot: SystemMemorySnapshot | null;
  doneSnapshot: SystemMemorySnapshot | null;
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

  const runStart = startSnapshot ?? result?.before ?? null;
  const runDone = doneSnapshot ?? result?.after ?? null;
  const deltaAvailableMb =
    runStart && runDone ? runDone.available_mb - runStart.available_mb : null;
  const freedAvailableMb =
    deltaAvailableMb !== null ? Math.max(0, deltaAvailableMb) : null;

  const color = memColor(percent);
  const showBottom = isCleaning || !isAdmin || result;

  return (
    <div
      className="overflow-hidden rounded-xl border border-border-subtle"
      style={{
        background: `linear-gradient(155deg, var(--color-bg-card) 60%, ${color}08 100%)`,
      }}
    >
      {/* Top: gauge + info + button */}
      <div className="flex items-start gap-5 px-5 pb-4 pt-5">
        <motion.div
          animate={isCleaning ? { scale: [1, 1.03, 1] } : {}}
          transition={
            isCleaning
              ? { repeat: Number.POSITIVE_INFINITY, duration: 2, ease: "easeInOut" }
              : {}
          }
          className="shrink-0"
        >
          <MemoryGauge percent={percent} />
        </motion.div>

        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-text-primary">
                RAM Cleaner
              </div>
              <div className="mt-0.5 text-[11px] text-text-muted">
                Frees memory by trimming background apps
              </div>
            </div>
            <button
              onClick={onClean}
              disabled={isCleaning}
              className="shrink-0 rounded-lg px-5 py-2 text-xs font-semibold text-white transition-all disabled:opacity-60"
              style={{
                background: "linear-gradient(145deg, #3c82f6, #5a9fff)",
                boxShadow: "0 2px 8px rgba(60,130,246,0.25)",
              }}
            >
              {isCleaning ? "Cleaning\u2026" : "Clean RAM"}
            </button>
          </div>

          {/* Stats row */}
          <div className="mt-4 flex items-end gap-5 text-xs">
            <div className="flex flex-col gap-0.5">
              <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
                Used
              </span>
              <span className="font-mono text-text-primary">
                {formatGbFromMb(usedMb)} GB
              </span>
            </div>
            <div
              className="mb-0.5 h-4 w-px"
              style={{ backgroundColor: "var(--color-border-subtle)" }}
            />
            <div className="flex flex-col gap-0.5">
              <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
                Total
              </span>
              <span className="font-mono text-text-primary">
                {formatGbFromMb(totalMb)} GB
              </span>
            </div>
            <div
              className="mb-0.5 h-4 w-px"
              style={{ backgroundColor: "var(--color-border-subtle)" }}
            />
            <div className="flex flex-col gap-0.5">
              <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
                Available
              </span>
              <span className="font-mono font-semibold" style={{ color }}>
                {formatGbFromMb(availableMb)} GB
              </span>
            </div>
            {systemMem?.standby_mb != null && (
              <>
                <div
                  className="mb-0.5 h-4 w-px"
                  style={{ backgroundColor: "var(--color-border-subtle)" }}
                />
                <div className="flex flex-col gap-0.5">
                  <span className="text-[10px] uppercase tracking-wide text-text-dimmed">
                    Standby
                  </span>
                  <span className="font-mono text-text-primary">
                    {formatGbFromMb(systemMem.standby_mb)} GB
                  </span>
                </div>
              </>
            )}
          </div>
        </div>
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
              style={{
                backgroundColor: "var(--color-bg-elevated)",
              }}
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

  // Sync local input when parent value changes (e.g. profile switch)
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
              boxShadow: isUncapped
                ? "0 1px 6px rgba(60,130,246,0.3)"
                : "none",
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
        onChange={(e) => {
          const v = Number(e.target.value);
          onChange(v);
        }}
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
      <p className="mb-3 text-[11px] text-text-muted">
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
        <span className="mt-4 text-xs text-text-dimmed">\u00D7</span>
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
      {error && (
        <p className="mt-2 text-xs text-status-error">{error}</p>
      )}
    </div>
  );
}

function OptGroup({
  title,
  active,
  total,
  accent,
  children,
}: {
  title: string;
  active: number;
  total: number;
  accent: string;
  children: ReactNode;
}) {
  const allActive = active === total;

  return (
    <section
      className="overflow-hidden rounded-xl border border-border-subtle bg-bg-card"
      style={{ borderTopColor: allActive ? accent : undefined, borderTopWidth: allActive ? 2 : undefined }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5">
        <span className="text-[11px] font-semibold uppercase tracking-widest text-text-dimmed">
          {title}
        </span>
        <span
          className="rounded-md px-2 py-0.5 font-mono text-[10px] font-medium"
          style={{
            backgroundColor:
              active > 0 ? `${accent}15` : "var(--color-bg-elevated)",
            color: active > 0 ? accent : "var(--color-text-dimmed)",
          }}
        >
          {active}/{total}
        </span>
      </div>
      {/* Rows */}
      <div className="divide-y divide-border-subtle border-t border-border-subtle">
        {children}
      </div>
    </section>
  );
}

function OptRow({
  title,
  desc,
  impact,
  risk,
  enabled,
  onChange,
}: {
  title: string;
  desc: string;
  impact: string;
  risk?: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div
      className="relative flex items-center justify-between px-4 py-3 transition-colors duration-200"
      style={{
        backgroundColor: enabled ? "rgba(60, 130, 246, 0.025)" : "transparent",
      }}
    >
      {/* Active indicator bar */}
      {enabled && (
        <div
          className="absolute bottom-2 left-0 top-2 w-[2px] rounded-r"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
        />
      )}

      <div className="flex min-w-0 flex-col gap-0.5 pr-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[13px] font-medium text-text-primary">
            {title}
          </span>
          <span
            className="rounded px-1.5 py-0.5 text-[10px] font-medium"
            style={{
              backgroundColor: "var(--color-accent-lime-soft-10)",
              color: "var(--color-accent-lime)",
            }}
          >
            {impact}
          </span>
          {risk && (
            <span
              className="rounded px-1.5 py-0.5 text-[10px] font-medium"
              style={{
                backgroundColor: "var(--color-status-warning-soft-10)",
                color: "var(--color-status-warning)",
              }}
            >
              {risk}
            </span>
          )}
        </div>
        <span className="text-[11px] text-text-muted">{desc}</span>
      </div>
      <Toggle enabled={enabled} onChange={onChange} />
    </div>
  );
}
