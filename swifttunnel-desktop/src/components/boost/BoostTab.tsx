import { useEffect, useState, useCallback, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import { Toggle } from "../common/Toggle";
import type {
  Config,
  SystemOptimizationConfig,
  NetworkConfig,
  RobloxSettingsConfig,
  OptimizationProfile,
} from "../../lib/types";

// ── Profile presets ──

const PROFILES: { id: OptimizationProfile; name: string; desc: string; icon: string }[] = [
  { id: "LowEnd", name: "Performance", desc: "Max FPS, lowest quality", icon: "\u26A1" },
  { id: "Balanced", name: "Balanced", desc: "Good FPS, decent visuals", icon: "\u2696\uFE0F" },
  { id: "HighEnd", name: "Quality", desc: "Best visuals, stable perf", icon: "\u2728" },
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

export function parseWindowDimensionInput(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

// ── Component ──

export function BoostTab() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);

  const boost = useBoostStore();

  // Draft config — local buffer until user hits Apply
  const savedConfig = settings.config;
  const [draft, setDraft] = useState<Config>(savedConfig);

  // Sync draft when saved config changes externally (e.g. settings loaded)
  useEffect(() => {
    setDraft(savedConfig);
  }, [savedConfig]);

  const hasChanges = !configsEqual(draft, savedConfig);
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

  // Apply: persist draft to settings + backend
  const applyChanges = useCallback(() => {
    if (windowValidationError) {
      return;
    }
    updateSettings({ config: draft });
    saveSettings();
    void boost.updateConfig(JSON.stringify(draft));
  }, [draft, saveSettings, updateSettings, boost, windowValidationError]);

  // Restart & Apply: close Roblox, apply, relaunch
  const restartAndApply = useCallback(async () => {
    if (windowValidationError) {
      return;
    }
    setIsRestarting(true);
    updateSettings({ config: draft });
    saveSettings();
    void boost.updateConfig(JSON.stringify(draft));
    await boost.restartRoblox();
    setIsRestarting(false);
  }, [draft, saveSettings, updateSettings, boost, windowValidationError]);

  // Discard: reset draft to saved
  const discardChanges = useCallback(() => {
    setDraft(savedConfig);
  }, [savedConfig]);

  // Draft mutators (no persistence, just local state)
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

  return (
    <div className="flex flex-col gap-6 pb-16">
      {boost.error && (
        <p className="text-xs text-status-error">{boost.error}</p>
      )}

      {/* ── Profile Selector ── */}
      <Section title="Profile">
        <div className="grid grid-cols-3 gap-2">
          {PROFILES.map((p) => {
            const sel = draft.profile === p.id;
            return (
              <button
                key={p.id}
                onClick={() => selectProfile(p.id)}
                className="rounded-[var(--radius-card)] border p-4 text-left transition-all"
                style={{
                  backgroundColor: sel
                    ? "var(--color-accent-primary-soft-8)"
                    : "var(--color-bg-card)",
                  borderColor: sel
                    ? "var(--color-accent-primary)"
                    : "var(--color-border-subtle)",
                }}
              >
                <div className="flex items-center gap-2 text-sm font-medium text-text-primary">
                  <span>{p.icon}</span>
                  {p.name}
                </div>
                <div className="mt-0.5 text-xs text-text-muted">{p.desc}</div>
              </button>
            );
          })}
        </div>
        {draft.profile === "Custom" && (
          <p className="mt-2 text-xs text-text-muted">
            Custom configuration — individual settings below
          </p>
        )}
      </Section>

      {/* ── System Optimizations ── */}
      <Section title="System Optimizations">
        <BoostCard
          title="High Priority Mode"
          desc="Boost game process priority"
          impact="+5-15 FPS"
          enabled={draft.system_optimization.set_high_priority}
          onChange={(v) => updateSysOpt({ set_high_priority: v })}
        />
        <BoostCard
          title="0.5ms Timer Resolution"
          desc="Max precision frame pacing"
          impact="Smoother frames"
          enabled={draft.system_optimization.timer_resolution_1ms}
          onChange={(v) => updateSysOpt({ timer_resolution_1ms: v })}
        />
        <BoostCard
          title="MMCSS Gaming Profile"
          desc="Better thread scheduling"
          impact="Stable frame times"
          enabled={draft.system_optimization.mmcss_gaming_profile}
          onChange={(v) => updateSysOpt({ mmcss_gaming_profile: v })}
        />
        <BoostCard
          title="Windows Game Mode"
          desc="System resource prioritization"
          impact="Consistent perf"
          enabled={draft.system_optimization.game_mode_enabled}
          onChange={(v) => updateSysOpt({ game_mode_enabled: v })}
        />
      </Section>

      {/* ── Network Optimizations ── */}
      <Section title="Network Optimizations">
        <BoostCard
          title="Disable Nagle's Algorithm"
          desc="Faster packet delivery"
          impact="-5-15ms"
          enabled={draft.network_settings.disable_nagle}
          onChange={(v) => updateNetOpt({ disable_nagle: v })}
        />
        <BoostCard
          title="Disable Network Throttling"
          desc="Full bandwidth for games"
          impact="Less lag spikes"
          enabled={draft.network_settings.disable_network_throttling}
          onChange={(v) => updateNetOpt({ disable_network_throttling: v })}
        />
        <BoostCard
          title="Optimize MTU"
          desc="Find best packet size"
          impact="Less fragmentation"
          risk="Low Risk"
          enabled={draft.network_settings.optimize_mtu}
          onChange={(v) => updateNetOpt({ optimize_mtu: v })}
        />
        <BoostCard
          title="Gaming QoS"
          desc="Prioritize Roblox + tunnel UDP"
          impact="-5-20ms"
          enabled={draft.network_settings.gaming_qos}
          onChange={(v) => updateNetOpt({ gaming_qos: v })}
        />
      </Section>

      {/* ── Roblox Settings ── */}
      <Section title="Roblox">
        <BoostCard
          title="Unlock FPS"
          desc="Remove 60 FPS cap"
          impact="Uncapped FPS"
          enabled={draft.roblox_settings.unlock_fps}
          onChange={(v) => updateRblxOpt({ unlock_fps: v })}
        />

        {draft.roblox_settings.unlock_fps && (
          <div className="rounded-[var(--radius-card)] border border-border-subtle bg-bg-card px-4 py-3">
            <div className="flex items-center justify-between">
              <label
                htmlFor="target-fps-slider"
                className="text-sm text-text-primary"
              >
                Target FPS
              </label>
              <span className="font-mono text-sm text-accent-secondary">
                {draft.roblox_settings.target_fps >= 99999
                  ? "Uncapped"
                  : draft.roblox_settings.target_fps}
              </span>
            </div>
            <input
              id="target-fps-slider"
              type="range"
              aria-label="Target FPS"
              min={30}
              max={1010}
              step={10}
              value={
                draft.roblox_settings.target_fps >= 99999
                  ? 1010
                  : draft.roblox_settings.target_fps
              }
              onChange={(e) => {
                const v = Number(e.target.value);
                updateRblxOpt({ target_fps: v >= 1010 ? 99999 : v });
              }}
              className="mt-2 w-full accent-accent-primary"
            />
          </div>
        )}

        <BoostCard
          title="Ultraboost"
          desc="All allowlisted performance FFlags for max FPS"
          impact="+20-40% FPS"
          enabled={draft.roblox_settings.ultraboost}
          onChange={(v) => updateRblxOpt({ ultraboost: v })}
        />

        <div className="rounded-[var(--radius-card)] border border-border-subtle bg-bg-card px-4 py-3">
          <div className="mb-2 text-sm font-medium text-text-primary">
            Window Resolution
          </div>
          <p className="mb-3 text-xs text-text-muted">
            Sets Roblox launch window size in pixels.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-xs text-text-muted">Width</span>
              <input
                type="number"
                min={MIN_WINDOW_WIDTH}
                max={MAX_WINDOW_WIDTH}
                step={2}
                value={draft.roblox_settings.window_width}
                onChange={(e) =>
                  updateRblxOpt({
                    window_width: parseWindowDimensionInput(
                      e.target.value,
                      MIN_WINDOW_WIDTH,
                    ),
                  })}
                className="rounded-[var(--radius-input)] border border-border-subtle bg-bg-elevated px-3 py-2 text-sm text-text-primary outline-none transition-colors focus:border-accent-primary"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-text-muted">Height</span>
              <input
                type="number"
                min={MIN_WINDOW_HEIGHT}
                max={MAX_WINDOW_HEIGHT}
                step={2}
                value={draft.roblox_settings.window_height}
                onChange={(e) =>
                  updateRblxOpt({
                    window_height: parseWindowDimensionInput(
                      e.target.value,
                      MIN_WINDOW_HEIGHT,
                    ),
                  })}
                className="rounded-[var(--radius-input)] border border-border-subtle bg-bg-elevated px-3 py-2 text-sm text-text-primary outline-none transition-colors focus:border-accent-primary"
              />
            </label>
          </div>
          {windowValidationError && (
            <p className="mt-2 text-xs text-status-error">{windowValidationError}</p>
          )}
        </div>

        <BoostCard
          title="Launch Fullscreen"
          desc="Set Roblox fullscreen default"
          impact="Display mode"
          enabled={draft.roblox_settings.window_fullscreen}
          onChange={(v) => updateRblxOpt({ window_fullscreen: v })}
        />
      </Section>

      {/* ── Sticky Apply Bar ── */}
      <AnimatePresence>
        {hasChanges && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="fixed bottom-0 left-[var(--spacing-sidebar)] right-0 z-40 border-t px-6 py-3"
            style={{
              backgroundColor: "var(--color-bg-sidebar)",
              borderColor: "var(--color-border-subtle)",
              backdropFilter: "blur(12px)",
            }}
          >
            <div className="mx-auto flex max-w-[640px] items-center justify-between">
              <span className="text-xs text-text-muted">
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
                  className="rounded-[var(--radius-button)] px-4 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:bg-bg-hover disabled:opacity-50"
                >
                  Discard
                </button>
                {hasRobloxChanges && boost.robloxRunning ? (
                  <button
                    onClick={() => void restartAndApply()}
                    disabled={isRestarting || Boolean(windowValidationError)}
                    className="rounded-[var(--radius-button)] px-5 py-1.5 text-xs font-semibold text-white transition-all disabled:opacity-50"
                    style={{
                      background: "linear-gradient(145deg, #3c82f6, #5a9fff)",
                      boxShadow: "0 2px 8px rgba(60,130,246,0.25)",
                    }}
                  >
                    {isRestarting ? "Restarting\u2026" : "Restart & Apply"}
                  </button>
                ) : (
                  <button
                    onClick={applyChanges}
                    disabled={isRestarting || Boolean(windowValidationError)}
                    className="rounded-[var(--radius-button)] px-5 py-1.5 text-xs font-semibold text-white transition-all disabled:opacity-50"
                    style={{
                      background: "linear-gradient(145deg, #3c82f6, #5a9fff)",
                      boxShadow: "0 2px 8px rgba(60,130,246,0.25)",
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

function Section({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section>
      <h3 className="mb-3 text-xs font-medium uppercase tracking-wider text-text-muted">
        {title}
      </h3>
      <div className="flex flex-col gap-2">{children}</div>
    </section>
  );
}

function BoostCard({
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
    <div className="flex items-center justify-between rounded-[var(--radius-card)] border border-border-subtle bg-bg-card px-4 py-3">
      <div className="flex flex-col gap-0.5">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text-primary">
            {title}
          </span>
          <span
            className="rounded px-1.5 py-0.5 text-[10px]"
            style={{
              backgroundColor: "var(--color-accent-lime-soft-10)",
              color: "var(--color-accent-lime)",
            }}
          >
            {impact}
          </span>
          {risk && (
            <span
              className="rounded px-1.5 py-0.5 text-[10px]"
              style={{
                backgroundColor: "var(--color-status-warning-soft-10)",
                color: "var(--color-status-warning)",
              }}
            >
              {risk}
            </span>
          )}
        </div>
        <span className="text-xs text-text-muted">{desc}</span>
      </div>
      <Toggle enabled={enabled} onChange={onChange} />
    </div>
  );
}
