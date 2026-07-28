import { useState } from "react";
import { Toggle, Chip, Panel, Readout, StatRail } from "../ui";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import type {
  Config,
  OverlayConfig,
  OverlayMetric,
  OverlayPosition,
  OverlaySize,
  OverlayStyle,
} from "../../lib/types";
import { OverlayBar } from "./OverlayBar";
import {
  MAX_OVERLAY_METRICS,
  OVERLAY_COLORS,
  OVERLAY_METRIC_GROUPS,
  OVERLAY_METRICS,
  OVERLAY_SAMPLE_VALUES,
} from "./overlayMetrics";

const POSITIONS: OverlayPosition[][] = [
  ["top-left", "top-center", "top-right"],
  ["center-left", "center", "center-right"],
  ["bottom-left", "bottom-center", "bottom-right"],
];

const SIZES: OverlaySize[] = ["small", "medium", "large"];
const STYLES: { id: OverlayStyle; label: string }[] = [
  { id: "straight", label: "Straight" },
  { id: "layered", label: "Layered" },
];

export function InGameTab() {
  const config = useSettingsStore((s) => s.settings.config);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const updateConfig = useBoostStore((s) => s.updateConfig);
  const [ramBusy, setRamBusy] = useState(false);
  const ov = config.overlay;
  const hasCustomPos = ov.custom_x !== null && ov.custom_y !== null;

  function patch(p: Partial<OverlayConfig>) {
    const next: Config = { ...config, overlay: { ...ov, ...p } };
    updateSettings({ config: next });
    void saveSettings();
  }

  // Auto-RAM-clean lives in system_optimization, which the backend applies -
  // persist it through boost_update_config (same pattern as the Optimize tab)
  // so a later config sync can't revert the toggle.
  async function toggleAutoRamClean(next: boolean) {
    const nextConfig: Config = {
      ...config,
      system_optimization: {
        ...config.system_optimization,
        auto_ram_clean: next,
      },
    };
    setRamBusy(true);
    try {
      const applied = await updateConfig(JSON.stringify(nextConfig));
      updateSettings({ config: applied });
      void saveSettings();
    } catch {
      // updateConfig surfaces errors through the boost store.
    } finally {
      setRamBusy(false);
    }
  }

  function toggleMetric(id: OverlayMetric) {
    const has = ov.metrics.includes(id);
    const metrics = has
      ? ov.metrics.filter((m) => m !== id)
      : [...ov.metrics, id];
    if (metrics.length > MAX_OVERLAY_METRICS) return;
    patch({ metrics });
  }

  const disabled = !ov.enabled;

  return (
    <div className="flex w-full flex-col gap-4 pb-24">
      {/* Console head, overlay state, bound key and payload at a glance. */}
      <Panel
        grid
        aurora
        corners
        live={ov.enabled}
        status={ov.enabled ? "connected" : null}
        anchorId="overlay_enabled"
        eyebrow="In-Game Overlay"
        title={
          <span className="flex items-center gap-2">
            <span className="display-hero">
              {ov.enabled ? "Overlay armed" : "Overlay off"}
            </span>
            <Chip size="xs" tone="accent">
              BETA
            </Chip>
          </span>
        }
        desc="A movable on-screen bar showing live FPS, CPU, RAM, network and more, drawn over the game without touching it (anti-cheat safe)."
        actions={
          <Toggle
            enabled={ov.enabled}
            ariaLabel="In-Game Overlay"
            onChange={(v) => patch({ enabled: v })}
          />
        }
      >
        <StatRail
          items={[
            <Readout
              key="state"
              size="md"
              value={ov.enabled ? "ON" : "OFF"}
              label="State"
              tone={
                ov.enabled ? "var(--color-status-connected)" : undefined
              }
            />,
            <Readout key="hotkey" size="md" value={ov.hotkey} label="Hotkey" />,
            <Readout
              key="metrics"
              size="md"
              value={`${ov.metrics.length}/${MAX_OVERLAY_METRICS}`}
              label="Metrics"
            />,
          ]}
        />
      </Panel>

      <div
        className={disabled ? "pointer-events-none opacity-50" : ""}
        style={{ transition: "opacity 120ms" }}
      >
        {/* Live preview, sunk into the panel face like a screen. */}
        <Panel
          className="mb-4"
          anchorId="overlay_preview"
          eyebrow="Overlay preview"
        >
          <div className="instrument-well flex min-h-[52px] items-center justify-center px-3 py-4">
            <OverlayBar
              metrics={ov.metrics}
              values={OVERLAY_SAMPLE_VALUES}
              size={ov.size}
              color={ov.color}
              style={ov.style}
            />
          </div>
        </Panel>

        {/* Metrics */}
        <Panel
          className="mb-4"
          anchorId="overlay_metrics"
          eyebrow="Metrics"
          title={`${ov.metrics.length} / ${MAX_OVERLAY_METRICS} selected`}
          desc="Pick what to display. Temperatures arrive in a later update."
        >
          <div className="flex flex-col gap-3">
            {OVERLAY_METRIC_GROUPS.map((group) => {
              const items = OVERLAY_METRICS.filter((m) => m.group === group);
              if (items.length === 0) return null;
              return (
                <div key={group}>
                  <h4 className="eyebrow mb-1.5 text-text-secondary">{group}</h4>
                  <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
                    {items.map((m) => {
                      const checked = ov.metrics.includes(m.id);
                      return (
                        <button
                          key={m.id}
                          type="button"
                          onClick={() => toggleMetric(m.id)}
                          className="flex items-center gap-2 rounded-[7px] px-2.5 py-1.5 text-left text-[11.5px] transition-colors"
                          style={{
                            border: `1px solid ${checked ? "var(--color-border-default)" : "var(--color-border-subtle)"}`,
                            backgroundColor: checked
                              ? "var(--color-bg-elevated)"
                              : "transparent",
                          }}
                        >
                          <span
                            className="flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[4px]"
                            style={{
                              border: `1px solid ${checked ? "var(--color-text-primary)" : "var(--color-border-default)"}`,
                              backgroundColor: checked
                                ? "var(--color-text-primary)"
                                : "transparent",
                            }}
                          >
                            {checked && (
                              <svg width="9" height="9" viewBox="0 0 12 12" fill="none">
                                <path
                                  d="M2.5 6.5L5 9l4.5-5.5"
                                  stroke="var(--color-bg-base)"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                />
                              </svg>
                            )}
                          </span>
                          <span className="flex-1 truncate text-text-primary">
                            {m.label}
                          </span>
                          {m.soon && (
                            <span className="text-[8.5px] uppercase tracking-wide text-text-muted">
                              soon
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        {/* Style + Size + Color */}
        <Panel className="mb-4" anchorId="overlay_style" eyebrow="Appearance">
          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <h4 className="eyebrow mb-2 text-text-secondary">Display style</h4>
              <div className="flex gap-1.5">
                {STYLES.map((st) => (
                  <SegBtn
                    key={st.id}
                    active={ov.style === st.id}
                    onClick={() => patch({ style: st.id })}
                  >
                    {st.label}
                  </SegBtn>
                ))}
              </div>
            </div>
            <div>
              <h4 className="eyebrow mb-2 text-text-secondary">Display size</h4>
              <div className="flex gap-1.5">
                {SIZES.map((sz) => (
                  <SegBtn
                    key={sz}
                    active={ov.size === sz}
                    onClick={() => patch({ size: sz })}
                  >
                    {sz[0].toUpperCase() + sz.slice(1)}
                  </SegBtn>
                ))}
              </div>
            </div>
            <div>
              <h4 className="eyebrow mb-2 text-text-secondary">Accent color</h4>
              <div className="flex items-center gap-2">
                {OVERLAY_COLORS.map((c) => (
                  <button
                    key={c}
                    type="button"
                    aria-label={`Color ${c}`}
                    onClick={() => patch({ color: c })}
                    className="h-6 w-6 rounded-full transition-transform hover:scale-110"
                    style={{
                      backgroundColor: c,
                      boxShadow:
                        ov.color === c
                          ? "0 0 0 2px var(--color-bg-elevated), 0 0 0 4px var(--color-text-primary)"
                          : "0 0 0 1px rgba(255,255,255,0.15)",
                    }}
                  />
                ))}
              </div>
            </div>
          </div>
        </Panel>

        {/* Position */}
        <Panel
          className="mb-4"
          anchorId="overlay_position"
          eyebrow="Position"
          desc={
            hasCustomPos
              ? "Custom spot set by dragging in-game. Pick a corner to snap back."
              : "Pick a corner here, or just grab the bar in-game to move it anywhere."
          }
          actions={
            hasCustomPos ? (
              <SegBtn
                active={false}
                onClick={() => patch({ custom_x: null, custom_y: null })}
              >
                Reset
              </SegBtn>
            ) : undefined
          }
        >
          <div className="flex justify-center">
            <div
              className="rounded-xl p-3"
              style={{
                width: 280,
                background: "var(--color-bg-base)",
                border: "1px solid var(--color-border-default)",
              }}
            >
              <div className="grid grid-cols-3 grid-rows-3 gap-1.5" style={{ height: 150 }}>
                {POSITIONS.flat().map((pos) => {
                  const active = !hasCustomPos && ov.position === pos;
                  return (
                    <button
                      key={pos}
                      type="button"
                      aria-label={pos}
                      onClick={() =>
                        patch({ position: pos, custom_x: null, custom_y: null })
                      }
                      className="rounded-md transition-colors"
                      style={{
                        border: `1px dashed ${active ? "transparent" : "var(--color-border-default)"}`,
                        backgroundColor: active
                          ? "var(--color-text-primary)"
                          : "var(--color-bg-elevated)",
                        color: active
                          ? "var(--color-bg-base)"
                          : "var(--color-text-muted)",
                      }}
                    />
                  );
                })}
              </div>
              <div className="mx-auto mt-2 h-1 w-16 rounded-full bg-[color:var(--color-border-default)]" />
            </div>
          </div>
        </Panel>

      </div>

      {/* When my game starts - independent of the overlay master toggle:
          auto-RAM-clean (and its toast) works without the stats HUD. */}
      <Panel
        flush
        className="overflow-hidden"
        anchorId="auto_ram_clean"
        eyebrow="When my game starts"
      >
        <div className="divide-y divide-[color:var(--color-border-subtle)] border-t border-[color:var(--color-border-subtle)]">
          <ToggleRow
            label="Auto-clean RAM on game launch"
            desc="Frees memory when you join a game and shows a 'RAM freed' overlay."
            enabled={config.system_optimization.auto_ram_clean}
            disabled={ramBusy}
            onChange={(v) => void toggleAutoRamClean(v)}
          />
          <ToggleRow
            label="Monitor FPS and keep a session chart"
            desc="Records FPS while you play so you can review it after the game."
            enabled={ov.monitor_fps_chart}
            onChange={(v) => patch({ monitor_fps_chart: v })}
          />
          <ToggleRow
            label="Show max FPS after playing"
            desc="A desktop notification with your session's peak FPS when the game closes."
            enabled={ov.show_max_fps_message}
            onChange={(v) => patch({ show_max_fps_message: v })}
          />
        </div>
      </Panel>
    </div>
  );
}

function SegBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-[7px] px-3 py-1.5 text-[11.5px] font-medium transition-colors"
      style={{
        border: `1px solid ${active ? "var(--color-border-default)" : "var(--color-border-subtle)"}`,
        backgroundColor: active ? "var(--color-bg-elevated)" : "transparent",
        color: active ? "var(--color-text-primary)" : "var(--color-text-muted)",
      }}
    >
      {children}
    </button>
  );
}

function ToggleRow({
  label,
  desc,
  enabled,
  disabled,
  onChange,
}: {
  label: string;
  desc: string;
  enabled: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-2.5">
      <div className="min-w-0">
        <div className="text-[12.5px] font-medium text-text-primary">{label}</div>
        <div className="text-[11px] text-text-muted">{desc}</div>
      </div>
      <Toggle
        enabled={enabled}
        disabled={disabled}
        ariaLabel={label}
        onChange={onChange}
      />
    </div>
  );
}
