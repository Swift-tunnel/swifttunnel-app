import { useState } from "react";
import {
  Toggle,
  Chip,
  Panel,
  Readout,
  StatRail,
  Icon,
  ErrorBanner,
} from "../ui";
import { useSettingsStore } from "../../stores/settingsStore";
import {
  OVERLAY_HOTKEY,
  useOverlayRuntimeStore,
} from "../../stores/overlayRuntimeStore";
import { formatErrorMessage } from "../../lib/errors";
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
  supportedOverlayMetrics,
  metricMeta,
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

export function OverlayTab() {
  const config = useSettingsStore((s) => s.settings.config);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const [error, setError] = useState<string | null>(null);
  const runtime = useOverlayRuntimeStore();
  const ov = config.overlay;
  const selectedMetrics = supportedOverlayMetrics(ov.metrics);
  const hasCustomPos = ov.custom_x !== null && ov.custom_y !== null;

  function patch(p: Partial<OverlayConfig>) {
    const current = useSettingsStore.getState().settings.config;
    const next: Config = {
      ...current,
      overlay: { ...current.overlay, ...p, hotkey: OVERLAY_HOTKEY },
    };
    updateSettings({ config: next });
    setError(null);
    void saveSettings(true).catch((e) => setError(formatErrorMessage(e)));
  }

  function toggleMetric(id: OverlayMetric) {
    const has = selectedMetrics.includes(id);
    const metrics = has
      ? selectedMetrics.filter((m) => m !== id)
      : [...selectedMetrics, id];
    if (metrics.length > MAX_OVERLAY_METRICS || (ov.enabled && !metrics.length))
      return;
    patch({ metrics });
  }

  function moveMetric(index: number, direction: number) {
    const next = [...selectedMetrics];
    const target = index + direction;
    if (target < 0 || target >= next.length) return;
    [next[index], next[target]] = [next[target], next[index]];
    patch({ metrics: next });
  }

  return (
    <div className="flex w-full flex-col gap-4 pb-24">
      {/* Console head, overlay state, bound key and payload at a glance. */}
      <Panel
        grid
        aurora
        corners
        anchorId="overlay_enabled"
        watermark={{
          icon: "ingame",
          at: "right",
          size: 180,
          rotate: -6,
          fade: true,
        }}
        eyebrow="Overlay"
        title={
          <span className="flex items-center gap-2">
            <span className="display-hero">
              {ov.enabled ? "Overlay enabled" : "Overlay off"}
            </span>
            <Chip size="xs" tone="accent">
              BETA
            </Chip>
          </span>
        }
        desc="Live FPS, CPU, memory and connection stats over Roblox. Hides when you switch apps."
        actions={
          <Toggle
            enabled={ov.enabled}
            disabled={!ov.enabled && !selectedMetrics.length}
            ariaLabel="Enable overlay"
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
            />,
            <Readout
              key="hotkey"
              size="md"
              value={
                runtime.shortcutAvailable === false
                  ? "Unavailable"
                  : OVERLAY_HOTKEY
              }
              label="Hotkey"
            />,
            <Readout
              key="metrics"
              size="md"
              value={`${selectedMetrics.length}/${MAX_OVERLAY_METRICS}`}
              label="Metrics"
            />,
          ]}
        />
      </Panel>

      {(error || runtime.error) && (
        <ErrorBanner tone="error">{error || runtime.error}</ErrorBanner>
      )}
      {runtime.shortcutAvailable === false && (
        <ErrorBanner tone="warning">
          Ctrl+Shift+O is unavailable. Use the overlay switch above.
        </ErrorBanner>
      )}
      <div>
        {/* Live preview, sunk into the panel face like a screen. */}
        <Panel
          className="mb-4"
          anchorId="overlay_preview"
          eyebrow="Overlay preview"
          actions={
            <span className="font-mono text-[10px] text-text-dimmed">
              SAMPLE VALUES
            </span>
          }
        >
          {/* The bar is as wide as the metric set the user picked, so at 7+
              metrics it outgrows the panel. Scroll it inside the well instead
              of letting it bleed past the panel edge. justify-start once it
              overflows, otherwise centring pushes the leading metric out of
              reach on the left. */}
          <div className="instrument-well overflow-x-auto px-3 py-4">
            <div className="flex w-max min-w-full justify-center">
              <OverlayBar
                metrics={selectedMetrics}
                values={OVERLAY_SAMPLE_VALUES}
                size={ov.size}
                color={ov.color}
                style={ov.style}
              />
            </div>
          </div>
        </Panel>

        {/* Metrics */}
        <Panel
          className="mb-4"
          anchorId="overlay_metrics"
          eyebrow="Metrics"
          title={`${selectedMetrics.length} / ${MAX_OVERLAY_METRICS} selected`}
          desc="Game ping estimates the route to your detected server. Relay measures your connection to SwiftTunnel. Traffic counts the tunnel."
        >
          <div className="flex flex-col gap-3">
            {OVERLAY_METRIC_GROUPS.map((group) => {
              const items = OVERLAY_METRICS.filter(
                (m) => m.group === group && !m.soon,
              );
              if (items.length === 0) return null;
              return (
                <div key={group}>
                  <h4 className="eyebrow mb-1.5 text-text-secondary">
                    {group}
                  </h4>
                  <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
                    {items.map((m) => {
                      const checked = selectedMetrics.includes(m.id);
                      return (
                        <button
                          key={m.id}
                          type="button"
                          aria-pressed={checked}
                          disabled={
                            ov.enabled &&
                            checked &&
                            selectedMetrics.length === 1
                          }
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
                              <Icon
                                name="check"
                                size={9}
                                strokeWidth={3.6}
                                style={{ color: "var(--color-bg-base)" }}
                              />
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
          {!selectedMetrics.length && (
            <p className="mt-3 text-[11.5px] text-text-muted">
              Choose at least one metric to enable the overlay.
            </p>
          )}
          {!!selectedMetrics.length && (
            <div className="mt-4 border-t border-border-subtle pt-3">
              <p className="eyebrow mb-2 text-text-secondary">Display order</p>
              <div className="flex flex-wrap gap-1.5">
                {selectedMetrics.map((id, i) => (
                  <div
                    key={id}
                    className="flex items-center gap-1 rounded-[7px] bg-bg-base px-2 py-1.5"
                  >
                    <span className="mr-1 text-[11px] text-text-secondary">
                      {metricMeta(id)?.label}
                    </span>
                    <button
                      type="button"
                      aria-label={`Move ${metricMeta(id)?.label} left`}
                      disabled={i === 0}
                      onClick={() => moveMetric(i, -1)}
                      className="text-text-muted disabled:opacity-25"
                    >
                      <Icon name="chevron-left" size={11} />
                    </button>
                    <button
                      type="button"
                      aria-label={`Move ${metricMeta(id)?.label} right`}
                      disabled={i === selectedMetrics.length - 1}
                      onClick={() => moveMetric(i, 1)}
                      className="text-text-muted disabled:opacity-25"
                    >
                      <Icon name="chevron-right" size={11} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>

        {/* Style + Size + Color */}
        <Panel className="mb-4" anchorId="overlay_style" eyebrow="Appearance">
          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <h4 className="eyebrow mb-2 text-text-secondary">
                Display style
              </h4>
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
                    aria-pressed={ov.color === c}
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
              : "Pick a position, or unlock the bar to drag it while playing."
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
              <div
                className="grid grid-cols-3 grid-rows-3 gap-1.5"
                style={{ height: 150 }}
              >
                {POSITIONS.flat().map((pos) => {
                  const active = !hasCustomPos && ov.position === pos;
                  return (
                    <button
                      key={pos}
                      type="button"
                      aria-label={pos}
                      aria-pressed={active}
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
          <ToggleRow
            label="Lock overlay position"
            desc="Lets game clicks pass through. Unlock to drag the bar."
            enabled={ov.locked ?? true}
            onChange={(locked) => patch({ locked })}
          />
        </Panel>
      </div>
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
      aria-pressed={active}
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
        <div className="text-[12.5px] font-medium text-text-primary">
          {label}
        </div>
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
