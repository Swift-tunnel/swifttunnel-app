import { SectionHeader, Toggle, Chip } from "../ui";
import { useSettingsStore } from "../../stores/settingsStore";
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
  const ov = config.overlay;
  const hasCustomPos = ov.custom_x !== null && ov.custom_y !== null;

  function patch(p: Partial<OverlayConfig>) {
    const next: Config = { ...config, overlay: { ...ov, ...p } };
    updateSettings({ config: next });
    void saveSettings();
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
      {/* Master toggle + hotkey */}
      <section className="surface-card rounded-[var(--radius-card)] px-4 py-3.5">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <h3 className="text-[13px] font-semibold text-text-primary">
              In-Game Overlay
            </h3>
            <Chip size="xs" tone="accent">
              BETA
            </Chip>
          </div>
          <div className="flex items-center gap-3">
            <span
              className="rounded-[5px] px-2 py-[3px] font-mono text-[10px]"
              style={{
                backgroundColor: "var(--color-bg-elevated)",
                color: "var(--color-text-muted)",
                border: "1px solid var(--color-border-subtle)",
              }}
            >
              {ov.hotkey}
            </span>
            <Toggle
              enabled={ov.enabled}
              ariaLabel="In-Game Overlay"
              onChange={(v) => patch({ enabled: v })}
            />
          </div>
        </div>
        <p className="mt-1 text-[11px] text-text-muted">
          A movable on-screen bar showing live FPS, CPU, RAM, network and more —
          drawn over the game without touching it (anti-cheat safe).
        </p>
      </section>

      <div
        className={disabled ? "pointer-events-none opacity-50" : ""}
        style={{ transition: "opacity 120ms" }}
      >
        {/* Live preview */}
        <section className="surface-card mb-4 rounded-[var(--radius-card)] px-4 py-4">
          <SectionHeader label="Overlay preview" size="sm" />
          <div
            className="flex min-h-[52px] items-center justify-center rounded-lg px-3 py-4"
            style={{ background: "var(--color-bg-base)" }}
          >
            <OverlayBar
              metrics={ov.metrics}
              values={OVERLAY_SAMPLE_VALUES}
              size={ov.size}
              color={ov.color}
              style={ov.style}
            />
          </div>
        </section>

        {/* Metrics */}
        <section className="surface-card mb-4 rounded-[var(--radius-card)] px-4 py-4">
          <SectionHeader
            label="Metrics"
            tag={`${ov.metrics.length} / ${MAX_OVERLAY_METRICS}`}
            description="Pick what to display. FPS and temperatures arrive in a later update."
          />
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
        </section>

        {/* Style + Size + Color */}
        <section className="surface-card mb-4 rounded-[var(--radius-card)] px-4 py-4">
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
        </section>

        {/* Position */}
        <section className="surface-card mb-4 rounded-[var(--radius-card)] px-4 py-4">
          <SectionHeader
            label="Position"
            size="sm"
            description={
              hasCustomPos
                ? "Custom spot set by dragging in-game. Pick a corner to snap back."
                : "Pick a corner here, or just grab the bar in-game to move it anywhere."
            }
            action={
              hasCustomPos ? (
                <SegBtn
                  active={false}
                  onClick={() => patch({ custom_x: null, custom_y: null })}
                >
                  Reset
                </SegBtn>
              ) : undefined
            }
          />
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
                      className="flex items-center justify-center rounded-md text-[8px] font-semibold uppercase tracking-wide transition-colors"
                      style={{
                        border: `1px dashed ${active ? "transparent" : "var(--color-border-default)"}`,
                        backgroundColor: active
                          ? "var(--color-text-primary)"
                          : "var(--color-bg-elevated)",
                        color: active
                          ? "var(--color-bg-base)"
                          : "var(--color-text-muted)",
                      }}
                    >
                      {active ? "INFO" : ""}
                    </button>
                  );
                })}
              </div>
              <div className="mx-auto mt-2 h-1 w-16 rounded-full bg-[color:var(--color-border-default)]" />
            </div>
          </div>
        </section>

        {/* When my game starts */}
        <section className="surface-card overflow-hidden rounded-[var(--radius-card)]">
          <div className="px-4 pb-1 pt-3">
            <h4 className="eyebrow text-text-secondary">When my game starts</h4>
          </div>
          <div className="divide-y divide-[color:var(--color-border-subtle)]">
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
        </section>
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
  onChange,
}: {
  label: string;
  desc: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-2.5">
      <div className="min-w-0">
        <div className="text-[12.5px] font-medium text-text-primary">{label}</div>
        <div className="text-[11px] text-text-muted">{desc}</div>
      </div>
      <Toggle enabled={enabled} ariaLabel={label} onChange={onChange} />
    </div>
  );
}
