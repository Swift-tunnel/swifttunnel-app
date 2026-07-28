import type { ReactNode } from "react";

/* ──────────────────────────────────────────────────────────────────────────
   Telemetry console primitives.

   Every tab is assembled from these, so the app reads as one instrument
   rather than eight separately-styled dashboards. Monochrome by
   construction: `status`/`tone` are the only things that introduce color, and
   only ever from real state, never decoration.
   ────────────────────────────────────────────────────────────────────────── */

export interface PanelProps {
  /** Small uppercase label above the title. */
  eyebrow?: string;
  title?: ReactNode;
  desc?: ReactNode;
  /** Right-aligned header controls. */
  actions?: ReactNode;
  children?: ReactNode;
  /** Faint engineering grid across the panel face. */
  grid?: boolean;
  /** Soft drifting light source behind the panel, for hero surfaces only. */
  aurora?: boolean;
  /** HUD brackets on opposing corners. */
  corners?: boolean;
  /** Slow sweep marking the panel as carrying live data. */
  live?: boolean;
  /** Real state only. */
  status?: "connected" | "error" | null;
  /** Edge-to-edge body, for divided lists. */
  flush?: boolean;
  className?: string;
  /** Deep-link / search target. */
  anchorId?: string;
}

export function Panel({
  eyebrow,
  title,
  desc,
  actions,
  children,
  grid,
  aurora,
  corners,
  live,
  status,
  flush,
  className,
  anchorId,
}: PanelProps) {
  const glow =
    status === "connected"
      ? "glow-connected"
      : status === "error"
        ? "glow-error"
        : "";
  const hasHeader = Boolean(eyebrow || title || actions);

  return (
    <section
      data-search-anchor={anchorId}
      className={`instrument ${corners ? "corner-frame" : ""} ${glow} ${
        className ?? ""
      }`}
    >
      {aurora && (
        <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-[inherit]">
          <div
            className={`aurora ${status === "connected" ? "aurora-live" : ""}`}
            aria-hidden
          />
        </div>
      )}
      {grid && <div className="grid-layer" aria-hidden />}
      {/* The sweep translates past its own bounds, so it needs its own
          clipping box, clipping the panel itself would eat the corner
          brackets, which sit at -1px. */}
      {live && (
        <div
          className="pointer-events-none absolute inset-0 overflow-hidden rounded-[inherit]"
          aria-hidden
        >
          <div className="sweep-layer" />
        </div>
      )}

      <div className="relative">
        {hasHeader && (
          <header className="flex items-start justify-between gap-3 px-4 pb-3 pt-3.5">
            <div className="min-w-0">
              {eyebrow && <div className="eyebrow">{eyebrow}</div>}
              {title && (
                <h3 className="mt-1.5 text-[14px] font-semibold leading-tight text-text-primary">
                  {title}
                </h3>
              )}
              {desc && (
                <p className="mt-1 max-w-[560px] text-[11.5px] leading-snug text-text-muted">
                  {desc}
                </p>
              )}
            </div>
            {actions && (
              <div className="flex shrink-0 items-center gap-2">{actions}</div>
            )}
          </header>
        )}
        <div className={flush ? "" : `px-4 pb-4 ${hasHeader ? "" : "pt-4"}`}>
          {children}
        </div>
      </div>
    </section>
  );
}

export interface ReadoutProps {
  value: ReactNode;
  unit?: string;
  label?: string;
  size?: "md" | "lg" | "xl";
  /** Drive from real state (latency colour, status colour). */
  tone?: string;
  className?: string;
}

export function Readout({
  value,
  unit,
  label,
  size = "lg",
  tone,
  className,
}: ReadoutProps) {
  return (
    <div className={`min-w-0 ${className ?? ""}`}>
      <div className="flex items-baseline gap-1.5">
        <span
          className={`readout readout-${size} truncate`}
          style={tone ? { color: tone } : undefined}
        >
          {value}
        </span>
        {unit && <span className="readout-unit">{unit}</span>}
      </div>
      {label && <div className="eyebrow mt-2">{label}</div>}
    </div>
  );
}

export interface MeterProps {
  /** 0..1; clamped, and NaN-safe so a missing metric renders empty not broken. */
  value: number;
  /** LED-bar look. */
  segments?: boolean;
  tone?: string;
  className?: string;
}

export function Meter({ value, segments, tone, className }: MeterProps) {
  const safe = Number.isFinite(value) ? value : 0;
  const pct = Math.max(0, Math.min(1, safe)) * 100;
  return (
    <div
      className={`meter ${segments ? "meter-segments" : ""} ${className ?? ""}`}
    >
      <div
        className="meter-fill"
        style={{ width: `${pct}%`, ...(tone ? { background: tone } : null) }}
      />
    </div>
  );
}

/** A recessed well of readouts divided by hairlines, the console's stat strip. */
export function StatRail({
  items,
  className,
}: {
  items: ReactNode[];
  className?: string;
}) {
  return (
    <div className={`instrument-well flex items-stretch ${className ?? ""}`}>
      {items.map((item, i) => (
        <div
          key={i}
          className="flex min-w-0 flex-1 items-center px-3.5 py-3"
          style={
            i > 0
              ? { borderLeft: "1px solid var(--color-border-subtle)" }
              : undefined
          }
        >
          {item}
        </div>
      ))}
    </div>
  );
}

/** Gauge bezel ticks. Purely decorative, so it's hidden from assistive tech. */
export function TickRule({ className }: { className?: string }) {
  return <div className={`tick-rule ${className ?? ""}`} aria-hidden />;
}
