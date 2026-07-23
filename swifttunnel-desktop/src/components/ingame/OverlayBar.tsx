import type { ReactElement } from "react";
import type {
  OverlayMetric,
  OverlaySize,
  OverlayStyle,
} from "../../lib/types";
import { metricMeta } from "./overlayMetrics";

interface OverlayBarProps {
  metrics: OverlayMetric[];
  /** Live (or sample) value per metric; missing -> shown as a dash. */
  values: Partial<Record<OverlayMetric, string>>;
  size: OverlaySize;
  color: string;
  style: OverlayStyle;
}

const SIZE_PX: Record<
  OverlaySize,
  { font: number; label: number; padY: number; gap: number }
> = {
  small: { font: 11, label: 9, padY: 5, gap: 9 },
  medium: { font: 13.5, label: 10.5, padY: 6.5, gap: 11 },
  large: { font: 16.5, label: 12.5, padY: 8, gap: 13 },
};

/**
 * The on-screen stats bar. Pure/presentational so it can be used both in the
 * settings preview and in the always-on-top overlay window.
 *
 * "straight" is one continuous HUD bar with hairline-separated metrics;
 * "layered" gives each metric its own chip. Both use uppercase micro-labels +
 * a bold tabular value, with depth (gradient + inset highlight + drop shadow)
 * so they stay legible over any game background.
 */
export function OverlayBar({ metrics, values, size, color, style }: OverlayBarProps) {
  const s = SIZE_PX[size];
  const layered = style === "layered";

  const cell = (m: OverlayMetric): ReactElement | null => {
    const meta = metricMeta(m);
    if (!meta) return null;
    const value = values[m] ?? "--";
    return (
      <span
        key={m}
        className="inline-flex items-baseline gap-1.5 whitespace-nowrap"
        style={
          layered
            ? {
                background:
                  "linear-gradient(180deg, rgba(24,24,26,0.9) 0%, rgba(10,10,11,0.92) 100%)",
                border: "1px solid rgba(255,255,255,0.10)",
                borderRadius: 7,
                padding: `${Math.max(2, s.padY - 2)}px 8px`,
                boxShadow:
                  "0 1px 6px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05)",
              }
            : undefined
        }
      >
        <span
          style={{
            color: "rgba(255,255,255,0.42)",
            fontWeight: 600,
            fontSize: s.label,
            textTransform: "uppercase",
            letterSpacing: "0.045em",
          }}
        >
          {meta.label}
        </span>
        <span style={{ color, fontWeight: 700, letterSpacing: "-0.01em" }}>
          {value}
        </span>
      </span>
    );
  };

  const cells = metrics
    .map((m) => cell(m))
    .filter((el): el is ReactElement => el !== null);

  // In the continuous "straight" bar, hairline-separate metrics for a cleaner
  // HUD read. Layered chips are self-contained, so no dividers there.
  const children =
    layered || cells.length <= 1
      ? cells
      : cells.flatMap((el, i) =>
          i === 0
            ? [el]
            : [
                <span
                  key={`sep-${i}`}
                  aria-hidden="true"
                  style={{
                    width: 1,
                    alignSelf: "stretch",
                    marginTop: 1,
                    marginBottom: 1,
                    background: "rgba(255,255,255,0.12)",
                  }}
                />,
                el,
              ],
        );

  return (
    <div
      className="inline-flex items-center"
      style={{
        gap: s.gap,
        fontSize: s.font,
        lineHeight: 1,
        padding: layered ? 0 : `${s.padY}px ${Math.round(s.gap * 1.15)}px`,
        borderRadius: 9,
        background: layered
          ? "transparent"
          : "linear-gradient(180deg, rgba(22,22,24,0.86) 0%, rgba(9,9,10,0.9) 100%)",
        border: layered ? "none" : "1px solid rgba(255,255,255,0.10)",
        boxShadow: layered
          ? "none"
          : "0 2px 12px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.05)",
        fontVariantNumeric: "tabular-nums",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      }}
    >
      {metrics.length === 0 ? (
        <span style={{ color: "rgba(255,255,255,0.4)", fontSize: s.font }}>
          No metrics selected
        </span>
      ) : (
        children
      )}
    </div>
  );
}
