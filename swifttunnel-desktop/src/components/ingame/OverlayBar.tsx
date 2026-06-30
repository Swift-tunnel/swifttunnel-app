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

const SIZE_PX: Record<OverlaySize, { font: number; padY: number; gap: number }> =
  {
    small: { font: 11, padY: 5, gap: 9 },
    medium: { font: 13.5, padY: 6, gap: 11 },
    large: { font: 16.5, padY: 8, gap: 13 },
  };

/**
 * The on-screen stats bar. Pure/presentational so it can be used both in the
 * settings preview and in the always-on-top overlay window. "straight" is one
 * continuous bar; "layered" gives each metric its own chip.
 */
export function OverlayBar({ metrics, values, size, color, style }: OverlayBarProps) {
  const s = SIZE_PX[size];
  const layered = style === "layered";

  const cell = (m: OverlayMetric) => {
    const meta = metricMeta(m);
    if (!meta) return null;
    const value = values[m] ?? "--";
    return (
      <span
        key={m}
        className="inline-flex items-center gap-1 whitespace-nowrap"
        style={
          layered
            ? {
                background: "rgba(255,255,255,0.06)",
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 6,
                padding: `${Math.max(2, s.padY - 3)}px 7px`,
              }
            : undefined
        }
      >
        <span style={{ color: "rgba(255,255,255,0.5)", fontWeight: 500 }}>
          {meta.label}
        </span>
        <span style={{ color, fontWeight: 700 }}>{value}</span>
      </span>
    );
  };

  return (
    <div
      className="inline-flex items-center"
      style={{
        gap: s.gap,
        fontSize: s.font,
        lineHeight: 1,
        padding: layered ? 0 : `${s.padY}px ${s.gap}px`,
        borderRadius: 8,
        background: layered ? "transparent" : "rgba(8,8,8,0.82)",
        border: layered ? "none" : "1px solid rgba(255,255,255,0.08)",
        fontVariantNumeric: "tabular-nums",
        fontFamily:
          "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      }}
    >
      {metrics.length === 0 ? (
        <span style={{ color: "rgba(255,255,255,0.4)", fontSize: s.font }}>
          No metrics selected
        </span>
      ) : (
        metrics.map(cell)
      )}
    </div>
  );
}
