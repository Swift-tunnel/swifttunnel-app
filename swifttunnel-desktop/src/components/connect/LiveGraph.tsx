import { useId, useMemo } from "react";

export type DataSample = { t: number; up: number; down: number };

/** Cadence at which ConnectTab pushes new samples. */
export const SAMPLE_INTERVAL_MS = 500;

/** Number of samples kept and displayed (60 × 500ms = a 30s window). */
export const MAX_SAMPLES = 60;

/** EMA factor per sample (~2s time constant at the 500ms cadence). */
const EMA_ALPHA = 0.2;

const MIN_Y_MAX_BYTES = 8 * 1024;

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
  if (bytesPerSec < 1024 * 1024)
    return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  if (bytesPerSec < 1024 * 1024 * 1024)
    return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
  return `${(bytesPerSec / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
}

/** Catmull-Rom-style smooth line through the given points. */
function buildLinePath(pts: [number, number][]): string {
  let line = `M${pts[0][0].toFixed(2)},${pts[0][1].toFixed(2)}`;
  if (pts.length > 1) {
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(0, i - 1)];
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const p3 = pts[Math.min(pts.length - 1, i + 2)];
      const t = 0.5;
      const c1x = p1[0] + ((p2[0] - p0[0]) * t) / 6;
      const c1y = p1[1] + ((p2[1] - p0[1]) * t) / 6;
      const c2x = p2[0] - ((p3[0] - p1[0]) * t) / 6;
      const c2y = p2[1] - ((p3[1] - p1[1]) * t) / 6;
      line += ` C${c1x.toFixed(2)},${c1y.toFixed(2)} ${c2x.toFixed(2)},${c2y.toFixed(2)} ${p2[0].toFixed(2)},${p2[1].toFixed(2)}`;
    }
  }
  return line;
}

interface LiveGraphProps {
  samples: DataSample[];
  height?: number;
  lineColor?: string;
  fillColor?: string;
  /** Switch the graph off from its own header. */
  onDisable?: () => void;
}

/**
 * Throughput over the last 30 seconds.
 *
 * Drawn once per sample and never in between. It used to animate every
 * frame (a requestAnimationFrame scroll, a pulsing SVG tip, a pinging dot),
 * which kept WebView2 redrawing at the monitor's refresh rate for as long as
 * the tunnel was up. The SVG pulse even kept going behind a fullscreen game,
 * because pausing CSS animations does not reach SMIL. That is GPU time taken
 * from the game the tunnel is supposed to be helping, so the chart is now a
 * still picture that is replaced twice a second, and only while the window is
 * in front (ConnectTab holds new samples back while it is not).
 */
export function LiveGraph({
  samples,
  height = 160,
  lineColor = "var(--color-text-primary)",
  fillColor = "#ffffff",
  onDisable,
}: LiveGraphProps) {
  const W = 480;
  const H = height;
  const PAD_T = 28;
  const PAD_B = 20;
  const PAD_L = 10;
  const PAD_R = 10;
  const plotW = W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;
  const stepWidth = plotW / (MAX_SAMPLES - 1);

  // Two graphs on screen must not share gradient, clip and mask ids.
  const uid = useId().replace(/:/g, "");
  const fillId = `lg-fill-${uid}`;
  const clipId = `lg-clip-${uid}`;
  const edgeId = `lg-edge-${uid}`;
  const maskId = `lg-mask-${uid}`;

  const smoothed = useMemo(() => {
    if (samples.length === 0) return [] as number[];
    let emaUp = samples[0].up;
    let emaDown = samples[0].down;
    const out: number[] = [];
    for (const s of samples) {
      emaUp = EMA_ALPHA * s.up + (1 - EMA_ALPHA) * emaUp;
      emaDown = EMA_ALPHA * s.down + (1 - EMA_ALPHA) * emaDown;
      out.push(emaUp + emaDown);
    }
    return out;
  }, [samples]);

  const currentRate = smoothed.length > 0 ? smoothed[smoothed.length - 1] : 0;

  const shape = useMemo(() => {
    if (smoothed.length < 2) return null;
    const peak = Math.max(...smoothed);
    // Headroom above the busiest moment in the window, so the line never
    // touches the top edge. It rescales only when that moment changes.
    const yMax = Math.max(MIN_Y_MAX_BYTES, peak * 1.25);
    const N = smoothed.length;
    const pts: [number, number][] = smoothed.map((v, i) => [
      PAD_L + plotW - (N - 1 - i) * stepWidth,
      PAD_T + plotH - (Math.min(v, yMax) / yMax) * plotH,
    ]);
    const line = buildLinePath(pts);
    const bottomY = PAD_T + plotH;
    const rightX = PAD_L + plotW;
    const area = `${line} L${rightX.toFixed(2)},${bottomY.toFixed(2)} L${pts[0][0].toFixed(2)},${bottomY.toFixed(2)} Z`;
    return { line, area, tip: pts[N - 1], peak };
  }, [smoothed, plotW, plotH, stepWidth]);

  if (!shape) {
    return (
      <div
        className="relative flex flex-col justify-between overflow-hidden rounded-[var(--radius-card)] px-4 py-4"
        style={{
          height,
          backgroundColor: "var(--color-bg-card)",
          border: "1px solid var(--color-border-subtle)",
        }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: "var(--color-text-muted)" }}
            />
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-muted">
              Throughput · Live
            </span>
          </div>
          <span className="font-mono text-[10.5px] text-text-dimmed">
            Sampling…
          </span>
        </div>
        <span className="self-center font-mono text-[10px] text-text-dimmed">
          Warming up throughput monitor
        </span>
        <span />
      </div>
    );
  }

  return (
    <div
      className="relative overflow-hidden rounded-[var(--radius-card)]"
      style={{
        backgroundColor: "var(--color-bg-card)",
        border: "1px solid var(--color-border-subtle)",
      }}
    >
      <div className="absolute inset-x-0 top-0 z-10 flex items-center justify-between px-4 py-3">
        <div className="flex items-center gap-1.5">
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{
              backgroundColor: "var(--color-text-primary)",
              boxShadow: "0 0 6px rgba(255, 255, 255, 0.55)",
            }}
          />
          <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-muted">
            Throughput · Live
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[13px] font-semibold text-text-primary">
            {formatRate(currentRate)}
          </span>
          {onDisable && (
            <button
              type="button"
              onClick={onDisable}
              title="Hide the connection graph"
              aria-label="Hide the connection graph"
              className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-muted transition-colors hover:text-text-primary"
            >
              Hide
            </button>
          )}
        </div>
      </div>

      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height={height}
        preserveAspectRatio="none"
        style={{ display: "block" }}
      >
        <defs>
          <linearGradient id={fillId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={fillColor} stopOpacity="0.5" />
            <stop offset="60%" stopColor={fillColor} stopOpacity="0.12" />
            <stop offset="100%" stopColor={fillColor} stopOpacity="0" />
          </linearGradient>
          <clipPath id={clipId}>
            <rect x={PAD_L} y={0} width={plotW} height={H} />
          </clipPath>
          <linearGradient id={edgeId} x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="white" stopOpacity="0" />
            <stop offset="10%" stopColor="white" stopOpacity="1" />
            <stop offset="100%" stopColor="white" stopOpacity="1" />
          </linearGradient>
          <mask id={maskId}>
            <rect
              x={PAD_L}
              y={0}
              width={plotW}
              height={H}
              fill={`url(#${edgeId})`}
            />
          </mask>
        </defs>

        {/* Guide lines */}
        {[0.25, 0.5, 0.75].map((frac) => (
          <line
            key={frac}
            x1={PAD_L}
            x2={W - PAD_R}
            y1={PAD_T + plotH * frac}
            y2={PAD_T + plotH * frac}
            stroke="var(--color-border-subtle)"
            strokeWidth="0.5"
            strokeDasharray="2 4"
            opacity="0.5"
          />
        ))}

        <g clipPath={`url(#${clipId})`} mask={`url(#${maskId})`}>
          <path d={shape.area} fill={`url(#${fillId})`} />
          <path
            d={shape.line}
            fill="none"
            stroke={lineColor}
            strokeWidth="1.75"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <g
            transform={`translate(${shape.tip[0].toFixed(2)}, ${shape.tip[1].toFixed(2)})`}
          >
            <circle r="6" fill={fillColor} opacity="0.18" />
            <circle
              r="2.5"
              fill={fillColor}
              stroke="var(--color-bg-card)"
              strokeWidth="1.5"
            />
          </g>
        </g>
      </svg>

      <div className="pointer-events-none absolute bottom-1.5 left-3 right-3 flex justify-between font-mono text-[9px] text-text-dimmed">
        <span>0</span>
        <span>→ {formatRate(shape.peak)} peak</span>
      </div>
    </div>
  );
}
