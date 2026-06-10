import { useEffect, useMemo, useRef } from "react";

export type DataSample = { t: number; up: number; down: number };

/**
 * Cadence at which ConnectTab pushes new samples. The scroll animation is
 * time-based, so a late sample degrades gracefully instead of stuttering.
 */
export const SAMPLE_INTERVAL_MS = 500;

/** Number of samples kept and displayed (60 × 500ms = a 30s window). */
export const MAX_SAMPLES = 60;

/** EMA factor per sample (~2s time constant at the 500ms cadence). */
const EMA_ALPHA = 0.2;

/**
 * Vertical rescale easing per 60fps frame. The scale snaps outward instantly
 * when the line would clip, and eases back down smoothly.
 */
const Y_LERP_PER_FRAME = 0.08;
const REFERENCE_FRAME_MS = 1000 / 60;
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
}

export function LiveGraph({
  samples,
  height = 160,
  lineColor = "var(--color-text-primary)",
  fillColor = "#ffffff",
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

  const scrollRef = useRef<SVGGElement>(null);
  const lineRef = useRef<SVGPathElement>(null);
  const areaRef = useRef<SVGPathElement>(null);
  const tipRef = useRef<SVGGElement>(null);
  const peakRef = useRef<HTMLSpanElement>(null);
  const animYMaxRef = useRef(MIN_Y_MAX_BYTES);
  const peakTextRef = useRef("");

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

  // Latest data for the animation loop, refreshed on every render so the
  // loop itself never has to be re-created when a sample arrives.
  const frameData = useRef({ smoothed, lastSampleT: 0 });
  frameData.current = {
    smoothed,
    lastSampleT: samples.length > 0 ? samples[samples.length - 1].t : 0,
  };

  const active = samples.length >= 2;

  useEffect(() => {
    if (!active) {
      // Fresh session: don't inherit the previous session's scale.
      animYMaxRef.current = MIN_Y_MAX_BYTES;
      peakTextRef.current = "";
      return;
    }
    let raf = 0;
    let lastFrame = performance.now();

    const renderFrame = (nowFrame: number) => {
      const dt = Math.max(0.1, nowFrame - lastFrame);
      lastFrame = nowFrame;
      const { smoothed, lastSampleT } = frameData.current;

      if (smoothed.length >= 2) {
        // Y scale: snap outward so the line never clips, ease back down.
        const target = Math.max(MIN_Y_MAX_BYTES, Math.max(...smoothed) * 1.25);
        let yMax = animYMaxRef.current;
        if (target > yMax) {
          yMax = target;
        } else {
          const f = 1 - Math.pow(1 - Y_LERP_PER_FRAME, dt / REFERENCE_FRAME_MS);
          yMax += (target - yMax) * f;
          if (yMax - target < target * 0.001) yMax = target;
        }
        animYMaxRef.current = yMax;

        const N = smoothed.length;
        const toX = (i: number) => PAD_L + plotW - (N - 1 - i) * stepWidth;
        const toY = (v: number) =>
          PAD_T + plotH - (Math.min(v, yMax) / yMax) * plotH;
        const pts: [number, number][] = smoothed.map((v, i) => [
          toX(i),
          toY(v),
        ]);

        const line = buildLinePath(pts);
        const bottomY = PAD_T + plotH;
        const rightX = PAD_L + plotW;
        const area = `${line} L${rightX.toFixed(2)},${bottomY.toFixed(2)} L${pts[0][0].toFixed(2)},${bottomY.toFixed(2)} Z`;

        lineRef.current?.setAttribute("d", line);
        areaRef.current?.setAttribute("d", area);

        // Time-based scroll: a fresh sample starts one step beyond the right
        // edge of the plot and slides into view over one sample interval.
        const phase = Math.min(
          1,
          Math.max(0, (Date.now() - lastSampleT) / SAMPLE_INTERVAL_MS),
        );
        const offset = (1 - phase) * stepWidth;
        if (scrollRef.current) {
          scrollRef.current.style.transform = `translate3d(${offset}px, 0, 0)`;
        }

        const tip = pts[N - 1];
        tipRef.current?.setAttribute(
          "transform",
          `translate(${tip[0].toFixed(2)}, ${tip[1].toFixed(2)})`,
        );

        const peakText = `→ ${formatRate(yMax)} peak`;
        if (peakText !== peakTextRef.current && peakRef.current) {
          peakTextRef.current = peakText;
          peakRef.current.textContent = peakText;
        }
      }

      raf = requestAnimationFrame(renderFrame);
    };

    raf = requestAnimationFrame(renderFrame);
    return () => cancelAnimationFrame(raf);
  }, [active, plotW, plotH, stepWidth]);

  if (!active) {
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
              className="h-1.5 w-1.5 animate-pulse rounded-full"
              style={{ backgroundColor: "var(--color-text-primary)" }}
            />
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-muted">
              Throughput · Live
            </span>
          </div>
          <span className="font-mono text-[10.5px] text-text-dimmed">
            Sampling…
          </span>
        </div>
        <div className="flex flex-col items-center gap-2 self-center">
          <div
            className="h-8 w-32 rounded"
            style={{
              background:
                "linear-gradient(90deg, transparent, var(--color-bg-elevated), transparent)",
              backgroundSize: "200% 100%",
              animation: "sweep-shine 2s linear infinite",
            }}
          />
          <span className="font-mono text-[10px] text-text-dimmed">
            Warming up throughput monitor
          </span>
        </div>
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
            className="relative h-1.5 w-1.5 rounded-full"
            style={{ backgroundColor: "var(--color-text-primary)" }}
          >
            <span
              className="absolute inset-0 animate-ping rounded-full opacity-60"
              style={{ backgroundColor: "var(--color-text-primary)" }}
            />
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-muted">
            Throughput · Live
          </span>
        </div>
        <span className="font-mono text-[13px] font-semibold text-text-primary">
          {formatRate(currentRate)}
        </span>
      </div>

      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height={height}
        preserveAspectRatio="none"
        style={{ display: "block" }}
      >
        <defs>
          <linearGradient id="lg-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={fillColor} stopOpacity="0.5" />
            <stop offset="60%" stopColor={fillColor} stopOpacity="0.12" />
            <stop offset="100%" stopColor={fillColor} stopOpacity="0" />
          </linearGradient>
          <filter id="lg-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="1.1" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <clipPath id="lg-clip">
            <rect x={PAD_L} y={0} width={plotW} height={H} />
          </clipPath>
          <linearGradient id="lg-edge" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="white" stopOpacity="0" />
            <stop offset="10%" stopColor="white" stopOpacity="1" />
            <stop offset="100%" stopColor="white" stopOpacity="1" />
          </linearGradient>
          <mask id="lg-mask">
            <rect
              x={PAD_L}
              y={0}
              width={plotW}
              height={H}
              fill="url(#lg-edge)"
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

        <g clipPath="url(#lg-clip)" mask="url(#lg-mask)">
          {/* Geometry (path d, tip position, scroll offset) is driven from a
              requestAnimationFrame loop, not React renders, so the chart
              scrolls and rescales continuously between samples. */}
          <g ref={scrollRef} style={{ willChange: "transform" }}>
            <path ref={areaRef} fill="url(#lg-fill)" />
            <path
              ref={lineRef}
              fill="none"
              stroke={lineColor}
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
              filter="url(#lg-glow)"
            />
            <g ref={tipRef}>
              <circle r="4" fill={fillColor} opacity="0.3">
                <animate
                  attributeName="r"
                  values="4;10;4"
                  dur="2s"
                  repeatCount="indefinite"
                />
                <animate
                  attributeName="opacity"
                  values="0.35;0;0.35"
                  dur="2s"
                  repeatCount="indefinite"
                />
              </circle>
              <circle
                r="2.5"
                fill={fillColor}
                stroke="var(--color-bg-card)"
                strokeWidth="1.5"
              />
            </g>
          </g>
        </g>
      </svg>

      <div className="pointer-events-none absolute bottom-1.5 left-3 right-3 flex justify-between font-mono text-[9px] text-text-dimmed">
        <span>0</span>
        <span ref={peakRef} />
      </div>
    </div>
  );
}
