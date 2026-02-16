import { useState, useMemo, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useNetworkStore } from "../../stores/networkStore";
import type { PingSample } from "../../lib/types";
import "../connect/connect.css";

const DURATIONS = [5, 10, 30, 300] as const;

type TestStatus = "idle" | "running" | "complete" | "error";

// ── Helpers ──

function qualityColor(q: string): string {
  switch (q.toLowerCase()) {
    case "excellent":
      return "var(--color-latency-excellent)";
    case "good":
      return "var(--color-latency-good)";
    case "fair":
      return "var(--color-latency-fair)";
    case "poor":
      return "var(--color-latency-bad)";
    default:
      return "var(--color-text-muted)";
  }
}

function gradeColor(grade: string): string {
  switch (grade) {
    case "A+":
    case "A":
      return "var(--color-latency-excellent)";
    case "B":
      return "var(--color-latency-good)";
    case "C":
      return "var(--color-latency-fair)";
    case "D":
    case "F":
      return "var(--color-latency-bad)";
    default:
      return "var(--color-text-muted)";
  }
}

// ── Main Component ──

export function NetworkTab() {
  const net = useNetworkStore();
  const [duration, setDuration] = useState<number>(10);

  const anyRunning =
    net.stabilityStatus === "running" ||
    net.speedStatus === "running" ||
    net.bufferbloatStatus === "running";

  function runAll() {
    if (anyRunning) return;
    void net.runStabilityTest(duration);
    void net.runSpeedTest();
    void net.runBufferbloatTest();
  }

  return (
    <div className="connect-tab mx-auto flex w-full max-w-[640px] flex-col gap-5 pb-4">
      {/* ── Run All ── */}
      <button
        onClick={runAll}
        disabled={anyRunning}
        className="group relative w-full overflow-hidden rounded-[var(--radius-card)] border py-3.5 text-sm font-semibold transition-all disabled:opacity-60"
        style={{
          borderColor: anyRunning
            ? "var(--color-border-subtle)"
            : "var(--color-accent-primary)",
          color: anyRunning ? "var(--color-text-muted)" : "white",
          background: anyRunning
            ? "var(--color-bg-card)"
            : "linear-gradient(145deg, #3c82f6, #5a9fff)",
          boxShadow: anyRunning
            ? "none"
            : "0 2px 12px rgba(60,130,246,0.2)",
        }}
      >
        {anyRunning ? (
          <span className="flex items-center justify-center gap-2">
            <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
            Running tests...
          </span>
        ) : (
          "Run All Tests"
        )}
      </button>

      {/* ── Stability Test ── */}
      <TestCard
        title="Stability"
        desc="Ping, jitter, and packet loss"
        icon={
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
          </svg>
        }
        status={net.stabilityStatus}
        error={net.stabilityError}
        onRun={() => net.runStabilityTest(duration)}
        disabled={anyRunning}
        controls={
          <div className="flex items-center gap-1">
            {DURATIONS.map((d) => (
              <button
                key={d}
                onClick={(e) => {
                  e.stopPropagation();
                  setDuration(d);
                }}
                className="rounded px-2 py-0.5 text-[11px] font-medium transition-colors"
                style={{
                  backgroundColor:
                    duration === d
                      ? "var(--color-accent-primary)"
                      : "var(--color-bg-hover)",
                  color:
                    duration === d ? "white" : "var(--color-text-muted)",
                }}
              >
                {d >= 60 ? `${d / 60}min` : `${d}s`}
              </button>
            ))}
          </div>
        }
        result={
          net.stabilityResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              transition={{ duration: 0.25 }}
            >
              <div className="mt-4 border-t border-border-subtle pt-4">
                {/* Quality badge */}
                <div className="mb-3 flex items-center gap-2">
                  <span
                    className="rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
                    style={{
                      backgroundColor: `color-mix(in srgb, ${qualityColor(net.stabilityResult.quality)} 15%, transparent)`,
                      color: qualityColor(net.stabilityResult.quality),
                    }}
                  >
                    {net.stabilityResult.quality}
                  </span>
                  <span className="text-[11px] text-text-muted">
                    {net.stabilityResult.sample_count} samples
                  </span>
                </div>

                {/* Metrics grid */}
                <div
                  className="overflow-hidden rounded-[var(--radius-card)]"
                  style={{ backgroundColor: "var(--color-border-subtle)" }}
                >
                  <div className="grid grid-cols-4 gap-px">
                    <MetricCell
                      label="Avg Ping"
                      value={`${net.stabilityResult.avg_ping.toFixed(1)}`}
                      unit="ms"
                    />
                    <MetricCell
                      label="Min"
                      value={`${net.stabilityResult.min_ping}`}
                      unit="ms"
                    />
                    <MetricCell
                      label="Max"
                      value={`${net.stabilityResult.max_ping}`}
                      unit="ms"
                    />
                    <MetricCell
                      label="Jitter"
                      value={`${net.stabilityResult.jitter.toFixed(1)}`}
                      unit="ms"
                    />
                  </div>
                </div>

                {/* Packet loss bar */}
                <div className="mt-3 flex items-center gap-3">
                  <span className="text-[11px] text-text-muted">Packet Loss</span>
                  <div className="flex-1 overflow-hidden rounded-full" style={{ height: 4, backgroundColor: "var(--color-bg-hover)" }}>
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${Math.max(2, Math.min(100, net.stabilityResult.packet_loss * 20))}%`,
                        backgroundColor:
                          net.stabilityResult.packet_loss === 0
                            ? "var(--color-latency-excellent)"
                            : net.stabilityResult.packet_loss < 1
                              ? "var(--color-latency-good)"
                              : "var(--color-latency-bad)",
                      }}
                    />
                  </div>
                  <span className="connect-data text-[11px] font-medium text-text-primary">
                    {net.stabilityResult.packet_loss.toFixed(1)}%
                  </span>
                </div>

                {/* Ping timeline chart */}
                {net.stabilityResult.ping_samples.length > 0 && (
                  <PingTimeline samples={net.stabilityResult.ping_samples} />
                )}
              </div>
            </motion.div>
          )
        }
      />

      {/* ── Speed Test ── */}
      <TestCard
        title="Speed"
        desc="Download and upload bandwidth"
        icon={
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
          </svg>
        }
        status={net.speedStatus}
        error={net.speedError}
        onRun={() => net.runSpeedTest()}
        disabled={anyRunning}
        result={
          net.speedResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              transition={{ duration: 0.25 }}
            >
              <div className="mt-4 border-t border-border-subtle pt-4">
                <div className="grid grid-cols-2 gap-3">
                  {/* Download */}
                  <div className="rounded-[var(--radius-card)] bg-bg-elevated p-3">
                    <div className="flex items-center gap-1.5">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--color-status-connected)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 5v14M5 12l7 7 7-7" />
                      </svg>
                      <span className="text-[11px] text-text-muted">Download</span>
                    </div>
                    <div className="mt-1 flex items-baseline gap-1">
                      <span
                        className="connect-data text-xl font-bold"
                        style={{ color: "var(--color-status-connected)" }}
                      >
                        {net.speedResult.download_mbps.toFixed(1)}
                      </span>
                      <span className="text-[11px] text-text-muted">Mbps</span>
                    </div>
                  </div>

                  {/* Upload */}
                  <div className="rounded-[var(--radius-card)] bg-bg-elevated p-3">
                    <div className="flex items-center gap-1.5">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--color-accent-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 19V5M5 12l7-7 7 7" />
                      </svg>
                      <span className="text-[11px] text-text-muted">Upload</span>
                    </div>
                    <div className="mt-1 flex items-baseline gap-1">
                      <span
                        className="connect-data text-xl font-bold"
                        style={{ color: "var(--color-accent-cyan)" }}
                      >
                        {net.speedResult.upload_mbps.toFixed(1)}
                      </span>
                      <span className="text-[11px] text-text-muted">Mbps</span>
                    </div>
                  </div>
                </div>

                <div className="mt-2 text-center text-[11px] text-text-muted">
                  {net.speedResult.server}
                </div>
              </div>
            </motion.div>
          )
        }
      />

      {/* ── Bufferbloat Test ── */}
      <TestCard
        title="Bufferbloat"
        desc="Latency under network load"
        icon={
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <path d="M3 9h18M9 21V9" />
          </svg>
        }
        status={net.bufferbloatStatus}
        error={net.bufferbloatError}
        onRun={() => net.runBufferbloatTest()}
        disabled={anyRunning}
        result={
          net.bufferbloatResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              transition={{ duration: 0.25 }}
            >
              <div className="mt-4 border-t border-border-subtle pt-4">
                {/* Grade */}
                <div className="mb-3 flex items-center justify-between">
                  <span className="text-[11px] text-text-muted">Grade</span>
                  <span
                    className="connect-data text-2xl font-bold"
                    style={{ color: gradeColor(net.bufferbloatResult.grade) }}
                  >
                    {net.bufferbloatResult.grade}
                  </span>
                </div>

                {/* Latency comparison */}
                <div
                  className="overflow-hidden rounded-[var(--radius-card)]"
                  style={{ backgroundColor: "var(--color-border-subtle)" }}
                >
                  <div className="grid grid-cols-3 gap-px">
                    <MetricCell
                      label="Idle"
                      value={`${net.bufferbloatResult.idle_latency}`}
                      unit="ms"
                    />
                    <MetricCell
                      label="Under Load"
                      value={`${net.bufferbloatResult.loaded_latency}`}
                      unit="ms"
                    />
                    <MetricCell
                      label="Bloat"
                      value={`+${net.bufferbloatResult.bufferbloat_ms}`}
                      unit="ms"
                      accent={net.bufferbloatResult.bufferbloat_ms > 30}
                    />
                  </div>
                </div>

                {/* Explanation */}
                <p className="mt-2.5 text-[11px] leading-relaxed text-text-muted">
                  {net.bufferbloatResult.bufferbloat_ms <= 5
                    ? "Excellent — virtually no latency increase under load."
                    : net.bufferbloatResult.bufferbloat_ms <= 15
                      ? "Good — minimal latency increase, no impact on gaming."
                      : net.bufferbloatResult.bufferbloat_ms <= 50
                        ? "Fair — noticeable latency increase during heavy network usage."
                        : "Poor — significant latency spikes when network is under load. Consider enabling SQM/QoS on your router."}
                </p>
              </div>
            </motion.div>
          )
        }
      />
    </div>
  );
}

// ── Sub-components ──

function TestCard({
  title,
  desc,
  icon,
  status,
  error,
  onRun,
  disabled,
  controls,
  result,
}: {
  title: string;
  desc: string;
  icon: ReactNode;
  status: TestStatus;
  error: string | null;
  onRun: () => void;
  disabled: boolean;
  controls?: ReactNode;
  result: ReactNode;
}) {
  const isRunning = status === "running";
  const hasResult = status === "complete";

  return (
    <div className="rounded-[var(--radius-card)] border border-border-subtle bg-bg-card p-4">
      {/* Header row */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2.5">
          <div
            className="flex h-7 w-7 items-center justify-center rounded-[6px]"
            style={{
              backgroundColor: "var(--color-bg-hover)",
              color: isRunning
                ? "var(--color-accent-primary)"
                : hasResult
                  ? "var(--color-status-connected)"
                  : "var(--color-text-muted)",
            }}
          >
            {icon}
          </div>
          <div>
            <h3 className="text-sm font-medium text-text-primary">{title}</h3>
            <p className="text-[11px] text-text-muted">{desc}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {controls}
          <button
            onClick={onRun}
            disabled={disabled}
            className="rounded-[var(--radius-button)] px-3 py-1.5 text-[11px] font-medium transition-all disabled:opacity-40"
            style={{
              backgroundColor: isRunning
                ? "var(--color-bg-hover)"
                : "var(--color-accent-primary-soft-12)",
              color: isRunning
                ? "var(--color-text-muted)"
                : "var(--color-accent-secondary)",
            }}
          >
            {isRunning ? (
              <span className="flex items-center gap-1.5">
                <span className="inline-block h-3 w-3 animate-spin rounded-full border-[1.5px] border-current border-t-transparent" />
                Testing
              </span>
            ) : hasResult ? (
              "Rerun"
            ) : (
              "Run"
            )}
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <p className="mt-3 text-xs text-status-error">{error}</p>
      )}

      {/* Results (animated) */}
      <AnimatePresence>{result}</AnimatePresence>
    </div>
  );
}

function PingTimeline({ samples }: { samples: PingSample[] }) {
  const { maxTime, maxPing, yTicks, points, lossPoints } = useMemo(() => {
    const maxT = samples[samples.length - 1]?.elapsed_secs ?? 1;
    let maxP = 0;
    const pts: { x: number; y: number }[] = [];
    const loss: { x: number }[] = [];

    for (const s of samples) {
      if (s.latency_ms != null) {
        if (s.latency_ms > maxP) maxP = s.latency_ms;
        pts.push({ x: s.elapsed_secs, y: s.latency_ms });
      } else {
        loss.push({ x: s.elapsed_secs });
      }
    }

    // Add 20% headroom and round to a nice number
    const raw = Math.max(maxP * 1.2, 10);
    const ceil = raw <= 50 ? Math.ceil(raw / 10) * 10 : Math.ceil(raw / 25) * 25;

    // Generate 3-4 y-axis ticks
    const step = ceil <= 30 ? 10 : ceil <= 100 ? 25 : 50;
    const ticks: number[] = [];
    for (let v = 0; v <= ceil; v += step) ticks.push(v);

    return { maxTime: maxT, maxPing: ceil, yTicks: ticks, points: pts, lossPoints: loss };
  }, [samples]);

  const W = 560;
  const H = 120;
  const PAD_L = 36;
  const PAD_R = 8;
  const PAD_T = 8;
  const PAD_B = 20;
  const plotW = W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;

  const toX = (t: number) => PAD_L + (t / maxTime) * plotW;
  const toY = (ms: number) => PAD_T + plotH - (ms / maxPing) * plotH;

  const linePath =
    points.length > 1
      ? points
          .map((p, i) => `${i === 0 ? "M" : "L"}${toX(p.x).toFixed(1)},${toY(p.y).toFixed(1)}`)
          .join(" ")
      : "";

  // X-axis tick labels (evenly spaced time markers)
  const xTickCount = maxTime > 60 ? 5 : maxTime > 15 ? 4 : 3;
  const xTicks: number[] = [];
  for (let i = 0; i <= xTickCount; i++) {
    xTicks.push((i / xTickCount) * maxTime);
  }

  function formatTime(secs: number): string {
    if (secs >= 60) {
      const m = Math.floor(secs / 60);
      const s = Math.round(secs % 60);
      return s > 0 ? `${m}m${s}s` : `${m}m`;
    }
    return `${Math.round(secs)}s`;
  }

  return (
    <div className="mt-3">
      <div
        className="text-[10px] font-medium uppercase text-text-muted mb-1.5"
        style={{ letterSpacing: "0.06em" }}
      >
        Ping Timeline
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        style={{ display: "block", overflow: "visible" }}
      >
        {/* Grid lines + Y labels */}
        {yTicks.map((v) => (
          <g key={v}>
            <line
              x1={PAD_L}
              x2={W - PAD_R}
              y1={toY(v)}
              y2={toY(v)}
              stroke="var(--color-border-subtle)"
              strokeWidth={0.5}
            />
            <text
              x={PAD_L - 4}
              y={toY(v) + 3}
              textAnchor="end"
              fill="var(--color-text-muted)"
              fontSize={9}
              fontFamily="inherit"
            >
              {v}
            </text>
          </g>
        ))}

        {/* X labels */}
        {xTicks.map((t) => (
          <text
            key={t}
            x={toX(t)}
            y={H - 2}
            textAnchor="middle"
            fill="var(--color-text-muted)"
            fontSize={9}
            fontFamily="inherit"
          >
            {formatTime(t)}
          </text>
        ))}

        {/* Ping line */}
        {linePath && (
          <path
            d={linePath}
            fill="none"
            stroke="var(--color-accent-primary)"
            strokeWidth={1.5}
            strokeLinejoin="round"
          />
        )}

        {/* Packet loss markers (red dots at top) */}
        {lossPoints.map((p, i) => (
          <circle
            key={`loss-${i}`}
            cx={toX(p.x)}
            cy={PAD_T + 3}
            r={3}
            fill="var(--color-latency-bad)"
            opacity={0.8}
          />
        ))}
      </svg>
    </div>
  );
}

function MetricCell({
  label,
  value,
  unit,
  accent,
}: {
  label: string;
  value: string;
  unit: string;
  accent?: boolean;
}) {
  return (
    <div
      className="px-3 py-2.5"
      style={{ backgroundColor: "var(--color-bg-card)" }}
    >
      <div
        className="text-[10px] font-medium uppercase text-text-muted"
        style={{ letterSpacing: "0.06em" }}
      >
        {label}
      </div>
      <div className="mt-0.5 flex items-baseline gap-0.5">
        <span
          className="connect-data text-[13px] font-medium"
          style={{
            color: accent
              ? "var(--color-status-warning)"
              : "var(--color-text-primary)",
          }}
        >
          {value}
        </span>
        <span className="text-[10px] text-text-muted">{unit}</span>
      </div>
    </div>
  );
}
