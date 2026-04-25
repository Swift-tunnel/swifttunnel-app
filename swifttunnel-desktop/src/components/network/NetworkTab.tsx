import { useMemo, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { useNetworkStore } from "../../stores/networkStore";
import type { PingSample } from "../../lib/types";
import {
  Button,
  Card,
  Chip,
  MetricGrid,
  MetricCell,
} from "../ui";

const DURATIONS = [5, 10, 30, 300] as const;

type TestStatus = "idle" | "running" | "complete" | "error";

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

function gradeName(grade: string): string {
  switch (grade) {
    case "A+":
    case "A":
      return "Excellent";
    case "B":
      return "Good";
    case "C":
      return "Fair";
    case "D":
      return "Poor";
    case "F":
      return "Bad";
    default:
      return "Tested";
  }
}

export function NetworkTab() {
  const net = useNetworkStore();
  const [duration, setDuration] = useState<number>(10);

  const anyRunning =
    net.stabilityStatus === "running" ||
    net.speedStatus === "running" ||
    net.bufferbloatStatus === "running";

  const completedCount =
    Number(net.stabilityStatus === "complete") +
    Number(net.speedStatus === "complete") +
    Number(net.bufferbloatStatus === "complete");

  function runAll() {
    if (anyRunning) return;
    void net.runStabilityTest(duration);
    void net.runSpeedTest();
    void net.runBufferbloatTest();
  }

  const grade = net.bufferbloatResult?.grade ?? null;
  const heroLabel = anyRunning
    ? "Running diagnostics"
    : completedCount === 3
      ? "Diagnostics complete"
      : completedCount > 0
        ? "Partial results"
        : "Diagnostics";
  const heroState = anyRunning
    ? "Measuring"
    : grade
      ? gradeName(grade)
      : completedCount > 0
        ? "Tested"
        : "Ready";
  const heroBigValue = grade ?? (completedCount > 0 ? `${completedCount}` : "—");
  const heroBigColor = grade
    ? gradeColor(grade)
    : "var(--color-text-primary)";
  const heroHint = grade
    ? null
    : completedCount > 0
      ? `/ 3`
      : null;
  const stabilityPingSamples = net.stabilityResult?.ping_samples ?? [];

  return (
    <div className="flex w-full flex-col gap-5 pb-4">
      {/* ── Hero ── */}
      <section className="flex items-start justify-between gap-6 pt-1">
        <div className="min-w-0 flex-1">
          <div className="text-[10.5px] font-semibold uppercase tracking-[0.12em] text-text-muted">
            {heroLabel}
          </div>
          <div className="mt-2.5 flex items-center gap-2.5">
            <span
              className="text-[22px] font-semibold leading-none tracking-[-0.015em]"
              style={{ color: "var(--color-text-primary)" }}
            >
              {heroState}
            </span>
            <span className="font-mono text-[13px] text-text-muted">
              {anyRunning
                ? `${completedCount}/3 done`
                : completedCount === 0
                  ? "no tests run yet"
                  : `${completedCount}/3 tests`}
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-4">
            <div className="flex items-baseline gap-1.5">
              <span
                className="font-mono text-[34px] font-medium leading-none tabular-nums"
                style={{ color: heroBigColor }}
              >
                {heroBigValue}
              </span>
              {heroHint && (
                <span className="text-[13px] text-text-muted">{heroHint}</span>
              )}
            </div>
            {anyRunning && (
              <div className="flex items-center gap-1.5">
                <span
                  className="relative h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: "var(--color-accent-primary)" }}
                >
                  <span
                    className="absolute inset-0 animate-ping rounded-full opacity-60"
                    style={{ backgroundColor: "var(--color-accent-primary)" }}
                  />
                </span>
                <span
                  className="text-[10.5px] font-semibold uppercase tracking-[0.12em]"
                  style={{ color: "var(--color-accent-primary)" }}
                >
                  Live
                </span>
              </div>
            )}
          </div>
        </div>
        <Button
          variant={anyRunning ? "secondary" : "primary"}
          size="lg"
          onClick={runAll}
          disabled={anyRunning}
          loading={anyRunning}
        >
          {anyRunning ? "Running…" : "Run All Tests"}
        </Button>
      </section>

      <TestCard
        title="Stability"
        desc="Ping, jitter, and packet loss over time"
        status={net.stabilityStatus}
        error={net.stabilityError}
        onRun={() => net.runStabilityTest(duration)}
        disabled={anyRunning}
        controls={
          <div className="flex gap-0.5 rounded-[5px] p-0.5" style={{ backgroundColor: "var(--color-bg-elevated)", border: "1px solid var(--color-border-default)" }}>
            {DURATIONS.map((d) => (
              <button
                key={d}
                onClick={(e) => {
                  e.stopPropagation();
                  setDuration(d);
                }}
                className="rounded-[3px] px-2 py-0.5 text-[10.5px] font-medium transition-colors"
                style={{
                  backgroundColor:
                    duration === d ? "var(--color-accent-primary)" : "transparent",
                  color: duration === d ? "#000000" : "var(--color-text-muted)",
                }}
              >
                {d >= 60 ? `${d / 60}m` : `${d}s`}
              </button>
            ))}
          </div>
        }
        result={
          net.stabilityResult && (
            <ResultReveal>
              <div className="mb-3 flex items-center gap-2">
                <Chip
                  tone="custom"
                  color={qualityColor(net.stabilityResult.quality)}
                  uppercase
                >
                  {net.stabilityResult.quality}
                </Chip>
                <span className="font-mono text-[10.5px] text-text-muted">
                  {net.stabilityResult.sample_count} samples
                </span>
              </div>
              <MetricGrid cols={4}>
                <MetricCell
                  label="Avg Ping"
                  value={net.stabilityResult.avg_ping.toFixed(1)}
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
                  value={net.stabilityResult.jitter.toFixed(1)}
                  unit="ms"
                />
              </MetricGrid>
              <div className="mt-3 flex items-center gap-3">
                <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
                  Packet loss
                </span>
                <div
                  className="flex-1 overflow-hidden rounded-full"
                  style={{
                    height: 4,
                    backgroundColor: "var(--color-bg-elevated)",
                  }}
                >
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
                <span className="font-mono text-[11.5px] font-semibold text-text-primary">
                  {net.stabilityResult.packet_loss.toFixed(1)}%
                </span>
              </div>
              {stabilityPingSamples.length > 0 && (
                <PingTimeline samples={stabilityPingSamples} />
              )}
            </ResultReveal>
          )
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <TestCard
          title="Speed"
          desc="Download and upload bandwidth"
          status={net.speedStatus}
          error={net.speedError}
          onRun={() => net.runSpeedTest()}
          disabled={anyRunning}
          result={
            net.speedResult && (
              <ResultReveal>
                <div className="grid grid-cols-2 gap-3">
                  <SpeedCard
                    label="Download"
                    value={net.speedResult.download_mbps.toFixed(1)}
                    color="var(--color-status-connected)"
                    direction="down"
                  />
                  <SpeedCard
                    label="Upload"
                    value={net.speedResult.upload_mbps.toFixed(1)}
                    color="var(--color-text-primary)"
                    direction="up"
                  />
                </div>
                <div className="mt-2 text-center font-mono text-[10.5px] text-text-muted">
                  {net.speedResult.server}
                </div>
              </ResultReveal>
            )
          }
        />

        <TestCard
          title="Bufferbloat"
          desc="Latency under load"
          status={net.bufferbloatStatus}
          error={net.bufferbloatError}
          onRun={() => net.runBufferbloatTest()}
          disabled={anyRunning}
          result={
            net.bufferbloatResult && (
              <ResultReveal>
                <div className="mb-3 flex items-center justify-between">
                  <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
                    Grade
                  </span>
                  <span
                    className="font-mono text-[28px] font-bold leading-none"
                    style={{ color: gradeColor(net.bufferbloatResult.grade) }}
                  >
                    {net.bufferbloatResult.grade}
                  </span>
                </div>
                <MetricGrid cols={3}>
                  <MetricCell
                    label="Idle"
                    value={`${net.bufferbloatResult.idle_latency}`}
                    unit="ms"
                  />
                  <MetricCell
                    label="Load"
                    value={`${net.bufferbloatResult.loaded_latency}`}
                    unit="ms"
                  />
                  <MetricCell
                    label="Bloat"
                    value={`+${net.bufferbloatResult.bufferbloat_ms}`}
                    unit="ms"
                    accent={net.bufferbloatResult.bufferbloat_ms > 30}
                  />
                </MetricGrid>
                <p className="mt-2.5 text-[11px] leading-relaxed text-text-muted">
                  {net.bufferbloatResult.bufferbloat_ms <= 5
                    ? "Excellent — virtually no latency increase under load."
                    : net.bufferbloatResult.bufferbloat_ms <= 15
                      ? "Good — minimal latency increase, no impact on gaming."
                      : net.bufferbloatResult.bufferbloat_ms <= 50
                        ? "Fair — noticeable latency increase during heavy use."
                        : "Poor — significant latency spikes. Consider SQM/QoS on your router."}
                </p>
              </ResultReveal>
            )
          }
        />
      </div>
    </div>
  );
}

// ── Sub-components ──

function ResultReveal({ children }: { children: ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      transition={{ duration: 0.22 }}
    >
      <div
        className="mt-4 border-t pt-4"
        style={{ borderColor: "var(--color-border-subtle)" }}
      >
        {children}
      </div>
    </motion.div>
  );
}

function TestCard({
  title,
  desc,
  status,
  error,
  onRun,
  disabled,
  controls,
  result,
}: {
  title: string;
  desc: string;
  status: TestStatus;
  error: string | null;
  onRun: () => void;
  disabled: boolean;
  controls?: ReactNode;
  result: ReactNode;
}) {
  const isRunning = status === "running";

  return (
    <Card padding="md">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-[13px] font-semibold text-text-primary">
            {title}
          </h3>
          <p className="mt-0.5 text-[11px] text-text-muted">{desc}</p>
        </div>
        <div className="flex items-center gap-2">
          {controls}
          <Button
            size="sm"
            variant={isRunning ? "secondary" : "primary"}
            onClick={onRun}
            disabled={disabled}
            loading={isRunning}
          >
            {isRunning
              ? "Testing"
              : status === "complete"
                ? "Rerun"
                : "Run"}
          </Button>
        </div>
      </div>
      {error && (
        <p className="mt-3 text-[11px] text-status-error">{error}</p>
      )}
      {result}
    </Card>
  );
}

function SpeedCard({
  label,
  value,
  color,
  direction,
}: {
  label: string;
  value: string;
  color: string;
  direction: "up" | "down";
}) {
  return (
    <div
      className="rounded-[var(--radius-card)] p-3"
      style={{
        backgroundColor: "var(--color-bg-elevated)",
        border: "1px solid var(--color-border-subtle)",
      }}
    >
      <div className="flex items-center gap-1.5">
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke={color}
          strokeWidth="2.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          {direction === "down" ? (
            <>
              <path d="M12 5v14" />
              <path d="M5 12l7 7 7-7" />
            </>
          ) : (
            <>
              <path d="M12 19V5" />
              <path d="M5 12l7-7 7 7" />
            </>
          )}
        </svg>
        <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
          {label}
        </span>
      </div>
      <div className="mt-1 flex items-baseline gap-1">
        <span
          className="font-mono text-[22px] font-bold leading-none"
          style={{ color }}
        >
          {value}
        </span>
        <span className="text-[11px] font-medium text-text-muted">Mbps</span>
      </div>
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

    const raw = Math.max(maxP * 1.2, 10);
    const ceil = raw <= 50 ? Math.ceil(raw / 10) * 10 : Math.ceil(raw / 25) * 25;
    const step = ceil <= 30 ? 10 : ceil <= 100 ? 25 : 50;
    const ticks: number[] = [];
    for (let v = 0; v <= ceil; v += step) ticks.push(v);

    return {
      maxTime: maxT,
      maxPing: ceil,
      yTicks: ticks,
      points: pts,
      lossPoints: loss,
    };
  }, [samples]);

  const W = 560,
    H = 120;
  const PAD_L = 36,
    PAD_R = 8,
    PAD_T = 8,
    PAD_B = 20;
  const plotW = W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;

  const toX = (t: number) => PAD_L + (t / maxTime) * plotW;
  const toY = (ms: number) => PAD_T + plotH - (ms / maxPing) * plotH;

  const linePath =
    points.length > 1
      ? points
          .map(
            (p, i) =>
              `${i === 0 ? "M" : "L"}${toX(p.x).toFixed(1)},${toY(p.y).toFixed(1)}`,
          )
          .join(" ")
      : "";

  const xTickCount = maxTime > 60 ? 5 : maxTime > 15 ? 4 : 3;
  const xTicks: number[] = [];
  for (let i = 0; i <= xTickCount; i++)
    xTicks.push((i / xTickCount) * maxTime);

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
      <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        Ping timeline
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        style={{ display: "block", overflow: "visible" }}
      >
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
              fontFamily="Azeret Mono, monospace"
            >
              {v}
            </text>
          </g>
        ))}
        {xTicks.map((t) => (
          <text
            key={t}
            x={toX(t)}
            y={H - 2}
            textAnchor="middle"
            fill="var(--color-text-muted)"
            fontSize={9}
            fontFamily="Azeret Mono, monospace"
          >
            {formatTime(t)}
          </text>
        ))}
        {linePath && (
          <path
            d={linePath}
            fill="none"
            stroke="var(--color-accent-primary)"
            strokeWidth={1.5}
            strokeLinejoin="round"
          />
        )}
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
