import { useEffect, useState } from "react";
import { Button, Spinner, Chip } from "../ui";
import { useBoostStore } from "../../stores/boostStore";
import { systemRestartAsAdmin } from "../../lib/commands";
import { notify } from "../../lib/notifications";
import {
  deepCleanLabel,
  formatDeltaMb,
  formatGbFromMb,
  memColor,
} from "./boostConfig";

/** Standalone system-memory cleaner. Lives in the Optimization tab; reads its
 *  state directly from the boost store and owns its restart-as-admin flow so it
 *  can be dropped in as a single element. */
export function MemoryCleaner() {
  const systemMem = useBoostStore((s) => s.systemMem);
  const isCleaning = useBoostStore((s) => s.isCleaningRam);
  const stage = useBoostStore((s) => s.ramCleanStage);
  const trimmedCount = useBoostStore((s) => s.ramCleanTrimmedCount);
  const currentProcess = useBoostStore((s) => s.ramCleanCurrentProcess);
  const result = useBoostStore((s) => s.ramCleanResult);
  const isAdmin = useBoostStore((s) => s.isAdmin);
  const cleanRam = useBoostStore((s) => s.cleanRam);
  const fetchSystemInfo = useBoostStore((s) => s.fetchSystemInfo);

  const [restartState, setRestartState] = useState<
    "idle" | "restarting" | "error"
  >("idle");
  const [restartError, setRestartError] = useState<string | null>(null);

  // Ensure memory stats are present even if the user lands here first.
  useEffect(() => {
    if (!systemMem) void fetchSystemInfo();
  }, [systemMem, fetchSystemInfo]);

  async function onRestartAsAdmin() {
    try {
      setRestartState("restarting");
      setRestartError(null);
      await systemRestartAsAdmin();
    } catch (e) {
      setRestartState("error");
      setRestartError(String(e));
      await notify("Restart canceled", "Could not restart as Administrator.");
    }
  }

  const totalMb = systemMem?.total_mb ?? 0;
  const usedMb = systemMem?.used_mb ?? 0;
  const availableMb = systemMem?.available_mb ?? 0;
  const percent =
    totalMb > 0 ? Math.max(0, Math.min(100, (usedMb / totalMb) * 100)) : 0;
  const color = memColor(percent);
  const showBottom = isCleaning || !isAdmin || result;

  const stateLabel = isCleaning
    ? "Cleaning"
    : percent >= 85
      ? "High usage"
      : percent >= 70
        ? "Elevated"
        : percent > 0
          ? "Healthy"
          : "—";
  const heroLabel = isCleaning ? "Reclaiming" : "System Memory";
  const showLive = !isCleaning && percent >= 85;

  return (
    <section className="flex flex-col gap-3">
      {/* ── Hero ── */}
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card px-5 pt-4 pb-3">
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span
                className="h-2 w-2 rounded-full"
                style={{
                  backgroundColor: color,
                  boxShadow: showLive ? `0 0 6px ${color}` : "none",
                  animation: isCleaning
                    ? "status-breath 1.4s ease-in-out infinite"
                    : "none",
                }}
              />
              <span className="eyebrow">{heroLabel}</span>
              {showLive && (
                <span
                  className="pill-base"
                  style={{
                    backgroundColor: `${color}1a`,
                    color,
                    border: `1px solid ${color}40`,
                  }}
                >
                  Live
                </span>
              )}
            </div>
            <div className="mt-2 flex items-baseline gap-2.5">
              <span
                className="text-[20px] font-semibold leading-none text-text-primary"
                style={{ letterSpacing: "-0.02em" }}
              >
                {stateLabel}
              </span>
              {totalMb > 0 && (
                <span className="font-mono text-[12px] text-text-muted">
                  {formatGbFromMb(usedMb)} / {formatGbFromMb(totalMb)} GB
                </span>
              )}
            </div>
            <div className="mt-3 flex items-baseline gap-1.5">
              {totalMb > 0 ? (
                <>
                  <span
                    className="lcd-readout text-[28px] font-medium leading-none"
                    style={{ color: "var(--color-text-primary)" }}
                  >
                    {percent.toFixed(0)}
                  </span>
                  <span className="text-[12px] text-text-muted">%</span>
                </>
              ) : (
                <span className="text-[12px] text-text-muted">—</span>
              )}
            </div>
          </div>
          <Button
            variant="primary"
            size="lg"
            onClick={() => void cleanRam()}
            disabled={isCleaning}
            loading={isCleaning}
          >
            {isCleaning ? "Cleaning" : "Clean RAM"}
          </Button>
        </div>

        <div
          className="mt-4 h-1.5 overflow-hidden rounded-full"
          style={{ backgroundColor: "rgba(255,255,255,0.04)" }}
        >
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${percent}%`,
              background: `linear-gradient(90deg, ${color}, ${color}cc)`,
              boxShadow: `0 0 8px ${color}40`,
            }}
          />
        </div>
      </div>

      {/* ── Memory detail card ── */}
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card">
        <div className="flex gap-5 px-4 py-3 text-[11px]">
          <MemStat label="Used" value={`${formatGbFromMb(usedMb)} GB`} />
          <MemStat label="Total" value={`${formatGbFromMb(totalMb)} GB`} />
          <MemStat
            label="Available"
            value={`${formatGbFromMb(availableMb)} GB`}
            valueColor={color}
            bold
          />
          {systemMem?.standby_mb != null && (
            <MemStat
              label="Standby"
              value={`${formatGbFromMb(systemMem.standby_mb)} GB`}
            />
          )}
        </div>

        {showBottom && (
          <div
            className="space-y-2 border-t px-4 py-3"
            style={{ borderColor: "var(--color-border-subtle)" }}
          >
            {isCleaning && (
              <div className="flex items-center gap-2 text-[11.5px] text-text-muted">
                <Spinner size={10} color="var(--color-accent-primary)" />
                <span>
                  {stage === "flushing_modified"
                    ? "Flushing modified pages…"
                    : stage === "standby_purge"
                      ? "Purging standby list…"
                      : stage
                        ? stage
                        : "Cleaning…"}
                  {trimmedCount > 0 ? ` · Trimmed: ${trimmedCount}` : ""}
                  {currentProcess ? ` · ${currentProcess}` : ""}
                </span>
              </div>
            )}
            {!isAdmin && (
              <div className="text-[11.5px] text-text-muted">
                Deep clean requires Administrator.{" "}
                <button
                  type="button"
                  onClick={() => void onRestartAsAdmin()}
                  disabled={restartState === "restarting"}
                  className="font-semibold text-accent-secondary hover:underline disabled:opacity-60"
                >
                  {restartState === "restarting"
                    ? "Restarting…"
                    : "Restart as Admin"}
                </button>
                {restartState === "error" && restartError && (
                  <div className="mt-1 text-[11px] text-status-error">
                    {restartError}
                  </div>
                )}
              </div>
            )}
            {result && (
              <div
                className="rounded-[5px] px-3 py-2 text-[11px] text-text-muted"
                style={{ backgroundColor: "var(--color-bg-elevated)" }}
              >
                <div className="flex flex-wrap gap-x-5 gap-y-1">
                  <ResultPill label="Freed" value={formatDeltaMb(result.freed_mb)} />
                  {result.standby_freed_mb != null && (
                    <ResultPill
                      label="Standby"
                      value={formatDeltaMb(result.standby_freed_mb)}
                    />
                  )}
                  {result.modified_freed_mb != null && (
                    <ResultPill
                      label="Modified"
                      value={formatDeltaMb(result.modified_freed_mb)}
                    />
                  )}
                  <ResultPill
                    label="Trimmed"
                    value={String(result.trimmed_count)}
                  />
                  <ResultPill
                    label="Deep clean"
                    value={deepCleanLabel(result.standby_purge)}
                  />
                </div>
                {result.warnings.length > 0 && (
                  <div className="mt-1.5 text-[10.5px] text-status-warning">
                    <Chip tone="warning" size="xs">
                      {result.warnings.length} warning
                      {result.warnings.length !== 1 ? "s" : ""}
                    </Chip>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function MemStat({
  label,
  value,
  valueColor,
  bold,
}: {
  label: string;
  value: string;
  valueColor?: string;
  bold?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <span
        className={`font-mono text-[12px] ${bold ? "font-semibold" : ""}`}
        style={{ color: valueColor || "var(--color-text-primary)" }}
      >
        {value}
      </span>
    </div>
  );
}

function ResultPill({ label, value }: { label: string; value: string }) {
  return (
    <span>
      {label}{" "}
      <span className="font-mono font-medium text-text-primary">{value}</span>
    </span>
  );
}
