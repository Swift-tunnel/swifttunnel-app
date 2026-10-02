import { useEffect, useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { useToastStore } from "../../stores/toastStore";
import { beginRepair, saveRepairRun, useRepairStore } from "../../stores/repairStore";
import { cancelPendingConnectForRepair } from "../../stores/vpnStore";
import { prepareRepair } from "../../lib/repairPreflight";
import { SupportToolsSection } from "../support/SupportToolsSection";
import { RepairGuidance } from "./RepairGuidance";
import { formatErrorMessage } from "../../lib/errors";
import {
  serverGetLatencies,
  serverRefresh,
  systemCheckDriver,
  systemCleanupTunnelState,
  systemGetStartupRegistration,
  systemIsAdmin,
  systemReinstallDriver,
  systemRepairDriver,
  systemRepairNetwork,
  systemRepairStartupRegistration,
  systemRestartAsAdmin,
  systemRestoreStartupRegistration,
  systemRepairWindowsFirewall,
  vpnDisconnect,
  vpnGetDiagnostics,
  vpnGetPing,
  vpnGetState,
  vpnListNetworkAdapters,
} from "../../lib/commands";
import {
  DRIVER_REINSTALL_ISSUE,
  REPAIR_ISSUES,
  formatRepairForSupport,
  runDriverReinstall,
  runRepairIssue,
  statusLabel,
  type RepairCenterDeps,
  type RepairReport,
  type RepairStatus,
} from "../../lib/repairCenter";
import { repairCompletion } from "../../lib/repairCompletion";
import { resetTranslationCache } from "../../lib/i18n";
import type { Config } from "../../lib/types";
import { Button, Spinner, Readout, StatRail, Icon, Watermark } from "../ui";

import { formatRunForSupport, summarizeRepairRun, type RepairItemResult, type RepairRun } from "../../lib/repairRun";


const repairDeps: RepairCenterDeps = {
  now: Date.now,
  boostResetRobloxSettings: () => useSettingsStore.getState().resetRobloxSettings(),
  i18nResetCache: resetTranslationCache,
  overlayResetLayout: async () => {
    const store = useSettingsStore.getState();
    const config: Config = {
      ...store.settings.config,
      overlay: {
        ...store.settings.config.overlay,
        position: "top-left",
        custom_x: null,
        custom_y: null,
        size: "small",
      },
    };
    store.update({ config });
    await store.save(true);
  },
  serverGetLatencies,
  serverRefresh,
  systemCheckDriver,
  systemCleanupTunnelState,
  systemGetStartupRegistration,
  systemIsAdmin,
  systemRepairDriver,
  systemReinstallDriver,
  systemRepairNetwork,
  systemRepairWindowsFirewall,
  systemRepairStartupRegistration,
  systemRestoreStartupRegistration,
  vpnDisconnect,
  vpnGetDiagnostics,
  vpnGetPing,
  vpnGetState,
  vpnListNetworkAdapters,
};

export function RepairTab() {
  const settings = useSettingsStore((s) => s.settings);
  const addToast = useToastStore((s) => s.addToast);

  const { lastRun, running, progress, restarting, reinstalling, reinstallReport, currentStep, error, liveItems } = useRepairStore();
  const [resultOpen, setResultOpen] = useState(true);
  const [elapsed, setElapsed] = useState(0);
  const setRunning = (value: boolean) => useRepairStore.setState({ running: value });
  const setProgress = (value: number) => useRepairStore.setState({ progress: value });
  const setRestarting = (value: boolean) => useRepairStore.setState({ restarting: value });
  const setReinstalling = (value: boolean) => useRepairStore.setState({ reinstalling: value });
  const setReinstallReport = (value: RepairReport | null) => useRepairStore.setState({ reinstallReport: value });

  const busy = running || restarting || reinstalling;
  const total = REPAIR_ISSUES.length;
  useEffect(() => {
    setElapsed(0);
    if (!busy) return;
    const started = Date.now();
    const timer = window.setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [busy, currentStep]);

  async function runFullRepair() {
    if (!beginRepair("repair")) return;
    cancelPendingConnectForRepair();
    setProgress(0);

    const items: RepairItemResult[] = [];
    try {
      await prepareRepair(repairDeps);

      for (const issue of REPAIR_ISSUES) {
        useRepairStore.setState({ currentStep: issue.label });
        const report = await runRepairIssue(issue.id, repairDeps, { settings });
        items.push({
          id: issue.id,
          label: issue.label,
          ...report,
        });
        setProgress(items.length);
        useRepairStore.setState({ liveItems: [...items] });
      }

      const completion = repairCompletion(items);
      const run: RepairRun = {
        overall: completion.status,
        ranAt: Date.now(),
        items,
      };
      saveRepairRun(run);
      setResultOpen(true);

      addToast({ type: completion.type, message: completion.message });
      if (!completion.restart) return;
      setRestarting(true);
      // Let the toast land, then relaunch elevated (Windows shows the admin
      // prompt on the way back up).
      window.setTimeout(() => {
        void systemRestartAsAdmin().catch((error) => {
          setRestarting(false);
          addToast({
            type: "error",
            message: `Couldn't restart automatically, reopen SwiftTunnel to finish. (${formatErrorMessage(
              error,
            )})`,
          });
        });
      }, 1600);
    } catch (error) {
      const message = "Repair stopped: " + formatErrorMessage(error);
      useRepairStore.setState({ error: message });
      saveRepairRun({ overall: "partial", ranAt: Date.now(), items, interrupted: message });
      addToast({ type: "error", message });
    } finally {
      useRepairStore.setState({ currentStep: null });
      setRunning(false);
    }
  }

  async function runReinstallDriver() {
    if (!beginRepair("reinstall")) return;
    cancelPendingConnectForRepair();
    setReinstallReport(null);
    try {
      await prepareRepair(repairDeps);
      useRepairStore.setState({ currentStep: "Reinstalling and verifying the driver" });
      const report = await runDriverReinstall(repairDeps);
      setReinstallReport(report);

      if (report.status === "fixed") {
        addToast({
          type: "success",
          message: "Driver reinstalled, restarting SwiftTunnel…",
        });
        setRestarting(true);
        window.setTimeout(() => {
          void systemRestartAsAdmin().catch((error) => {
            setRestarting(false);
            addToast({
              type: "error",
              message: `Couldn't restart automatically, reopen SwiftTunnel to finish. (${formatErrorMessage(
                error,
              )})`,
            });
          });
        }, 1600);
      } else if (report.status === "needs_reboot") {
        addToast({
          type: "warning",
          message: "Restart Windows to finish the driver reinstall.",
        });
      } else if (report.status === "failed") {
        addToast({
          type: "error",
          message: "Driver reinstall could not complete, details below.",
        });
      }
    } catch (error) {
      const message = "Driver reinstall stopped: " + formatErrorMessage(error);
      useRepairStore.setState({ error: message });
      addToast({ type: "error", message });
    } finally {
      useRepairStore.setState({ currentStep: null });
      setReinstalling(false);
    }
  }

  async function copyReinstallForSupport() {
    if (!reinstallReport) return;
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(
        formatRepairForSupport(DRIVER_REINSTALL_ISSUE, reinstallReport),
      );
      addToast({ type: "success", message: "Reinstall result copied" });
    } catch (error) {
      addToast({
        type: "error",
        message: `Could not copy: ${formatErrorMessage(error)}`,
      });
    }
  }

  async function copyForSupport() {
    if (!lastRun) return;
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(formatRunForSupport(lastRun));
      addToast({ type: "success", message: "Repair result copied" });
    } catch (error) {
      addToast({
        type: "error",
        message: `Could not copy: ${formatErrorMessage(error)}`,
      });
    }
  }

  const buttonLabel = restarting
    ? "Restarting…"
    : running
      ? `Repairing… ${progress}/${total}`
      : "Repair";

  return (
    <div className="flex w-full flex-col gap-4 pb-6">
      {/* ── Hero: one-click repair ── */}
      {/* overflow-clip, not overflow-hidden: the glow below reaches past the
          right edge, and a hidden-overflow box is still scrollable from code.
          Focusing the button scrolled it sideways and cut off the left side
          at narrower window sizes. A clip box cannot scroll at all. */}
      <section
        data-search-anchor="repair_run"
        className="corner-frame relative isolate overflow-clip rounded-[var(--radius-card)] surface-card"
        style={{ padding: "20px 22px" }}
      >
        <Watermark icon="repair" at="bottom-right" size={170} rotate={-18} />
        <div className="aurora" aria-hidden />
        <div className="dot-grid pointer-events-none absolute inset-0 opacity-70" />
        <div className="relative flex items-start justify-between gap-4">
          <div className="min-w-0">
            <span className="eyebrow">Repair Center</span>
            <h2 className="mt-3 text-[24px] font-semibold leading-none text-text-primary">
              Repair
            </h2>
            <p className="mt-2 text-[12.5px] leading-snug text-text-muted">
              Checks common problems and repairs them where possible. Resets SwiftTunnel Roblox tweaks and overlay layout.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void copyForSupport()}
              disabled={!lastRun || busy}
            >
              Copy
            </Button>
            <button
              type="button"
              onClick={() => void runFullRepair()}
              disabled={busy}
              className="repair-cta relative flex items-center overflow-hidden rounded-[10px] px-5 py-2.5 text-[13px] font-semibold transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-75"
              style={{
                background: "linear-gradient(180deg, #ffffff 0%, #e9e9e9 100%)",
                color: "#0a0a0a",
                boxShadow:
                  "inset 0 1px 0 rgba(255,255,255,0.9), 0 2px 10px rgba(0,0,0,0.35)",
              }}
            >
              <span className="relative z-[1] flex items-center gap-2">
                {busy ? (
                  <Spinner size={14} color="#0a0a0a" />
                ) : (
                  <WrenchIcon />
                )}
                {buttonLabel}
              </span>
            </button>
          </div>
        </div>

        {/* Console rail, what the last repair actually did, without opening
            the log. */}
        <StatRail
          className="mt-5"
          items={[
            <Readout
              key="last"
              size="md"
              value={
                lastRun
                  ? new Date(lastRun.ranAt).toLocaleDateString()
                  : "Never"
              }
              label="Last run"
            />,
            <Readout
              key="checks"
              size="md"
              value={lastRun ? String(lastRun.items.length) : "-"}
              label="Checks"
            />,
            <Readout
              key="fixed"
              size="md"
              value={
                lastRun
                  ? String(
                      lastRun.items.filter((i) => i.status === "fixed").length,
                    )
                  : "-"
              }
              label="Fixed"
            />,
          ]}
        />
      </section>

      {error && <div role="alert" className="instrument px-4 py-3 text-[12px] text-status-error break-words">{error}</div>}
      {busy && (
        <section className="instrument px-4 py-3 text-[12px]" role="status" aria-live="polite">
          <p className="font-semibold">{restarting ? "Restarting SwiftTunnel" : currentStep}</p>
          <p className="mt-1 text-text-muted">{elapsed >= 30 ? "This step is taking longer than usual. Wait for its result before trying another repair." : "You can switch tabs. This operation will keep running."}</p>
          {running && <ol className="mt-3 grid gap-1 sm:grid-cols-2">{REPAIR_ISSUES.map((issue, index) => (
            <li key={issue.id} className="flex justify-between gap-2 text-text-muted"><span>{issue.label}</span><span>{liveItems[index] ? statusLabel(liveItems[index].status) : currentStep === issue.label ? "Running" : "Waiting"}</span></li>
          ))}</ol>}
        </section>
      )}
      <RepairGuidance />
      {/* ── Result ── */}
      <section
        className="instrument overflow-hidden"
        style={{ padding: "16px 18px" }}
      >
        <button
          type="button"
          onClick={() => setResultOpen((o) => !o)}
          className="flex w-full items-center justify-between gap-3"
        >
          <span className="flex items-center gap-2">
            <ChevronIcon open={resultOpen} />
            <span className="eyebrow">Last repair</span>
          </span>
          {lastRun && (
            <span className="font-mono text-[10.5px] text-text-dimmed">
              {new Date(lastRun.ranAt).toLocaleString()}
            </span>
          )}
        </button>

        {resultOpen &&
          (!lastRun ? (
          <p className="mt-3 text-[12px] text-text-muted">
            No repair has been run yet. Click Repair to fix common SwiftTunnel
            issues. Only completed changes that need an app restart trigger one.
          </p>
        ) : (
          <>
            <p className="mt-2.5 text-[13px] font-medium text-text-primary">
              {summarizeRepairRun(lastRun)}
            </p>
            <div className="mt-3 overflow-hidden rounded-[10px] border border-[color:var(--color-border-subtle)] divide-y divide-[color:var(--color-border-subtle)]">
              {lastRun.items.map((item) => (
                <div
                  key={item.id}
                  className="flex items-start gap-3 px-3.5 py-2.5"
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-[12px] font-medium text-text-primary">
                      {item.label}
                    </div>
                    <div className="break-words text-[10.5px] leading-snug text-text-muted">
                      {item.summary}
                    </div>
                    {item.nextStep && (
                      <p className="mt-1 break-words text-[11px] text-text-secondary">{item.nextStep}</p>
                    )}
                    {item.entries.length > 0 && (
                      <details className="mt-2 text-[11px] text-text-muted">
                        <summary className="cursor-pointer">Details</summary>
                        <dl className="mt-1 space-y-1">
                          {item.entries.map((entry, index) => (
                            <div key={index} className="break-words">
                              <dt className="inline font-medium">{entry.label}: </dt>
                              <dd className="inline">{entry.value}</dd>
                            </div>
                          ))}
                        </dl>
                      </details>
                    )}
                  </div>
                  <span
                    className="shrink-0 text-[9.5px] font-semibold uppercase tracking-[0.08em]"
                    style={{ color: statusColor(item.status) }}
                  >
                    {statusLabel(item.status)}
                  </span>
                </div>
              ))}
            </div>
          </>
          ))}
      </section>

      {/* ── Advanced: force driver reinstall (never part of Repair-all) ── */}
      <section
        data-search-anchor="driver_reinstall"
        className="instrument overflow-hidden"
        style={{ padding: "16px 18px" }}
      >
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <span className="eyebrow">Advanced</span>
            <h3 className="mt-1.5 text-[14px] font-semibold text-text-primary">
              {DRIVER_REINSTALL_ISSUE.label}
            </h3>
            <p className="mt-1 max-w-[520px] text-[12px] leading-snug text-text-muted">
              {DRIVER_REINSTALL_ISSUE.description}
            </p>
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void runReinstallDriver()}
            disabled={busy}
            loading={reinstalling}
            className="shrink-0"
          >
            {reinstalling ? "Reinstalling…" : "Reinstall driver"}
          </Button>
        </div>

        {reinstallReport && (
          <div
            className="mt-3 rounded-[10px] border px-3.5 py-3"
            style={{ borderColor: "var(--color-border-subtle)" }}
          >
            <div className="flex items-center justify-between gap-3">
              <span className="text-[12.5px] font-medium text-text-primary">
                {reinstallReport.summary}
              </span>
              <span
                className="shrink-0 text-[9.5px] font-semibold uppercase tracking-[0.08em]"
                style={{ color: statusColor(reinstallReport.status) }}
              >
                {statusLabel(reinstallReport.status)}
              </span>
            </div>
            <p className="mt-1 text-[11px] leading-snug text-text-muted">
              {reinstallReport.nextStep}
            </p>
            {reinstallReport.entries.length > 0 && (
              <div className="mt-2.5 flex flex-col gap-1">
                {reinstallReport.entries.map((entry, i) => (
                  <div
                    key={`${entry.label}-${i}`}
                    className="flex items-baseline justify-between gap-3 text-[10.5px]"
                  >
                    <span className="shrink-0 text-text-dimmed">
                      {entry.label}
                    </span>
                    <span
                      className={`truncate text-right ${entry.mono ? "font-mono" : ""}`}
                      style={{
                        color:
                          entry.tone === "bad"
                            ? "var(--color-latency-bad)"
                            : entry.tone === "warn"
                              ? "var(--color-latency-fair)"
                              : "var(--color-text-secondary)",
                      }}
                      title={entry.value}
                    >
                      {entry.value}
                    </span>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-2.5">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => void copyReinstallForSupport()}
              >
                Copy for support
              </Button>
            </div>
          </div>
        )}
      </section>

      <SupportToolsSection />
    </div>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <Icon
      name="chevron-right"
      size={12}
      strokeWidth={2.2}
      style={{
        color: "var(--color-text-muted)",
        transform: open ? "rotate(90deg)" : "none",
        transition: "transform 0.15s ease",
      }}
    />
  );
}

function WrenchIcon() {
  return (
    <Icon name="repair" size={15} strokeWidth={2} style={{ color: "#0a0a0a" }} />
  );
}

// Monochrome status palette, no green, matches the app's white-accent theme.
function statusColor(status: RepairStatus): string {
  switch (status) {
    case "healthy":
    case "checked":
    case "fixed":
      return "var(--color-text-primary)";
    case "partial":
    case "needs_reboot":
      return "var(--color-status-warning)";
    case "failed":
      return "var(--color-status-error)";
    case "unsupported":
    case "not_checked":
      return "var(--color-text-dimmed)";
  }
}
