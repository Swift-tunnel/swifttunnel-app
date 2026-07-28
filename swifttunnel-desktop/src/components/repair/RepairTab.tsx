import { useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { useToastStore } from "../../stores/toastStore";
import { formatErrorMessage } from "../../lib/errors";
import {
  boostResetRobloxSettings,
  serverGetLatencies,
  serverRefresh,
  systemCheckDriver,
  systemCleanupTunnelState,
  systemCopyLogToClipboard,
  systemGetStartupRegistration,
  systemIsAdmin,
  systemOpenUrl,
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
  type RepairIssueId,
  type RepairReport,
  type RepairStatus,
} from "../../lib/repairCenter";
import { COMMUNITY_URL } from "../../lib/maintenance";
import { resetTranslationCache } from "../../lib/i18n";
import type { Config } from "../../lib/types";
import { Button, Spinner, Readout, StatRail } from "../ui";

const LAST_REPAIR_STORAGE_KEY = "swifttunnel.lastRepairAll.v1";

interface RepairItemResult {
  id: RepairIssueId;
  label: string;
  status: RepairStatus;
  summary: string;
  changed: boolean;
}

interface RepairRun {
  overall: RepairStatus;
  ranAt: number;
  items: RepairItemResult[];
}

const repairDeps: RepairCenterDeps = {
  now: Date.now,
  boostResetRobloxSettings,
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
    await store.save();
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

  // Load the saved result synchronously (not in an effect) so its text is in
  // the DOM on first render, the translation pass runs on tab switch and would
  // otherwise miss late-mounted content, flashing English on every revisit.
  const [lastRun, setLastRun] = useState<RepairRun | null>(() => loadRepairRun());
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [restarting, setRestarting] = useState(false);
  const [resultOpen, setResultOpen] = useState(true);
  const [reinstalling, setReinstalling] = useState(false);
  const [reinstallReport, setReinstallReport] = useState<RepairReport | null>(
    null,
  );

  const busy = running || restarting || reinstalling;
  const total = REPAIR_ISSUES.length;

  async function runFullRepair() {
    if (busy) return;
    setRunning(true);
    setProgress(0);

    const items: RepairItemResult[] = [];
    try {
      // Most repairs (internet recovery especially) need a disconnected
      // tunnel; drop any session first, best-effort.
      await vpnDisconnect().catch(() => {});

      for (const issue of REPAIR_ISSUES) {
        const report = await runRepairIssue(issue.id, repairDeps, { settings });
        items.push({
          id: issue.id,
          label: issue.label,
          status: report.status,
          summary: report.summary,
          changed: report.changed,
        });
        setProgress(items.length);
      }

      const run: RepairRun = {
        overall: aggregateStatus(items.map((i) => i.status)),
        ranAt: Date.now(),
        items,
      };
      saveRepairRun(run);
      setLastRun(run);

      // Nothing was actually changed, don't force a pointless restart + UAC.
      if (!items.some((i) => i.changed)) {
        addToast({
          type: "success",
          message: "Everything looks healthy, nothing needed repair.",
        });
        return;
      }

      addToast({
        type: "success",
        message: "Repairs complete, restarting SwiftTunnel…",
      });
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
    } finally {
      setRunning(false);
    }
  }

  async function runReinstallDriver() {
    if (busy) return;
    setReinstalling(true);
    setReinstallReport(null);
    try {
      // The reinstall needs a torn-down tunnel; drop any session first.
      await vpnDisconnect().catch(() => {});
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
    } finally {
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

  async function copyLog() {
    try {
      await systemCopyLogToClipboard();
      addToast({
        type: "success",
        message: "Log copied, paste it into Discord for support.",
      });
    } catch (error) {
      addToast({
        type: "error",
        message: `Could not copy log: ${formatErrorMessage(error)}`,
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
      <section
        data-search-anchor="repair_run"
        className="corner-frame relative overflow-hidden rounded-[var(--radius-card)] surface-card"
        style={{ padding: "20px 22px" }}
      >
        <div className="aurora" aria-hidden />
        <div className="dot-grid pointer-events-none absolute inset-0 opacity-70" />
        <div className="relative flex items-start justify-between gap-4">
          <div className="min-w-0">
            <span className="eyebrow">Repair Center</span>
            <h2 className="mt-3 text-[24px] font-semibold leading-none text-text-primary">
              Repair
            </h2>
            <p className="mt-2 text-[12.5px] leading-snug text-text-muted">
              Repairs and resets SwiftTunnel completely.
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
              value={lastRun ? String(lastRun.items.length) : "—"}
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
                  : "—"
              }
              label="Fixed"
              tone={
                lastRun?.items.some((i) => i.status === "fixed")
                  ? "var(--color-status-connected)"
                  : undefined
              }
            />,
          ]}
        />
      </section>

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
            issues and restart the app.
          </p>
        ) : (
          <>
            <p className="mt-2.5 text-[13px] font-medium text-text-primary">
              {summarize(lastRun)}
            </p>
            <div className="mt-3 overflow-hidden rounded-[10px] border border-[color:var(--color-border-subtle)] divide-y divide-[color:var(--color-border-subtle)]">
              {lastRun.items.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center gap-3 px-3.5 py-2.5"
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-[12px] font-medium text-text-primary">
                      {item.label}
                    </div>
                    <div className="truncate text-[10.5px] leading-snug text-text-muted">
                      {item.summary}
                    </div>
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
                              : entry.tone === "good"
                                ? "var(--color-latency-excellent)"
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

      {/* ── Still stuck? → support ── */}
      <section
        className="instrument overflow-hidden"
        style={{ padding: "18px 20px" }}
      >
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <h3 className="text-[14px] font-semibold text-text-primary">
              Still have an issue?
            </h3>
            <p className="mt-1 max-w-[520px] text-[12px] leading-snug text-text-muted">
              If SwiftTunnel still isn&apos;t working after a repair, our team
              can help directly on Discord, copy your log first so we can see
              what happened.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => void copyLog()}>
              Copy log
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => void systemOpenUrl(COMMUNITY_URL)}
            >
              Contact support
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-text-muted)"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        transform: open ? "rotate(90deg)" : "none",
        transition: "transform 0.15s ease",
      }}
      aria-hidden
    >
      <path d="M9 6l6 6-6 6" />
    </svg>
  );
}

function aggregateStatus(statuses: RepairStatus[]): RepairStatus {
  if (statuses.includes("failed")) return "failed";
  if (statuses.includes("needs_reboot")) return "needs_reboot";
  if (statuses.includes("partial")) return "partial";
  if (statuses.includes("fixed")) return "fixed";
  return "healthy";
}

function summarize(run: RepairRun): string {
  const count = (set: RepairStatus[]) =>
    run.items.filter((i) => set.includes(i.status)).length;
  const parts: string[] = [];
  const fixed = count(["fixed"]);
  const healthy = count(["healthy", "checked"]);
  const partial = count(["partial"]);
  const reboot = count(["needs_reboot"]);
  const failed = count(["failed"]);
  if (fixed) parts.push(`${fixed} fixed`);
  if (healthy) parts.push(`${healthy} healthy`);
  if (partial) parts.push(`${partial} partial`);
  if (reboot) parts.push(`${reboot} need reboot`);
  if (failed) parts.push(`${failed} failed`);
  return `Ran ${run.items.length} repairs${
    parts.length ? `, ${parts.join(", ")}` : ""
  }.`;
}

function formatRunForSupport(run: RepairRun): string {
  return [
    "SwiftTunnel Repair (all)",
    `Overall: ${statusLabel(run.overall)}`,
    `Last run: ${new Date(run.ranAt).toLocaleString()}`,
    "",
    ...run.items.map(
      (i) => `- ${i.label}: ${statusLabel(i.status)}, ${i.summary}`,
    ),
  ].join("\n");
}

function WrenchIcon() {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      stroke="#0a0a0a"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
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

function saveRepairRun(run: RepairRun) {
  try {
    localStorage.setItem(LAST_REPAIR_STORAGE_KEY, JSON.stringify(run));
  } catch {
    // Non-fatal: the result just won't persist across restarts.
  }
}

function loadRepairRun(): RepairRun | null {
  try {
    const raw = localStorage.getItem(LAST_REPAIR_STORAGE_KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      typeof (parsed as RepairRun).ranAt !== "number" ||
      !Array.isArray((parsed as RepairRun).items)
    ) {
      return null;
    }
    return parsed as RepairRun;
  } catch {
    return null;
  }
}
