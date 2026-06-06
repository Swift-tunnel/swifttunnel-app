import { type ReactNode, useEffect, useMemo, useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { useToastStore } from "../../stores/toastStore";
import {
  serverGetLatencies,
  serverRefresh,
  systemCheckDriver,
  systemCleanup,
  systemGetStartupRegistration,
  systemIsAdmin,
  systemRepairDriver,
  systemRepairStartupRegistration,
  systemRestoreStartupRegistration,
  vpnDisconnect,
  vpnGetDiagnostics,
  vpnGetPing,
  vpnGetState,
  vpnListNetworkAdapters,
} from "../../lib/commands";
import {
  formatRepairForSupport,
  makeInitialRepairReports,
  REPAIR_ISSUES,
  restoreRepairRollback,
  runRepairIssue,
  statusLabel,
  type RepairCenterDeps,
  type RepairEntry,
  type RepairIssueDefinition,
  type RepairIssueId,
  type RepairReport,
  type RepairStatus,
} from "../../lib/repairCenter";
import { SupportToolsSection } from "../support/SupportToolsSection";
import { Button, SectionHeader } from "../ui";

const LAST_REPAIR_STORAGE_KEY = "swifttunnel.lastRepairResult.v2";

const repairDeps: RepairCenterDeps = {
  now: Date.now,
  serverGetLatencies,
  serverRefresh,
  systemCheckDriver,
  systemCleanup,
  systemGetStartupRegistration,
  systemIsAdmin,
  systemRepairDriver,
  systemRepairStartupRegistration,
  systemRestoreStartupRegistration,
  vpnDisconnect,
  vpnGetDiagnostics,
  vpnGetPing,
  vpnGetState,
  vpnListNetworkAdapters,
};

type SavedRepairResult = {
  issue: RepairIssueId;
  report: RepairReport;
};

export function RepairTab() {
  const settings = useSettingsStore((s) => s.settings);
  const addToast = useToastStore((s) => s.addToast);

  const [selectedIssue, setSelectedIssue] = useState<RepairIssueId>("driver");
  const [reports, setReports] = useState(() => makeInitialRepairReports());
  const [runningIssue, setRunningIssue] = useState<RepairIssueId | null>(null);
  const [reverting, setReverting] = useState(false);

  useEffect(() => {
    const saved = loadSavedRepairResult();
    if (!saved) return;
    setSelectedIssue(saved.issue);
    setReports((current) => ({ ...current, [saved.issue]: saved.report }));
  }, []);

  const selectedMeta = useMemo(
    () =>
      REPAIR_ISSUES.find((issue) => issue.id === selectedIssue) ??
      REPAIR_ISSUES[0],
    [selectedIssue],
  );
  const selectedReport = reports[selectedIssue];
  const running = runningIssue !== null;
  const canRevert =
    Boolean(selectedReport.rollback) &&
    selectedReport.reversible &&
    !running &&
    !reverting;

  function updateReport(issue: RepairIssueId, report: RepairReport) {
    setReports((current) => ({ ...current, [issue]: report }));
    saveRepairResult(issue, report);
  }

  async function runSelectedIssue() {
    if (running) return;
    const issue = selectedIssue;
    setRunningIssue(issue);

    try {
      const report = await runRepairIssue(issue, repairDeps, { settings });
      updateReport(issue, report);
      addToast({
        type: toastType(report.status),
        message: report.summary,
      });
    } finally {
      setRunningIssue(null);
    }
  }

  async function revertSelectedRepair() {
    const rollback = selectedReport.rollback;
    if (!rollback || !canRevert) return;
    setReverting(true);

    try {
      const report = await restoreRepairRollback(repairDeps, rollback);
      updateReport(selectedIssue, report);
      addToast({
        type: toastType(report.status),
        message: report.summary,
      });
    } finally {
      setReverting(false);
    }
  }

  async function copySelectedRepairForSupport() {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(
        formatRepairForSupport(selectedMeta, selectedReport),
      );
      addToast({ type: "success", message: "Repair details copied" });
    } catch (error) {
      addToast({
        type: "error",
        message: `Could not copy repair details: ${String(error)}`,
      });
    }
  }

  return (
    <div className="flex w-full flex-col gap-4 pb-4">
      <section
        className="overflow-hidden rounded-[var(--radius-card)] surface-card"
        style={{ padding: "18px 20px" }}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span
                className="h-2 w-2 rounded-full"
                style={{
                  backgroundColor: statusColor(selectedReport.status),
                  animation:
                    runningIssue === selectedIssue
                      ? "status-breath 1.4s ease-in-out infinite"
                      : "none",
                }}
              />
              <span className="eyebrow">Repair Center</span>
              <StatusPill status={selectedReport.status} />
            </div>
            <h2 className="mt-3 text-[22px] font-semibold leading-none text-text-primary">
              {selectedMeta.label}
            </h2>
            <p className="mt-2 max-w-[620px] text-[12px] leading-snug text-text-muted">
              {selectedMeta.description}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void copySelectedRepairForSupport()}
              disabled={selectedReport.status === "not_checked" || running}
            >
              Copy
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void revertSelectedRepair()}
              disabled={!canRevert}
              loading={reverting}
              title={
                canRevert
                  ? "Restore the exact captured startup registration"
                  : "No exact rollback snapshot is available"
              }
            >
              Revert
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => void runSelectedIssue()}
              disabled={running}
              loading={runningIssue === selectedIssue}
            >
              {selectedMeta.actionLabel}
            </Button>
          </div>
        </div>
      </section>

      <section>
        <SectionHeader label="Checks" />
        <div className="grid grid-cols-3 gap-2">
          {REPAIR_ISSUES.map((issue) => (
            <IssueButton
              key={issue.id}
              issue={issue}
              report={reports[issue.id]}
              selected={selectedIssue === issue.id}
              running={runningIssue === issue.id}
              disabled={running}
              onSelect={() => setSelectedIssue(issue.id)}
            />
          ))}
        </div>
      </section>

      <Section title={`${selectedMeta.label} result`}>
        <div className="grid grid-cols-2 gap-x-4 gap-y-3 px-4 py-3 text-[11px]">
          <RepairItem label="Status" value={statusLabel(selectedReport.status)} />
          <RepairItem
            label="Last run"
            value={
              selectedReport.status === "not_checked"
                ? "not run"
                : new Date(selectedReport.ranAt).toLocaleString()
            }
            mono
          />
          <div className="col-span-2">
            <RepairItem label="Result" value={selectedReport.summary} />
          </div>
          <div className="col-span-2">
            <RepairItem label="Next step" value={selectedReport.nextStep} />
          </div>
          <RepairItem
            label="Changed system"
            value={selectedReport.changed ? "yes" : "no"}
            tone={selectedReport.changed ? "warn" : "default"}
          />
          <RepairItem
            label="Revert available"
            value={canRevert ? "snapshot available" : "no"}
          />
          {selectedReport.entries.map((entry, index) => (
            <div
              key={`${entry.label}-${index}`}
              className={entry.value.length > 42 ? "col-span-2" : undefined}
            >
              <RepairItem
                label={entry.label}
                value={entry.value}
                tone={entry.tone}
                mono={entry.mono}
              />
            </div>
          ))}
        </div>
      </Section>

      <SupportToolsSection />
    </div>
  );
}

function IssueButton({
  issue,
  report,
  selected,
  running,
  disabled,
  onSelect,
}: {
  issue: RepairIssueDefinition;
  report: RepairReport;
  selected: boolean;
  running: boolean;
  disabled: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      disabled={disabled && !selected}
      className="min-h-[78px] rounded-[var(--radius-card)] border px-3 py-2.5 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-55"
      style={{
        backgroundColor: selected
          ? "var(--color-accent-primary-soft-8)"
          : "var(--color-bg-card)",
        borderColor: selected
          ? "var(--color-border-default)"
          : "var(--color-border-subtle)",
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[12px] font-semibold text-text-primary">
            {issue.label}
          </div>
          <div className="mt-1 line-clamp-2 text-[10.5px] leading-snug text-text-muted">
            {report.summary}
          </div>
        </div>
        <span
          className="mt-1 h-2 w-2 shrink-0 rounded-full"
          style={{
            backgroundColor: statusColor(report.status),
            animation: running ? "status-breath 1.4s ease-in-out infinite" : "none",
          }}
        />
      </div>
      <div className="mt-2 flex items-center gap-1.5">
        <span className="pill-base">{issue.actionLabel}</span>
        {issue.systemChanging && (
          <span
            className="pill-base"
            style={{
              backgroundColor: "var(--color-status-warning-soft-10)",
              color: "var(--color-status-warning)",
              border: "1px solid var(--color-status-warning-soft-20)",
            }}
          >
            changes system
          </span>
        )}
      </div>
    </button>
  );
}

function Section({
  title,
  tagElement,
  children,
}: {
  title: string;
  tagElement?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section>
      {tagElement ? (
        <div className="mb-2.5 flex items-center gap-2">
          <h3 className="text-[12.5px] font-semibold text-text-primary">
            {title}
          </h3>
          {tagElement}
        </div>
      ) : (
        <SectionHeader label={title} />
      )}
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card divide-y divide-[color:var(--color-border-subtle)]">
        {children}
      </div>
    </section>
  );
}

function StatusPill({ status }: { status: RepairStatus }) {
  return (
    <span
      className="pill-base"
      style={{
        backgroundColor: statusSoftColor(status),
        color: statusColor(status),
        border: `1px solid ${statusBorderColor(status)}`,
      }}
    >
      {statusLabel(status)}
    </span>
  );
}

function RepairItem({
  label,
  value,
  tone = "default",
  mono,
}: {
  label: string;
  value: string | number | null | undefined;
  tone?: RepairEntry["tone"];
  mono?: boolean;
}) {
  const color =
    tone === "good"
      ? "var(--color-status-connected)"
      : tone === "warn"
        ? "var(--color-status-warning)"
        : tone === "bad"
          ? "var(--color-status-error)"
          : "var(--color-text-primary)";

  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <span
        className={`min-w-0 break-words ${mono ? "font-mono text-[10px]" : "text-[11px]"}`}
        style={{ color }}
      >
        {value ?? "n/a"}
      </span>
    </div>
  );
}

function toastType(status: RepairStatus): "success" | "warning" | "error" {
  if (status === "failed") return "error";
  if (status === "partial" || status === "needs_reboot" || status === "unsupported") {
    return "warning";
  }
  return "success";
}

function statusColor(status: RepairStatus): string {
  switch (status) {
    case "healthy":
    case "checked":
    case "fixed":
      return "var(--color-status-connected)";
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

function statusSoftColor(status: RepairStatus): string {
  switch (status) {
    case "healthy":
    case "checked":
    case "fixed":
      return "var(--color-status-connected-soft-10)";
    case "partial":
    case "needs_reboot":
      return "var(--color-status-warning-soft-10)";
    case "failed":
      return "var(--color-status-error-soft-10)";
    case "unsupported":
    case "not_checked":
      return "var(--color-bg-elevated)";
  }
}

function statusBorderColor(status: RepairStatus): string {
  switch (status) {
    case "healthy":
    case "checked":
    case "fixed":
      return "var(--color-status-connected-soft-20)";
    case "partial":
    case "needs_reboot":
      return "var(--color-status-warning-soft-20)";
    case "failed":
      return "var(--color-status-error-soft-20)";
    case "unsupported":
    case "not_checked":
      return "var(--color-border-subtle)";
  }
}

function saveRepairResult(issue: RepairIssueId, report: RepairReport) {
  localStorage.setItem(
    LAST_REPAIR_STORAGE_KEY,
    JSON.stringify({ issue, report }),
  );
}

function loadSavedRepairResult(): SavedRepairResult | null {
  try {
    const raw = localStorage.getItem(LAST_REPAIR_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SavedRepairResult>;
    if (!parsed.issue || !parsed.report) return null;
    if (!REPAIR_ISSUES.some((issue) => issue.id === parsed.issue)) return null;
    return {
      issue: parsed.issue,
      report: parsed.report,
    };
  } catch {
    return null;
  }
}
