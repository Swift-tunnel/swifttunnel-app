import { useEffect, useRef, useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { useToastStore } from "../../stores/toastStore";
import { beginRepair, saveRepairRun, useRepairStore } from "../../stores/repairStore";
import { cancelPendingConnectForRepair, useVpnStore } from "../../stores/vpnStore";
import { useDeepLinkStore } from "../../stores/deepLinkStore";
import { prepareRepair } from "../../lib/repairPreflight";
import { useFocusAwareInterval } from "../../lib/useFocusAwareInterval";
import { SupportToolsSection } from "../support/SupportToolsSection";
import { formatErrorMessage } from "../../lib/errors";
import {
  serverGetLatencies,
  serverRefresh,
  systemCheckDriver,
  systemCleanupTunnelState,
  systemCopyLogToClipboard,
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
import {
  ADVANCED_REPAIRS,
  REPAIR_SYMPTOMS,
  type RepairSymptom,
} from "../../lib/repairSymptoms";
import type { RepairIssueId } from "../../lib/repairResults";
import { resetTranslationCache } from "../../lib/i18n";
import type { Config } from "../../lib/types";
import { Button, Icon, Watermark } from "../ui";

import {
  formatRunForSupport,
  plainRunSummary,
  type RepairItemResult,
  type RepairRun,
} from "../../lib/repairRun";

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

type CopyState =
  | { kind: "idle" }
  | { kind: "copying" }
  | { kind: "done"; ok: boolean; message: string };

const DRIVER_REINSTALL_CONFIRM = "driver_reinstall";

export function RepairTab() {
  const settings = useSettingsStore((s) => s.settings);
  const setTab = useSettingsStore((s) => s.setTab);
  const addToast = useToastStore((s) => s.addToast);

  const { lastRun, running, progress, restarting, reinstalling, reinstallReport, currentStep, error, liveItems, plan } = useRepairStore();
  const [symptomId, setSymptomId] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  // Every repair disconnects first. Say so before the click, not after.
  const tunnelUp = useVpnStore((s) => s.state !== "disconnected" && s.state !== "error");
  // Search can land on the driver reinstall, which sits inside Advanced.
  const linkedAnchor = useDeepLinkStore((s) => s.anchor);
  useEffect(() => {
    if (linkedAnchor === "driver_reinstall") setAdvancedOpen(true);
  }, [linkedAnchor]);
  const [copyState, setCopyState] = useState<CopyState>({ kind: "idle" });
  const [elapsed, setElapsed] = useState(0);
  const setRunning = (value: boolean) => useRepairStore.setState({ running: value });
  const setProgress = (value: number) => useRepairStore.setState({ progress: value });
  const setRestarting = (value: boolean) => useRepairStore.setState({ restarting: value });
  const setReinstalling = (value: boolean) => useRepairStore.setState({ reinstalling: value });
  const setReinstallReport = (value: RepairReport | null) => useRepairStore.setState({ reinstallReport: value });

  const busy = running || restarting || reinstalling;
  const symptom = REPAIR_SYMPTOMS.find((s) => s.id === symptomId) ?? null;
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const stepStartedAt = useRef(0);
  useEffect(() => {
    setElapsed(0);
    stepStartedAt.current = performance.now();
  }, [busy, currentStep]);
  useFocusAwareInterval(() => {
    setElapsed(Math.floor((performance.now() - stepStartedAt.current) / 1000));
  }, 1000, { enabled: busy });

  /** Every repair, whatever started it, goes through the same safeguards:
   *  one run at a time, the tunnel disconnected first, results kept. */
  async function runRepair(scope: string, ids: readonly RepairIssueId[]) {
    if (!beginRepair("repair")) return;
    cancelPendingConnectForRepair();
    setProgress(0);
    setConfirming(null);
    const issues = REPAIR_ISSUES.filter((issue) => ids.includes(issue.id));
    useRepairStore.setState({ plan: issues.map(({ id, label }) => ({ id, label })) });

    const items: RepairItemResult[] = [];
    try {
      await prepareRepair(repairDeps);

      for (const issue of issues) {
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
        scope,
      };
      saveRepairRun(run);

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
      saveRepairRun({ overall: "partial", ranAt: Date.now(), items, interrupted: message, scope });
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
    setConfirming(null);
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

  async function copyText(text: string, done: string) {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(text);
      addToast({ type: "success", message: done });
    } catch (error) {
      addToast({
        type: "error",
        message: `Could not copy: ${formatErrorMessage(error)}`,
      });
    }
  }

  /** Puts the log file itself on the clipboard, so it pastes into a support
   *  chat as an attachment. The result stays on screen, not only in a toast. */
  async function copyDiagnostics() {
    if (copyState.kind === "copying") return;
    setCopyState({ kind: "copying" });
    try {
      await systemCopyLogToClipboard();
      if (!mounted.current) return;
      setCopyState({
        kind: "done",
        ok: true,
        message: "Diagnostics copied. Paste them into your support chat with Ctrl+V.",
      });
    } catch (error) {
      if (!mounted.current) return;
      setCopyState({
        kind: "done",
        ok: false,
        message: `Diagnostics were not copied: ${formatErrorMessage(error)} Use Network diagnostics at the bottom of this page to save a file you can send.`,
      });
    }
  }

  const attention = lastRun?.items.filter(
    (item) => item.nextStep && !["healthy", "checked", "fixed"].includes(item.status),
  ) ?? [];

  return (
    <div className="flex w-full flex-col gap-4 pb-6">
      {/* ── Hero: pick the problem, or send diagnostics ── */}
      {/* overflow-clip, not overflow-hidden: the glow below reaches past the
          right edge, and a hidden-overflow box is still scrollable from code.
          Focusing a button scrolled it sideways and cut off the left side
          at narrower window sizes. A clip box cannot scroll at all. */}
      <section
        data-search-anchor="repair_run"
        className="corner-frame relative isolate overflow-clip rounded-[var(--radius-card)] surface-card"
        style={{ padding: "20px 16px" }}
      >
        <Watermark icon="repair" at="bottom-right" size={170} rotate={-18} />
        <div className="aurora" aria-hidden />
        <div className="dot-grid pointer-events-none absolute inset-0 opacity-70" />
        <div className="relative flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
          <div className="min-w-[220px] flex-1">
            <span className="eyebrow">Repair Center</span>
            <h2 className="mt-3 text-[24px] font-semibold leading-none text-text-primary">
              What's going wrong?
            </h2>
            <p className="mt-2 text-[12.5px] leading-snug text-text-muted">
              Pick the problem. SwiftTunnel suggests the safest fix first.
            </p>
          </div>
          <Button
            variant="secondary"
            size="md"
            onClick={() => void copyDiagnostics()}
            loading={copyState.kind === "copying"}
            disabled={copyState.kind === "copying"}
            leadingIcon={<Icon name="share" size={13} strokeWidth={2} />}
            className="shrink-0"
          >
            Copy diagnostics for support
          </Button>
        </div>
        {copyState.kind === "done" && (
          <p
            role={copyState.ok ? "status" : "alert"}
            className="relative mt-3 flex items-start gap-2 break-words rounded-[10px] border px-3 py-2 text-[12px] leading-snug"
            style={{
              borderColor: "var(--color-border-subtle)",
              color: copyState.ok ? "var(--color-text-primary)" : "var(--color-status-error)",
            }}
          >
            <Icon name={copyState.ok ? "check" : "alert"} size={13} strokeWidth={2.2} className="mt-[2px] shrink-0" />
            <span className="min-w-0">{copyState.message}</span>
          </p>
        )}

        <div
          data-search-anchor="repair_guidance"
          className="relative mt-4 grid gap-2"
          style={{ gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))" }}
        >
          {REPAIR_SYMPTOMS.map((item) => {
            const selected = item.id === symptomId;
            return (
              <button
                key={item.id}
                type="button"
                aria-pressed={selected}
                onClick={() => setSymptomId(selected ? null : item.id)}
                className="flex items-start gap-2.5 rounded-[10px] border px-3 py-2.5 text-left transition-colors duration-100 hover:bg-bg-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-accent-primary)]"
                style={{
                  borderColor: selected ? "var(--color-text-primary)" : "var(--color-border-subtle)",
                  backgroundColor: selected ? "var(--color-bg-elevated)" : undefined,
                }}
              >
                <Icon
                  name={item.icon}
                  size={15}
                  strokeWidth={2}
                  className="mt-[2px] shrink-0"
                  style={{ color: selected ? "var(--color-text-primary)" : "var(--color-text-muted)" }}
                />
                <span className="min-w-0">
                  <span className="block text-[12.5px] font-semibold text-text-primary">{item.title}</span>
                  <span className="mt-0.5 block text-[11px] leading-snug text-text-muted">{item.blurb}</span>
                </span>
              </button>
            );
          })}
        </div>
      </section>

      {symptom && (
        <SymptomPanel
          symptom={symptom}
          busy={busy}
          running={running}
          tunnelUp={tunnelUp}
          onRun={() => void runRepair(symptom.title, symptom.issues)}
          onOpenTab={() => setTab(symptom.tab)}
        />
      )}

      {error && <div role="alert" className="instrument px-4 py-3 text-[12px] text-status-error break-words">{error}</div>}
      {busy && (
        <section className="instrument px-4 py-3 text-[12px]" role="status" aria-live="polite">
          <p className="font-semibold">
            {restarting ? "Restarting SwiftTunnel" : currentStep}
            {running && plan.length > 0 && <span className="ml-2 font-mono text-[10.5px] font-normal text-text-dimmed">{progress}/{plan.length}</span>}
          </p>
          <p className="mt-1 text-text-muted">{elapsed >= 30 ? "This step is taking longer than usual. Wait for its result before trying another repair." : "You can switch tabs. This operation will keep running."}</p>
          {running && <ol className="mt-3 grid gap-x-4 gap-y-1" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>{plan.map((issue, index) => (
            <li key={issue.id} className="flex justify-between gap-2 text-text-muted"><span>{issue.label}</span><span>{liveItems[index] ? statusLabel(liveItems[index].status) : currentStep === issue.label ? "Running" : "Waiting"}</span></li>
          ))}</ol>}
        </section>
      )}

      {/* ── Result ── */}
      <section className="instrument overflow-hidden" style={{ padding: "16px" }}>
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
          <span className="eyebrow">Last result</span>
          {lastRun && (
            <span className="font-mono text-[10.5px] text-text-dimmed">
              {lastRun.scope ? `${lastRun.scope} · ` : ""}{new Date(lastRun.ranAt).toLocaleString()}
            </span>
          )}
        </div>

        {!lastRun ? (
          <p className="mt-3 text-[12px] text-text-muted">
            Nothing has been run yet. Pick a problem above to start.
          </p>
        ) : (
          <>
            <p className="mt-2.5 text-[13px] font-medium text-text-primary">
              {plainRunSummary(lastRun)}
            </p>
            {attention.length > 0 && (
              <ul className="mt-2 space-y-1.5">
                {attention.map((item) => (
                  <li key={item.id} className="flex items-start gap-2 text-[12px] leading-snug text-text-secondary">
                    <Icon name="arrow-right" size={12} strokeWidth={2.2} className="mt-[3px] shrink-0" style={{ color: statusColor(item.status) }} />
                    <span className="min-w-0 break-words"><span className="font-medium text-text-primary">{item.label}: </span>{item.nextStep}</span>
                  </li>
                ))}
              </ul>
            )}
            <details className="mt-3 text-[12px]">
              <summary className="cursor-pointer select-none text-text-muted">Technical details</summary>
              {lastRun.interrupted && <p data-no-translate className="mt-2 break-words text-[11px] text-status-error">{lastRun.interrupted}</p>}
              <div className="mt-2 overflow-hidden rounded-[10px] border border-[color:var(--color-border-subtle)] divide-y divide-[color:var(--color-border-subtle)]">
                {lastRun.items.map((item) => (
                  <div key={item.id} className="flex items-start gap-3 px-3.5 py-2.5">
                    <div className="min-w-0 flex-1">
                      <div className="text-[12px] font-medium text-text-primary">{item.label}</div>
                      <div className="break-words text-[10.5px] leading-snug text-text-muted">{item.summary}</div>
                      {item.entries.length > 0 && (
                        <dl className="mt-1.5 space-y-1 text-[11px] text-text-muted">
                          {item.entries.map((entry, index) => (
                            <div key={index} className="break-words">
                              <dt className="inline font-medium">{entry.label}: </dt>
                              <dd data-no-translate className="inline">{entry.value}</dd>
                            </div>
                          ))}
                        </dl>
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
              <div className="mt-2.5">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={busy}
                  onClick={() => void copyText(formatRunForSupport(lastRun), "Repair result copied")}
                >
                  Copy result as text
                </Button>
              </div>
            </details>
          </>
        )}
      </section>

      {/* ── Advanced: resets and the driver reinstall. Never a first step. ── */}
      <section data-search-anchor="driver_reinstall" className="instrument overflow-hidden" style={{ padding: "16px" }}>
        <details
          open={advancedOpen}
          onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}
        >
          <summary className="cursor-pointer select-none">
            <span className="eyebrow">Advanced</span>
            <span className="ml-2 text-[12px] text-text-muted">Resets and driver reinstall. Use these when support asks, or when the safe fix did not help.</span>
          </summary>
          <div className="mt-3 divide-y divide-[color:var(--color-border-subtle)]">
            {ADVANCED_REPAIRS.map((item) => (
              <AdvancedRow
                key={item.id}
                label={item.label}
                warning={item.warning}
                action={item.action}
                busy={busy}
                confirming={confirming === item.id}
                onAsk={() => setConfirming(item.id)}
                onCancel={() => setConfirming(null)}
                onConfirm={() => void runRepair(item.label, item.issues)}
              />
            ))}
            <AdvancedRow
              label={DRIVER_REINSTALL_ISSUE.label}
              warning={DRIVER_REINSTALL_ISSUE.description}
              action="Reinstall driver"
              busy={busy}
              loading={reinstalling}
              confirming={confirming === DRIVER_REINSTALL_CONFIRM}
              onAsk={() => setConfirming(DRIVER_REINSTALL_CONFIRM)}
              onCancel={() => setConfirming(null)}
              onConfirm={() => void runReinstallDriver()}
            />
          </div>
        </details>

        {reinstallReport && (
          <div
            className="mt-3 rounded-[10px] border px-3.5 py-3"
            style={{ borderColor: "var(--color-border-subtle)" }}
          >
            <div className="flex items-center justify-between gap-3">
              <span className="min-w-0 break-words text-[12.5px] font-medium text-text-primary">
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
              <details className="mt-2 text-[11px] text-text-muted">
                <summary className="cursor-pointer select-none">Technical details</summary>
                <div className="mt-1.5 flex flex-col gap-1">
                  {reinstallReport.entries.map((entry, i) => (
                    <div
                      key={`${entry.label}-${i}`}
                      className="flex items-baseline justify-between gap-3 text-[10.5px]"
                    >
                      <span className="shrink-0 text-text-dimmed">{entry.label}</span>
                      <span
                        data-no-translate
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
              </details>
            )}
            <div className="mt-2.5">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => void copyText(
                  formatRepairForSupport(DRIVER_REINSTALL_ISSUE, reinstallReport),
                  "Reinstall result copied",
                )}
              >
                Copy result as text
              </Button>
            </div>
          </div>
        )}
      </section>

      <SupportToolsSection />
    </div>
  );
}

function SymptomPanel({
  symptom,
  busy,
  running,
  tunnelUp,
  onRun,
  onOpenTab,
}: {
  symptom: RepairSymptom;
  busy: boolean;
  running: boolean;
  tunnelUp: boolean;
  onRun: () => void;
  onOpenTab: () => void;
}) {
  const issues = REPAIR_ISSUES.filter((issue) => symptom.issues.includes(issue.id));
  return (
    <section className="instrument px-4 py-4" aria-label={symptom.title}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3">
        <div className="min-w-[220px] flex-1">
          <span className="eyebrow">Try this first</span>
          <h3 className="mt-1.5 text-[15px] font-semibold text-text-primary">{symptom.title}</h3>
          <p className="mt-1 text-[12px] leading-snug text-text-muted">{symptom.effect}</p>
          {tunnelUp && !busy && (
            <p className="mt-1.5 flex items-start gap-1.5 text-[12px] leading-snug" style={{ color: "var(--color-status-warning)" }}>
              <Icon name="warning" size={13} strokeWidth={2} className="mt-[2px] shrink-0" />
              <span>You are connected. This disconnects you first, so leave your game before you start.</span>
            </p>
          )}
        </div>
        <Button variant="primary" size="md" onClick={onRun} disabled={busy} loading={running} className="shrink-0">
          {running ? "Working…" : symptom.action}
        </Button>
      </div>

      <details className="mt-3 text-[12px]">
        <summary className="cursor-pointer select-none text-text-muted">
          Technical details: the {issues.length === 1 ? "check" : `${issues.length} checks`} this runs
        </summary>
        <ul className="mt-2 space-y-1.5">
          {issues.map((issue) => (
            <li key={issue.id} className="break-words text-[11px] leading-snug text-text-muted">
              <span className="font-medium text-text-secondary">{issue.label}</span>
              {issue.systemChanging ? " (can change Windows settings): " : " (check only): "}
              {issue.description}
            </li>
          ))}
        </ul>
      </details>

      <div className="mt-3 border-t border-[color:var(--color-border-subtle)] pt-3">
        <h4 className="text-[12px] font-semibold text-text-primary">If that does not help</h4>
        <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-[12px] leading-snug text-text-muted">
          {symptom.steps.map((step) => <li key={step}>{step}</li>)}
        </ol>
        <div className="mt-3">
          <Button variant="secondary" size="sm" onClick={onOpenTab}>{symptom.tabAction}</Button>
        </div>
      </div>
    </section>
  );
}

/** A disruptive action never runs on one click: the first click shows what it
 *  costs, the second confirms. */
function AdvancedRow({
  label,
  warning,
  action,
  busy,
  loading = false,
  confirming,
  onAsk,
  onCancel,
  onConfirm,
}: {
  label: string;
  warning: string;
  action: string;
  busy: boolean;
  loading?: boolean;
  confirming: boolean;
  onAsk: () => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 py-3">
      <div className="min-w-[220px] flex-1">
        <h3 className="text-[12.5px] font-semibold text-text-primary">{label}</h3>
        <p className="mt-0.5 text-[11.5px] leading-snug text-text-muted">{warning}</p>
      </div>
      {confirming && !busy ? (
        <div className="flex shrink-0 items-center gap-2" role="group" aria-label={`Confirm: ${label}`}>
          <span className="text-[11.5px] text-text-secondary">Are you sure?</span>
          <Button variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>
          <Button variant="destructive" size="sm" onClick={onConfirm}>Yes, continue</Button>
        </div>
      ) : (
        <Button variant="secondary" size="sm" onClick={onAsk} disabled={busy} loading={loading} className="shrink-0">
          {action}
        </Button>
      )}
    </div>
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
