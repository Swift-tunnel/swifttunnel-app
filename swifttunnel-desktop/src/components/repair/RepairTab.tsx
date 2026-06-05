import { type ReactNode, useEffect, useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { useToastStore } from "../../stores/toastStore";
import {
  serverGetLatencies,
  serverRefresh,
  settingsGenerateNetworkDiagnosticsBundle,
  systemCheckDriver,
  systemCleanup,
  systemCopyLogToClipboard,
  systemGetStartupRegistration,
  systemIsAdmin,
  systemOpenUrl,
  systemRepairNetworkCaches,
  systemRestartApp,
  systemRestoreStartupRegistration,
  systemRepairDriver,
  vpnDisconnect,
  vpnGetDiagnostics,
  vpnGetPing,
  vpnGetState,
  vpnListNetworkAdapters,
} from "../../lib/commands";
import type { DiagnosticsResponse, DriverCheckResponse } from "../../lib/types";
import { Button, InfoIcon, Row, SectionHeader, Tooltip } from "../ui";
import type { StartupRegistrationSnapshot } from "../../lib/commands";

const LAST_REPAIR_STORAGE_KEY = "swifttunnel.lastRepairResult.v1";
const MIN_REPAIR_VISIBLE_MS = 1800;

type RepairIssue =
  | "driver"
  | "adapter"
  | "tunnel_cleanup"
  | "route_assist"
  | "roblox"
  | "network_booster"
  | "startup"
  | "relay"
  | "country_bypass"
  | "installer";

type RepairStatus =
  | "not_checked"
  | "running"
  | "fixed"
  | "healthy"
  | "checked"
  | "partial"
  | "needs_admin"
  | "needs_reboot"
  | "failed";

interface RepairEntry {
  label: string;
  value: string;
  tone?: "default" | "good" | "warn" | "bad";
  mono?: boolean;
}

interface RepairReport {
  status: RepairStatus;
  summary: string;
  nextStep: string;
  changed: boolean;
  reversible: boolean;
  ranAt: number | null;
  entries: RepairEntry[];
  rollback?: RepairRollback;
}

type RepairRollback = {
  kind: "startup_registration";
  snapshot: StartupRegistrationSnapshot;
};

const REPAIR_ISSUES: Array<{
  id: RepairIssue;
  label: string;
  desc: string;
}> = [
  {
    id: "driver",
    label: "Split tunnel driver",
    desc: "Fixes WinpkFilter missing, broken, or unavailable driver installs",
  },
  {
    id: "adapter",
    label: "Adapter routing",
    desc: "Checks selected adapter, route binding, and packet counters",
  },
  {
    id: "tunnel_cleanup",
    label: "Tunnel cleanup",
    desc: "Checks tunnel state and only clears stale helper state when needed",
  },
  {
    id: "route_assist",
    label: "Route Assist",
    desc: "Checks API tunneling state for browser login and Roblox web traffic",
  },
  {
    id: "roblox",
    label: "Roblox settings",
    desc: "Checks saved Roblox boost settings without changing them",
  },
  {
    id: "network_booster",
    label: "Network booster",
    desc: "Checks saved network boost settings without changing them",
  },
  {
    id: "startup",
    label: "Startup login",
    desc: "Re-saves startup configuration for Windows sign-in launch issues",
  },
  {
    id: "relay",
    label: "Relay latency",
    desc: "Refreshes relays and checks current tunnel ping data",
  },
  {
    id: "country_bypass",
    label: "Country bypass",
    desc: "Checks local DPI bypass settings without touching Route Assist",
  },
  {
    id: "installer",
    label: "Installer/update",
    desc: "Collects installer/update support data for MSI and first-run issues",
  },
];

const DEFAULT_REPORT: RepairReport = {
  status: "not_checked",
  summary: "No repair has been run for this issue yet.",
  nextStep: "Choose an issue type, then click Run repair.",
  changed: false,
  reversible: false,
  ranAt: null,
  entries: [],
};

function makeInitialReports(): Record<RepairIssue, RepairReport> {
  return REPAIR_ISSUES.reduce(
    (acc, issue) => {
      acc[issue.id] = DEFAULT_REPORT;
      return acc;
    },
    {} as Record<RepairIssue, RepairReport>,
  );
}

export function RepairTab() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const setTab = useSettingsStore((s) => s.setTab);
  const addToast = useToastStore((s) => s.addToast);

  const [selectedIssue, setSelectedIssue] = useState<RepairIssue>("driver");
  const [reports, setReports] =
    useState<Record<RepairIssue, RepairReport>>(makeInitialReports);
  const [running, setRunning] = useState(false);
  const [reverting, setReverting] = useState(false);
  const [isGeneratingDiagnostics, setIsGeneratingDiagnostics] = useState(false);
  const [diagnosticsPath, setDiagnosticsPath] = useState<string | null>(null);
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);
  const [isCopyingLog, setIsCopyingLog] = useState(false);
  const [copyLogPath, setCopyLogPath] = useState<string | null>(null);
  const [copyLogError, setCopyLogError] = useState<string | null>(null);

  const selectedMeta =
    REPAIR_ISSUES.find((issue) => issue.id === selectedIssue) ??
    REPAIR_ISSUES[0];
  const selectedReport = reports[selectedIssue] ?? DEFAULT_REPORT;
  const canRevert =
    selectedReport.reversible &&
    selectedReport.rollback !== undefined &&
    !running &&
    !reverting;

  useEffect(() => {
    const saved = loadSavedRepairResult();
    if (!saved) return;
    setSelectedIssue(saved.issue);
    setReports((current) => ({ ...current, [saved.issue]: saved.report }));
  }, []);

  function setReport(issue: RepairIssue, report: RepairReport) {
    setReports((current) => ({ ...current, [issue]: report }));
  }

  async function runRepair() {
    const issue = selectedIssue;
    const startedAt = Date.now();
    setRunning(true);
    // Intentionally do NOT overwrite the report with a "running" placeholder.
    // The Run button itself shows the running state — the diagnostics card
    // below keeps showing the previous result until the new one lands so
    // there is only ever one loading indicator on screen.

    try {
      const report = await runRepairForIssue(issue);
      await waitForMinimumDuration(startedAt, MIN_REPAIR_VISIBLE_MS);
      setReport(issue, report);
      saveRepairResult(issue, report);
      addToast({
        type:
          report.status === "failed" ||
          report.status === "needs_admin" ||
          report.status === "needs_reboot"
            ? "warning"
            : "success",
        message: report.summary,
      });
      setTab("repair");
      await saveSettings();
      await waitForMinimumDuration(Date.now(), 650);
      // The backend exits the process inside system_restart_app, so this
      // promise normally never resolves (the renderer is killed). Race it
      // against a 5s deadline so a wedged restart helper cannot lock the
      // UI on "Running repair..." forever — if we are still here after 5s,
      // surface the error and fall through to the finally that clears
      // setRunning so the user regains control.
      try {
        await Promise.race([
          systemRestartApp(),
          new Promise<never>((_, reject) =>
            setTimeout(
              () => reject(new Error("Restart timed out after 5s")),
              5000,
            ),
          ),
        ]);
      } catch {
        // Repair itself succeeded — only the restart failed. Tell the user
        // to restart manually, but DO NOT re-throw: that would fall into
        // the outer catch and overwrite the successful repair report with
        // "Repair failed".
        addToast({
          type: "warning",
          message:
            "Repair finished but the app could not restart automatically. Close and reopen SwiftTunnel to apply.",
        });
      }
    } catch (error) {
      await waitForMinimumDuration(startedAt, MIN_REPAIR_VISIBLE_MS);
      const report: RepairReport = {
        status: "failed",
        summary: "Repair failed",
        nextStep: "Copy the log file or generate diagnostics for support.",
        changed: false,
        reversible: false,
        ranAt: Date.now(),
        entries: [{ label: "Error", value: String(error), tone: "bad" }],
      };
      setReport(issue, report);
      saveRepairResult(issue, report);
      addToast({ type: "error", message: "Repair failed" });
    } finally {
      setRunning(false);
    }
  }

  async function revertLastRepair() {
    if (!canRevert) return;
    setReverting(true);
    try {
      const restored = await restoreRepairRollback(selectedReport.rollback!);
      const report: RepairReport = {
        ...DEFAULT_REPORT,
        status: restored.status,
        summary: restored.summary,
        nextStep: "Run the repair again if the issue returns.",
        changed: true,
        reversible: false,
        ranAt: Date.now(),
        entries: restored.entries,
      };
      setReport(selectedIssue, report);
      saveRepairResult(selectedIssue, report);
      addToast({ type: "success", message: "Repair reverted" });
    } catch (error) {
      const report: RepairReport = {
        status: "failed",
        summary: "Revert failed",
        nextStep: "Copy this result and the log file for support.",
        changed: false,
        reversible: true,
        ranAt: Date.now(),
        rollback: selectedReport.rollback,
        entries: [{ label: "Error", value: String(error), tone: "bad" }],
      };
      setReport(selectedIssue, report);
      saveRepairResult(selectedIssue, report);
      addToast({ type: "error", message: "Revert failed" });
    } finally {
      setReverting(false);
    }
  }

  async function restoreRepairRollback(rollback: RepairRollback): Promise<{
    status: RepairStatus;
    summary: string;
    entries: RepairEntry[];
  }> {
    switch (rollback.kind) {
      case "startup_registration": {
        const after = await systemRestoreStartupRegistration(rollback.snapshot);
        return {
          status: "fixed",
          summary: "Startup repair reverted to the previous registry value.",
          entries: [
            {
              label: "Restored startup value",
              value: formatStartupRegistration(after),
              tone: "good",
              mono: true,
            },
          ],
        };
      }
    }
  }

  async function runRepairForIssue(issue: RepairIssue): Promise<RepairReport> {
    switch (issue) {
      case "driver":
        return repairDriver();
      case "adapter":
        return repairAdapter();
      case "tunnel_cleanup":
        return repairTunnelCleanup();
      case "route_assist":
        return checkRouteAssist();
      case "roblox":
        return repairBoost("roblox");
      case "network_booster":
        return repairBoost("network");
      case "startup":
        return repairStartup();
      case "relay":
        return checkRelay();
      case "country_bypass":
        return checkCountryBypass();
      case "installer":
        return checkInstaller();
      default:
        return DEFAULT_REPORT;
    }
  }

  async function repairDriver(): Promise<RepairReport> {
    const before = await systemCheckDriver();
    if (before.ready) {
      return driverReport(
        before,
        "healthy",
        "Split tunnel driver is healthy.",
        false,
      );
    }

    const admin = await systemIsAdmin().catch(() => ({ is_admin: false }));
    if (!admin.is_admin) {
      return {
        status: "needs_admin",
        summary: "Driver repair could not run without admin access.",
        nextStep: "If the driver issue continues, restart SwiftTunnel as admin and run this check again.",
        changed: false,
        reversible: false,
        ranAt: Date.now(),
        entries: driverEntries(before).concat({
          label: "Admin",
          value: "not elevated",
          tone: "bad",
        }),
      };
    }

    const after = await systemRepairDriver();
    const status = after.ready
      ? "fixed"
      : after.reboot_required
        ? "needs_reboot"
        : "failed";
    return driverReport(
      after,
      status,
      after.ready ? "Split tunnel driver repaired." : "Driver repair did not finish.",
      true,
    );
  }

  async function repairAdapter(): Promise<RepairReport> {
    const [adapters, diagnostics] = await Promise.all([
      vpnListNetworkAdapters(),
      vpnGetDiagnostics().catch(() => null),
    ]);
    const selectedAdapter = settings.preferred_physical_adapter_guid
      ? adapters.find((a) => a.guid === settings.preferred_physical_adapter_guid)
      : null;
    const defaultAdapter = adapters.find((a) => a.is_default_route);
    const entries: RepairEntry[] = [
      {
        label: "Binding mode",
        value: settings.adapter_binding_mode,
      },
      {
        label: "Default adapter",
        value:
          defaultAdapter?.friendly_name ||
          defaultAdapter?.description ||
          "not found",
        tone: defaultAdapter ? "good" : "bad",
      },
      {
        label: "Selected adapter",
        value:
          selectedAdapter?.friendly_name ||
          selectedAdapter?.description ||
          (settings.preferred_physical_adapter_guid ? "missing" : "auto"),
        tone:
          settings.preferred_physical_adapter_guid && !selectedAdapter
            ? "bad"
            : "default",
      },
      ...diagnosticEntries(diagnostics),
    ];

    if (settings.adapter_binding_mode === "manual" && !selectedAdapter) {
      return {
        status: "partial",
        summary: "Manual adapter selection points to an adapter that is not available.",
        nextStep: "Smart Auto is the safer setting when the selected adapter is unavailable.",
        changed: false,
        reversible: false,
        ranAt: Date.now(),
        entries,
      };
    }

    return {
      status: defaultAdapter ? "checked" : "failed",
      summary: defaultAdapter
        ? "Adapter diagnostics complete."
        : "No active adapter found.",
      nextStep: defaultAdapter
        ? "Adapter data was collected. Copy this result for support if needed."
        : "No active adapter was found. Check Wi-Fi/Ethernet, then run this check again.",
      changed: false,
      reversible: false,
      ranAt: Date.now(),
      entries,
    };
  }

  async function repairTunnelCleanup(): Promise<RepairReport> {
    const [state, diagnosticsBefore] = await Promise.all([
      vpnGetState(),
      vpnGetDiagnostics().catch(() => null),
    ]);
    const shouldCleanup =
      state.state === "error" ||
      state.error !== null ||
      diagnosticsBefore?.last_validation_result === "error" ||
      diagnosticsBefore?.binding_stage === "error";
    const baseEntries = [
      { label: "State", value: state.state },
      {
        label: "Split tunnel active",
        value: state.split_tunnel_active ? "yes" : "no",
      },
      ...diagnosticEntries(diagnosticsBefore),
    ];

    if (!shouldCleanup) {
      return {
        status: "checked",
        summary: "Tunnel cleanup skipped because no error state was detected.",
        nextStep: "No cleanup was applied. Copy this result for support if the tunnel issue continues.",
        changed: false,
        reversible: false,
        ranAt: Date.now(),
        entries: baseEntries,
      };
    }

    const entries: RepairEntry[] = [];
    try {
      await vpnDisconnect();
      entries.push({ label: "Disconnect", value: "completed", tone: "good" });
    } catch (error) {
      entries.push({
        label: "Disconnect",
        value: String(error),
        tone: "warn",
      });
    }
    await systemCleanup();
    const diagnostics = await vpnGetDiagnostics().catch(() => null);
    return {
      status: "fixed",
      summary: "Tunnel cleanup completed.",
      nextStep: "Cleanup state was refreshed. Copy this result for support if needed.",
      changed: true,
      reversible: false,
      ranAt: Date.now(),
      entries: baseEntries.concat(
        entries,
        { label: "Cleanup", value: "completed", tone: "good" },
        ...diagnosticEntries(diagnostics),
      ),
    };
  }

  async function checkRouteAssist(): Promise<RepairReport> {
    const [diagnostics, cacheRepair] = await Promise.all([
      vpnGetDiagnostics().catch(() => null),
      systemRepairNetworkCaches(),
    ]);
    return {
      status: cacheRepair.steps.every((step) => step.success)
        ? "fixed"
        : "partial",
      summary: "Route Assist diagnostics and network cache repair complete.",
      nextStep: settings.enable_api_tunneling
        ? "Route Assist is enabled. Copy this result for support if web/login routing needs review."
        : "Route Assist is disabled. Enable it only when browser login/API routing is needed.",
      changed: true,
      reversible: false,
      ranAt: Date.now(),
      entries: [
        {
          label: "Route Assist",
          value: settings.enable_api_tunneling ? "enabled" : "disabled",
          tone: settings.enable_api_tunneling ? "warn" : "default",
        },
        ...networkRepairEntries(cacheRepair),
        ...diagnosticEntries(diagnostics),
      ],
    };
  }

  async function repairBoost(kind: "roblox" | "network"): Promise<RepairReport> {
    const relevantConfig =
      kind === "roblox"
        ? settings.config.roblox_settings
        : settings.config.network_settings;
    const enabledCount = Object.values(relevantConfig).filter(
      (value) => value === true,
    ).length;

    return {
      status: "checked",
      summary:
        kind === "roblox"
          ? "Roblox settings snapshot collected."
          : "Network booster settings snapshot collected.",
      nextStep: "No settings were changed. Copy this result for support if needed.",
      changed: false,
      reversible: false,
      ranAt: Date.now(),
      entries: [
        {
          label: "Enabled toggles",
          value: String(enabledCount),
          mono: true,
        },
        {
          label: "Config",
          value: JSON.stringify(relevantConfig),
          mono: true,
        },
      ],
    };
  }

  async function repairStartup(): Promise<RepairReport> {
    const [admin, before] = await Promise.all([
      systemIsAdmin().catch(() => ({ is_admin: false })),
      systemGetStartupRegistration(),
    ]);
    updateSettings({ run_on_startup: settings.run_on_startup });
    await saveSettings();
    const after = await systemGetStartupRegistration();
    const changed =
      before.exists !== after.exists || before.value !== after.value;
    return {
      status: changed ? "fixed" : "checked",
      summary: changed
        ? "Startup registration repaired."
        : "Startup registration already matched settings.",
      nextStep: settings.run_on_startup
        ? "Startup registration was checked. Verify after the next Windows sign-in if needed."
        : "Startup is disabled. Enable Run on startup in Settings if this behavior is wanted.",
      changed,
      reversible: changed,
      rollback: changed
        ? { kind: "startup_registration", snapshot: before }
        : undefined,
      ranAt: Date.now(),
      entries: [
        {
          label: "Run on startup",
          value: settings.run_on_startup ? "enabled" : "disabled",
          tone: settings.run_on_startup ? "good" : "warn",
        },
        {
          label: "Admin",
          value: admin.is_admin ? "elevated" : "standard user",
        },
        {
          label: "Startup before",
          value: formatStartupRegistration(before),
          mono: true,
        },
        {
          label: "Startup after",
          value: formatStartupRegistration(after),
          mono: true,
          tone: changed ? "good" : "default",
        },
      ],
    };
  }

  async function checkRelay(): Promise<RepairReport> {
    await serverRefresh();
    const [latencies, ping] = await Promise.all([
      serverGetLatencies(),
      vpnGetPing().catch(() => null),
    ]);
    const best = latencies
      .filter((entry) => entry.latency_ms !== null)
      .sort((a, b) => (a.latency_ms ?? 99999) - (b.latency_ms ?? 99999))
      .slice(0, 5);
    return {
      status: "checked",
      summary: "Relay diagnostics refreshed.",
      nextStep:
        "Compare these relay latencies with the user's expected region and copy this result for support if needed.",
      changed: false,
      reversible: false,
      ranAt: Date.now(),
      entries: [
        {
          label: "Current ping",
          value: ping === null ? "not connected" : `${ping} ms`,
          mono: true,
        },
        ...best.map((entry) => ({
          label: entry.region,
          value: `${entry.latency_ms} ms`,
          tone: "good" as const,
          mono: true,
        })),
      ],
    };
  }

  async function checkCountryBypass(): Promise<RepairReport> {
    const [diagnostics, firstReachability] = await Promise.all([
      vpnGetDiagnostics().catch(() => null),
      checkRobloxWebsiteReachability(),
    ]);
    const cacheRepair = firstReachability.reachable
      ? null
      : await systemRepairNetworkCaches();
    const secondReachability = firstReachability.reachable
      ? firstReachability
      : await checkRobloxWebsiteReachability();
    const reachable = secondReachability.reachable;
    const summary = reachable
      ? firstReachability.reachable
        ? "Roblox website is reachable from this network."
        : "Roblox website became reachable after network cache repair."
      : "Roblox website did not respond from this network.";
    const nextStep = reachable
      ? settings.enable_country_ban
        ? "Country bypass is enabled, but this network does not appear blocked right now."
        : "No country bypass is needed on this network right now."
      : settings.enable_country_ban
        ? "Local bypass is enabled but reachability still failed. Copy this result for support if the block continues."
        : "Roblox reachability failed. Enable Bypass country bans only if this network is expected to be country-blocked.";

    return {
      status: firstReachability.reachable
        ? "checked"
        : reachable
          ? "fixed"
          : "partial",
      summary,
      nextStep,
      changed: cacheRepair !== null,
      reversible: false,
      ranAt: Date.now(),
      entries: [
        {
          label: "Roblox website before",
          value: firstReachability.reachable
            ? "reachable"
            : `unreachable (${firstReachability.reason})`,
          tone: firstReachability.reachable ? "good" : "warn",
        },
        ...(cacheRepair ? networkRepairEntries(cacheRepair) : []),
        {
          label: "Roblox website after",
          value: reachable
            ? "reachable"
            : `unreachable (${secondReachability.reason})`,
          tone: reachable ? "good" : "warn",
        },
        {
          label: "Country bypass",
          value: settings.enable_country_ban ? "enabled" : "disabled",
          tone: settings.enable_country_ban && reachable ? "warn" : "default",
        },
        {
          label: "Route Assist",
          value: settings.enable_api_tunneling ? "enabled" : "disabled",
        },
        ...diagnosticEntries(diagnostics),
      ],
    };
  }

  async function checkInstaller(): Promise<RepairReport> {
    const driver = await systemCheckDriver().catch(() => null);
    return {
      status: driver?.ready ? "checked" : "partial",
      summary: "Installer/update diagnostics checked.",
      nextStep:
        "Installer/update data was collected. Copy this result and the log for support if needed.",
      changed: false,
      reversible: false,
      ranAt: Date.now(),
      entries: [
        ...(driver ? driverEntries(driver) : []),
        {
          label: "MSI note",
          value:
            "MSI installs the app and drivers; users normally launch SwiftTunnel from Start/Menu after install.",
        },
      ],
    };
  }

  async function generateDiagnosticsBundle() {
    setIsGeneratingDiagnostics(true);
    setDiagnosticsError(null);

    try {
      const response = await settingsGenerateNetworkDiagnosticsBundle();
      setDiagnosticsPath(response.file_path);
      addToast({ type: "success", message: "Diagnostics bundle generated" });

      try {
        await systemOpenUrl(response.folder_path);
      } catch (openError) {
        setDiagnosticsError(
          `Bundle generated, but failed to open folder: ${String(openError)}`,
        );
      }
    } catch (e) {
      setDiagnosticsError(String(e));
    } finally {
      setIsGeneratingDiagnostics(false);
    }
  }

  async function copyLogToClipboard() {
    setIsCopyingLog(true);
    setCopyLogError(null);

    try {
      const response = await systemCopyLogToClipboard();
      setCopyLogPath(response.file_path);
      addToast({
        type: "success",
        message: "Log file copied - paste it into Discord or email.",
      });
    } catch (e) {
      setCopyLogError(String(e));
    } finally {
      setIsCopyingLog(false);
    }
  }

  async function copySelectedRepairForSupport() {
    const text = formatRepairForSupport(selectedMeta.label, selectedReport);
    try {
      await navigator.clipboard.writeText(text);
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
      {running && <div className="fixed inset-0 z-40 cursor-default" />}

      <Section title="Repair Center">
        <div className="px-4 py-3">
          <div className="grid grid-cols-[1fr_auto_auto] gap-2">
            <div className="relative min-w-0">
              <select
                value={selectedIssue}
                onChange={(event) =>
                  setSelectedIssue(event.target.value as RepairIssue)
                }
                disabled={running}
                className="w-full rounded-[4px] py-2 pl-3 pr-9 text-[12px] outline-none transition-colors disabled:opacity-50"
                style={{
                  backgroundColor: "var(--color-bg-elevated)",
                  border: "1px solid var(--color-border-default)",
                  color: "var(--color-text-primary)",
                }}
              >
                {REPAIR_ISSUES.map((issue) => (
                  <option key={issue.id} value={issue.id}>
                    {issue.label}
                  </option>
                ))}
              </select>
            </div>
            <Button
              variant="primary"
              size="sm"
              onClick={() => void runRepair()}
              disabled={running}
              loading={running}
            >
              {running ? "Running" : "Run"}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void revertLastRepair()}
              disabled={!canRevert}
              loading={reverting}
              title={
                canRevert
                  ? "Restore the exact snapshot captured before this repair"
                  : "No exact rollback snapshot is available for this repair"
              }
            >
              {canRevert ? "Revert" : "No revert"}
            </Button>
          </div>
          <div className="mt-2 flex items-center gap-2 text-[11px] text-text-muted">
            <span className="min-w-0">{selectedMeta.desc}</span>
          </div>
        </div>

        <details
          open
          className="relative mx-4 mb-3 rounded-[5px]"
          style={{
            backgroundColor: "var(--color-bg-elevated)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          <summary className="cursor-pointer py-2 pl-3 pr-20 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-muted">
            {selectedMeta.label} diagnostics
          </summary>
          <button
            type="button"
            onClick={(event) => {
              event.preventDefault();
              event.stopPropagation();
              void copySelectedRepairForSupport();
            }}
            disabled={running || selectedReport.status === "not_checked"}
            className="absolute right-2 top-1.5 rounded-[4px] border px-2 py-1 text-[10.5px] font-medium text-text-primary transition-colors hover:bg-bg-hover disabled:cursor-not-allowed disabled:opacity-50"
            style={{
              borderColor: "var(--color-border-subtle)",
              backgroundColor: "var(--color-bg-base)",
            }}
          >
            Copy
          </button>
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 px-3 pb-3 text-[10.5px]">
            <RepairItem
              label="Status"
              value={statusLabel(selectedReport.status)}
            />
            <RepairItem
              label="Last run"
              value={
                selectedReport.ranAt
                  ? new Date(selectedReport.ranAt).toLocaleString()
                  : "not run"
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
            />
            <RepairItem
              label="Revert available"
              value={canRevert ? "exact snapshot available" : "no exact rollback"}
            />
            {selectedReport.entries.map((entry, index) => (
              <div
                key={`${entry.label}-${index}`}
                className={entry.value.length > 44 ? "col-span-2" : undefined}
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
        </details>
      </Section>

      <Section
        title="Support"
        tagElement={
          <button
            type="button"
            onClick={() =>
              void systemOpenUrl("https://discord.com/invite/8FjPxk92Tf")
            }
            aria-label="Open SwiftTunnel Discord support server"
            className="inline-flex cursor-pointer items-center gap-1 rounded-[4px] px-1.5 py-[2px] font-mono text-[9.5px] font-medium transition-colors hover:bg-bg-hover active:scale-[0.98]"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              color: "var(--color-text-muted)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            <span>Contact support</span>
            <Tooltip content="Opens the SwiftTunnel Discord support server">
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          </button>
        }
      >
        <Row
          label="Network diagnostics"
          desc="Generate a support-ready bundle with ISP, routing, and split tunnel info"
        >
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void generateDiagnosticsBundle()}
            disabled={isGeneratingDiagnostics}
            loading={isGeneratingDiagnostics}
          >
            {isGeneratingDiagnostics ? "Generating" : "Generate"}
          </Button>
        </Row>
        {diagnosticsPath && (
          <div className="px-4 pb-3 text-[11px] text-text-muted">
            Saved to:{" "}
            <span className="break-all font-mono text-[10.5px] text-text-secondary">
              {diagnosticsPath}
            </span>
          </div>
        )}
        {diagnosticsError && (
          <div className="px-4 pb-3 text-[11px] text-status-error">
            {diagnosticsError}
          </div>
        )}
        <Row
          label="Copy Log File"
          desc="Puts the SwiftTunnel log file on your clipboard - paste into Discord/email to share with support"
        >
          <button
            onClick={() => void copyLogToClipboard()}
            disabled={isCopyingLog}
            className="rounded-[var(--radius-button)] border border-border-subtle px-3 py-1.5 text-xs text-text-primary transition-colors hover:bg-bg-hover disabled:opacity-50"
          >
            {isCopyingLog ? "Copying..." : "Copy"}
          </button>
        </Row>
        {copyLogPath && (
          <div className="px-4 pb-3 text-xs text-text-muted">
            Copied:{" "}
            <span className="break-all font-mono text-[11px] text-text-secondary">
              {copyLogPath}
            </span>
          </div>
        )}
        {copyLogError && (
          <div className="px-4 pb-3 text-xs text-status-error">
            {copyLogError}
          </div>
        )}
      </Section>
    </div>
  );
}

async function checkRobloxWebsiteReachability() {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 4000);

  try {
    await fetch("https://www.roblox.com/", {
      method: "GET",
      mode: "no-cors",
      cache: "no-store",
      signal: controller.signal,
    });
    return { reachable: true, reason: "ok" };
  } catch (error) {
    return {
      reachable: false,
      reason: error instanceof Error ? error.message : String(error),
    };
  } finally {
    window.clearTimeout(timeout);
  }
}

function saveRepairResult(issue: RepairIssue, report: RepairReport) {
  localStorage.setItem(
    LAST_REPAIR_STORAGE_KEY,
    JSON.stringify({ issue, report }),
  );
}

function loadSavedRepairResult():
  | { issue: RepairIssue; report: RepairReport }
  | null {
  try {
    const raw = localStorage.getItem(LAST_REPAIR_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as {
      issue?: RepairIssue;
      report?: RepairReport;
    };
    if (!parsed.issue || !parsed.report) return null;
    if (!REPAIR_ISSUES.some((issue) => issue.id === parsed.issue)) return null;
    return { issue: parsed.issue, report: parsed.report };
  } catch {
    return null;
  }
}

function waitForMinimumDuration(startedAt: number, minimumMs: number) {
  const remaining = minimumMs - (Date.now() - startedAt);
  if (remaining <= 0) return Promise.resolve();
  return new Promise<void>((resolve) => window.setTimeout(resolve, remaining));
}

function formatRepairForSupport(label: string, report: RepairReport) {
  const lines = [
    `SwiftTunnel Repair: ${label}`,
    `Status: ${statusLabel(report.status)}`,
    `Result: ${report.summary}`,
    `Next step: ${report.nextStep}`,
    `Changed system: ${report.changed ? "yes" : "no"}`,
    `Revert available: ${report.reversible && report.rollback ? "yes" : "no"}`,
    `Last run: ${report.ranAt ? new Date(report.ranAt).toLocaleString() : "not run"}`,
  ];

  if (report.entries.length > 0) {
    lines.push("", "Details:");
    for (const entry of report.entries) {
      lines.push(`- ${entry.label}: ${entry.value}`);
    }
  }

  return lines.join("\n");
}

function driverReport(
  driver: DriverCheckResponse,
  status: RepairStatus,
  summary: string,
  changed: boolean,
): RepairReport {
  return {
    status,
    summary,
    nextStep: driver.ready
      ? "Driver check is healthy. If the issue continues, copy this result for support."
      : driver.reboot_required
        ? "Windows reports a reboot is required before the driver can be checked again."
        : driver.message || "If the driver error repeats, copy this result for support.",
    changed,
    reversible: false,
    ranAt: Date.now(),
    entries: driverEntries(driver),
  };
}

function driverEntries(driver: DriverCheckResponse): RepairEntry[] {
  return [
    { label: "Installed", value: driver.installed ? "yes" : "no" },
    {
      label: "Ready",
      value: driver.ready ? "yes" : "no",
      tone: driver.ready ? "good" : "bad",
    },
    { label: "Status", value: driver.status },
    { label: "Action", value: driver.recommended_action },
    {
      label: "Reboot",
      value: driver.reboot_required ? "required" : "not required",
      tone: driver.reboot_required ? "warn" : "default",
    },
    { label: "Message", value: driver.message },
  ];
}

function networkRepairEntries(response: {
  steps: Array<{ name: string; success: boolean; output: string }>;
}): RepairEntry[] {
  return response.steps.flatMap((step) => {
    const entries: RepairEntry[] = [
      {
        label: step.name,
        value: step.success ? "completed" : "failed",
        tone: step.success ? "good" : "warn",
      },
    ];
    if (!step.success && step.output) {
      entries.push({
        label: `${step.name} output`,
        value: step.output,
        tone: "warn",
      });
    }
    return entries;
  });
}

function formatStartupRegistration(snapshot: StartupRegistrationSnapshot) {
  if (!snapshot.exists) {
    return "absent";
  }
  return snapshot.value || "present with empty value";
}

function diagnosticEntries(
  diagnostics: DiagnosticsResponse | null,
): RepairEntry[] {
  if (!diagnostics) {
    return [{ label: "Diagnostics", value: "not available", tone: "warn" }];
  }

  return [
    { label: "Adapter", value: diagnostics.adapter_name || "not resolved" },
    {
      label: "Selected ifIndex",
      value: String(diagnostics.selected_if_index ?? "n/a"),
      mono: true,
    },
    {
      label: "Resolved ifIndex",
      value: String(diagnostics.resolved_if_index ?? "n/a"),
      mono: true,
    },
    {
      label: "Route source",
      value: diagnostics.route_resolution_source || "n/a",
    },
    { label: "Binding stage", value: diagnostics.binding_stage || "n/a" },
    { label: "Validation", value: diagnostics.last_validation_result || "n/a" },
    {
      label: "Packets",
      value: `${diagnostics.packets_tunneled} tunneled / ${diagnostics.packets_bypassed} bypassed`,
      mono: true,
    },
  ];
}

function Section({
  title,
  tag,
  tagElement,
  children,
}: {
  title: string;
  tag?: string;
  tagElement?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section>
      {tagElement ? (
        <div className="mb-2.5 flex items-center gap-2">
          <h3
            className="text-[12.5px] font-semibold text-text-primary"
            style={{ letterSpacing: "-0.005em" }}
          >
            {title}
          </h3>
          {tagElement}
        </div>
      ) : (
        <SectionHeader label={title} tag={tag} />
      )}
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card divide-y divide-[color:var(--color-border-subtle)]">
        {children}
      </div>
    </section>
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

function statusLabel(status: RepairStatus) {
  switch (status) {
    case "not_checked":
      return "Not checked";
    case "running":
      return "Running";
    case "fixed":
      return "Fixed";
    case "healthy":
      return "Healthy";
    case "checked":
      return "Checked";
    case "partial":
      return "Partial";
    case "needs_admin":
      return "Needs admin";
    case "needs_reboot":
      return "Needs reboot";
    case "failed":
      return "Failed";
    default:
      return status;
  }
}
