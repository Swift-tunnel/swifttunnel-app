import type {
  AppSettings,
  DiagnosticsResponse,
  DriverCheckResponse,
  LatencyEntry,
  NetworkAdapterInfo,
  VpnStateResponse,
  WindowsFirewallRepairResponse,
} from "./types";
import type {
  NetworkRepairResponse,
  StartupRegistrationSnapshot,
} from "./commands";
import { formatErrorMessage } from "./errors";

export type RepairIssueId =
  | "no_internet"
  | "driver"
  | "adapter"
  | "tunnel_cleanup"
  | "windows_firewall"
  | "route_assist"
  | "roblox"
  | "network_booster"
  | "startup"
  | "relay"
  | "installer";

export type RepairStatus =
  | "not_checked"
  | "healthy"
  | "checked"
  | "fixed"
  | "partial"
  | "needs_reboot"
  | "failed"
  | "unsupported";

const REPAIR_STATUSES: readonly RepairStatus[] = [
  "not_checked",
  "healthy",
  "checked",
  "fixed",
  "partial",
  "needs_reboot",
  "failed",
  "unsupported",
];

export interface RepairIssueDefinition {
  id: RepairIssueId;
  label: string;
  description: string;
  actionLabel: "Check" | "Repair";
  systemChanging: boolean;
}

export interface RepairEntry {
  label: string;
  value: string;
  tone?: "default" | "good" | "warn" | "bad";
  mono?: boolean;
}

export type RepairRollback = {
  kind: "startup_registration";
  snapshot: StartupRegistrationSnapshot;
};

export interface RepairReport {
  status: RepairStatus;
  summary: string;
  nextStep: string;
  changed: boolean;
  reversible: boolean;
  ranAt: number;
  entries: RepairEntry[];
  rollback?: RepairRollback;
}

export type SavedRepairResult = {
  issue: RepairIssueId;
  report: RepairReport;
};

export interface RepairContext {
  settings: AppSettings;
}

export interface RepairCenterDeps {
  now: () => number;
  serverGetLatencies: () => Promise<LatencyEntry[]>;
  serverRefresh: () => Promise<string>;
  systemCheckDriver: () => Promise<DriverCheckResponse>;
  systemCleanupTunnelState: () => Promise<void>;
  systemGetStartupRegistration: () => Promise<StartupRegistrationSnapshot>;
  systemIsAdmin: () => Promise<{ is_admin: boolean }>;
  systemRepairDriver: () => Promise<DriverCheckResponse>;
  systemRepairWindowsFirewall: () => Promise<WindowsFirewallRepairResponse>;
  systemRepairNetwork: () => Promise<NetworkRepairResponse>;
  systemRepairStartupRegistration: (
    enabled: boolean,
  ) => Promise<StartupRegistrationSnapshot>;
  systemRestoreStartupRegistration: (
    snapshot: StartupRegistrationSnapshot,
  ) => Promise<StartupRegistrationSnapshot>;
  vpnDisconnect: () => Promise<void>;
  vpnGetDiagnostics: () => Promise<DiagnosticsResponse | null>;
  vpnGetPing: () => Promise<number | null>;
  vpnGetState: () => Promise<VpnStateResponse>;
  vpnListNetworkAdapters: () => Promise<NetworkAdapterInfo[]>;
}

export const REPAIR_ISSUES: RepairIssueDefinition[] = [
  {
    id: "no_internet",
    label: "Internet recovery",
    description:
      "Fixes no-internet-after-SwiftTunnel: resets stuck packet filter state, unbinds a leftover network-filter (nt_ndisrd) driver binding that can blackhole traffic after a crash, removes leftover IPv6/offload changes, and flushes DNS. Safe to run any time while disconnected.",
    actionLabel: "Repair",
    systemChanging: true,
  },
  {
    id: "driver",
    label: "Split tunnel driver",
    description: "Checks and repairs the Windows Packet Filter driver path.",
    actionLabel: "Repair",
    systemChanging: true,
  },
  {
    id: "adapter",
    label: "Adapter routing",
    description: "Checks selected adapter, default route, and split tunnel binding.",
    actionLabel: "Check",
    systemChanging: false,
  },
  {
    id: "tunnel_cleanup",
    label: "Tunnel cleanup",
    description: "Clears stale tunnel state only when an error state is present.",
    actionLabel: "Repair",
    systemChanging: true,
  },
  {
    id: "windows_firewall",
    label: "Windows Firewall",
    description: "Repairs the firewall path used for IPv6 leak prevention.",
    actionLabel: "Repair",
    systemChanging: true,
  },
  {
    id: "route_assist",
    label: "Route Assist",
    description: "Checks Roblox API/browser routing state without changing it.",
    actionLabel: "Check",
    systemChanging: false,
  },
  {
    id: "roblox",
    label: "Roblox settings",
    description: "Captures the saved Roblox boost settings for support review.",
    actionLabel: "Check",
    systemChanging: false,
  },
  {
    id: "network_booster",
    label: "Network booster",
    description: "Captures the saved network boost settings for support review.",
    actionLabel: "Check",
    systemChanging: false,
  },
  {
    id: "startup",
    label: "Startup login",
    description: "Repairs the Windows sign-in launch registration.",
    actionLabel: "Repair",
    systemChanging: true,
  },
  {
    id: "relay",
    label: "Relay latency",
    description: "Refreshes relay data and captures current ping.",
    actionLabel: "Check",
    systemChanging: false,
  },
  {
    id: "installer",
    label: "Installer/update",
    description: "Checks driver install state used by support triage.",
    actionLabel: "Check",
    systemChanging: false,
  },
];

export function notCheckedReport(now = Date.now): RepairReport {
  return {
    status: "not_checked",
    summary: "No check has been run yet.",
    nextStep: "Choose an item and run it.",
    changed: false,
    reversible: false,
    ranAt: now(),
    entries: [],
  };
}

export function makeInitialRepairReports(
  now = Date.now,
): Record<RepairIssueId, RepairReport> {
  return REPAIR_ISSUES.reduce(
    (acc, issue) => {
      acc[issue.id] = notCheckedReport(now);
      return acc;
    },
    {} as Record<RepairIssueId, RepairReport>,
  );
}

export function parseSavedRepairResult(raw: string | null): SavedRepairResult | null {
  if (!raw) return null;

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) return null;

    const issue = parsed.issue;
    const report = parsed.report;
    if (!isRepairIssueId(issue) || !isRepairReport(report)) return null;

    return { issue, report };
  } catch {
    return null;
  }
}

function isRepairIssueId(value: unknown): value is RepairIssueId {
  return (
    typeof value === "string" &&
    REPAIR_ISSUES.some((issue) => issue.id === value)
  );
}

function isRepairReport(value: unknown): value is RepairReport {
  if (!isRecord(value)) return false;
  if (!isRepairStatus(value.status)) return false;
  if (typeof value.summary !== "string") return false;
  if (typeof value.nextStep !== "string") return false;
  if (typeof value.changed !== "boolean") return false;
  if (typeof value.reversible !== "boolean") return false;
  if (typeof value.ranAt !== "number" || !Number.isFinite(value.ranAt)) {
    return false;
  }
  if (!Array.isArray(value.entries) || !value.entries.every(isRepairEntry)) {
    return false;
  }
  if (
    value.rollback !== undefined &&
    !isRepairRollback(value.rollback)
  ) {
    return false;
  }
  return true;
}

function isRepairStatus(value: unknown): value is RepairStatus {
  return (
    typeof value === "string" &&
    REPAIR_STATUSES.includes(value as RepairStatus)
  );
}

function isRepairEntry(value: unknown): value is RepairEntry {
  if (!isRecord(value)) return false;
  if (typeof value.label !== "string") return false;
  if (typeof value.value !== "string") return false;
  if (
    value.tone !== undefined &&
    value.tone !== "default" &&
    value.tone !== "good" &&
    value.tone !== "warn" &&
    value.tone !== "bad"
  ) {
    return false;
  }
  if (value.mono !== undefined && typeof value.mono !== "boolean") {
    return false;
  }
  return true;
}

function isRepairRollback(value: unknown): value is RepairRollback {
  if (!isRecord(value)) return false;
  if (value.kind !== "startup_registration") return false;
  return isStartupRegistrationSnapshot(value.snapshot);
}

function isStartupRegistrationSnapshot(
  value: unknown,
): value is StartupRegistrationSnapshot {
  if (!isRecord(value)) return false;
  return (
    typeof value.exists === "boolean" &&
    (value.value === null || typeof value.value === "string")
  );
}

export async function runRepairIssue(
  issue: RepairIssueId,
  deps: RepairCenterDeps,
  context: RepairContext,
): Promise<RepairReport> {
  try {
    switch (issue) {
      case "no_internet":
        return await repairNoInternet(deps);
      case "driver":
        return await repairDriver(deps);
      case "adapter":
        return await checkAdapterRouting(deps, context.settings);
      case "tunnel_cleanup":
        return await repairTunnelCleanup(deps);
      case "windows_firewall":
        return await repairWindowsFirewall(deps);
      case "route_assist":
        return await checkRouteAssist(deps, context.settings);
      case "roblox":
        return checkBoostSettings(
          deps,
          "Roblox settings snapshot collected.",
          context.settings.config.roblox_settings,
        );
      case "network_booster":
        return checkBoostSettings(
          deps,
          "Network booster settings snapshot collected.",
          context.settings.config.network_settings,
        );
      case "startup":
        return await repairStartupRegistration(deps, context.settings);
      case "relay":
        return await checkRelay(deps);
      case "installer":
        return await checkInstaller(deps);
    }
  } catch (error) {
    return errorReport(deps, "Repair failed", formatErrorMessage(error));
  }
}

export async function restoreRepairRollback(
  deps: RepairCenterDeps,
  rollback: RepairRollback,
): Promise<RepairReport> {
  try {
    switch (rollback.kind) {
      case "startup_registration": {
        const restored = await deps.systemRestoreStartupRegistration(
          rollback.snapshot,
        );
        const restoredMatches = startupSnapshotsEqual(rollback.snapshot, restored);
        return {
          status: restoredMatches ? "fixed" : "partial",
          summary: restoredMatches
            ? "Startup registration restored."
            : "Startup restore completed, but the current registration differs from the saved snapshot.",
          nextStep: restoredMatches
            ? "Run startup repair again if the sign-in launch issue returns."
            : "Copy this result and the log file for support.",
          changed: true,
          reversible: false,
          ranAt: deps.now(),
          entries: [
            {
              label: "Restored startup value",
              value: formatStartupRegistration(restored),
              tone: restoredMatches ? "good" : "warn",
              mono: true,
            },
          ],
        };
      }
      default:
        return errorReport(deps, "Unknown rollback kind", rollback.kind);
    }
  } catch (error) {
    return errorReport(deps, "Revert failed", formatErrorMessage(error));
  }
}

export function statusLabel(status: RepairStatus): string {
  switch (status) {
    case "not_checked":
      return "Not checked";
    case "healthy":
      return "Healthy";
    case "checked":
      return "Checked";
    case "fixed":
      return "Fixed";
    case "partial":
      return "Partial";
    case "needs_reboot":
      return "Needs reboot";
    case "failed":
      return "Failed";
    case "unsupported":
      return "Unsupported";
  }
}

export function formatRepairForSupport(
  issue: RepairIssueDefinition,
  report: RepairReport,
): string {
  const lines = [
    `SwiftTunnel Repair: ${issue.label}`,
    `Status: ${statusLabel(report.status)}`,
    `Result: ${report.summary}`,
    `Next step: ${report.nextStep}`,
    `Changed system: ${report.changed ? "yes" : "no"}`,
    `Revert available: ${report.reversible && report.rollback ? "yes" : "no"}`,
    `Last run: ${new Date(report.ranAt).toLocaleString()}`,
  ];

  if (report.entries.length > 0) {
    lines.push("", "Details:");
    for (const entry of report.entries) {
      lines.push(`- ${entry.label}: ${entry.value}`);
    }
  }

  return lines.join("\n");
}

// Unlike tunnel cleanup, this never gates on an error state: the stuck
// tunnel-mode failure leaves the app looking healthy ("disconnected", no
// error) while the kernel filter blackholes all traffic. The only
// precondition is that no session is active.
async function repairNoInternet(deps: RepairCenterDeps): Promise<RepairReport> {
  const state = await deps.vpnGetState().catch(() => null);
  if (state !== null && state.state !== "disconnected" && state.state !== "error") {
    return {
      status: "partial",
      summary: "Internet recovery did not run because SwiftTunnel is connected.",
      nextStep: "Disconnect SwiftTunnel, then run Internet recovery again.",
      changed: false,
      reversible: false,
      ranAt: deps.now(),
      entries: [{ label: "State", value: state.state, tone: "warn" }],
    };
  }

  const repair = await deps.systemRepairNetwork();

  if (!repair.supported) {
    return {
      status: "unsupported",
      summary: "Internet recovery is only available on Windows.",
      nextStep: "No changes were made.",
      changed: false,
      reversible: false,
      ranAt: deps.now(),
      entries: [],
    };
  }

  const status: RepairStatus =
    repair.overall === "fixed"
      ? "fixed"
      : repair.overall === "healthy"
        ? "healthy"
        : repair.overall === "partial"
          ? "partial"
          : "failed";
  const changed = repair.steps.some((step) => step.status === "fixed");
  const failedSteps = repair.steps.filter((step) => step.status === "failed");

  return {
    status,
    summary:
      repair.overall === "healthy"
        ? "No leftover SwiftTunnel network state was found."
        : repair.overall === "fixed"
          ? "Leftover SwiftTunnel network state was found and repaired."
          : repair.overall === "partial"
            ? "Some leftover network state was repaired, but not all of it."
            : "Internet recovery could not repair the leftover network state.",
    nextStep:
      repair.overall === "healthy"
        ? "If the internet is still broken, reboot Windows (this always clears driver filter state), then run this again."
        : repair.overall === "fixed"
          ? "Check whether the internet works now. If not, reboot Windows and run this again."
          : !repair.is_admin
            ? "Relaunch SwiftTunnel as Administrator, then run Internet recovery again."
            : failedSteps.some((step) => step.id === "adapter_modes")
              ? "Run the split tunnel driver repair, then run Internet recovery again. A Windows reboot also clears this state."
              : "Reboot Windows, then run Internet recovery again. Copy this result for support if it still fails.",
    changed,
    reversible: false,
    ranAt: deps.now(),
    entries: [
      {
        label: "Admin",
        value: repair.is_admin ? "elevated" : "standard user",
        tone: repair.is_admin ? "default" : "warn",
      },
      ...repair.steps.map((step) => ({
        label: step.label,
        value: step.detail,
        tone:
          step.status === "failed"
            ? ("bad" as const)
            : step.status === "fixed"
              ? ("good" as const)
              : ("default" as const),
      })),
    ],
  };
}

async function repairDriver(deps: RepairCenterDeps): Promise<RepairReport> {
  const [before, admin] = await Promise.all([
    deps.systemCheckDriver(),
    deps.systemIsAdmin().catch(() => ({ is_admin: false })),
  ]);

  if (before.status === "unsupported") {
    return driverReport(deps, before, "unsupported", "Driver repair is unsupported.", false, admin);
  }

  if (before.reboot_required || before.recommended_action === "reboot") {
    return driverReport(
      deps,
      before,
      "needs_reboot",
      "Windows requires a reboot before driver repair can continue.",
      false,
      admin,
    );
  }

  let after: DriverCheckResponse;
  try {
    after = await deps.systemRepairDriver();
  } catch (error) {
    const [afterCheck] = await Promise.allSettled([deps.systemCheckDriver()]);
    return driverRepairCommandFailedReport(
      deps,
      before,
      admin,
      formatErrorMessage(error),
      commandOutcome(afterCheck),
    );
  }

  const status = after.ready
    ? "fixed"
    : after.reboot_required
      ? "needs_reboot"
      : after.status === "unsupported"
        ? "unsupported"
        : "failed";

  return driverReport(
    deps,
    after,
    status,
    after.ready ? "Split tunnel driver repaired." : "Driver repair did not finish.",
    after.ready,
    admin,
    before,
  );
}

async function checkAdapterRouting(
  deps: RepairCenterDeps,
  settings: AppSettings,
): Promise<RepairReport> {
  const [adaptersResult, diagnosticsResult] = await Promise.allSettled([
    deps.vpnListNetworkAdapters(),
    deps.vpnGetDiagnostics(),
  ]);
  const diagnostics = resultValueOrNull(diagnosticsResult);

  if (adaptersResult.status === "rejected") {
    return {
      status: "failed",
      summary: "Adapter routing check failed.",
      nextStep: "Copy this result and the log file for support.",
      changed: false,
      reversible: false,
      ranAt: deps.now(),
      entries: [
        {
          label: "Adapter inventory",
          value: formatErrorMessage(adaptersResult.reason),
          tone: "bad",
        },
        ...diagnosticEntriesFromResult(diagnosticsResult),
      ],
    };
  }

  const adapters = adaptersResult.value;
  const selectedAdapter = settings.preferred_physical_adapter_guid
    ? adapters.find((a) => a.guid === settings.preferred_physical_adapter_guid)
    : null;
  const defaultAdapter = adapters.find((a) => a.is_default_route);
  const manualAdapterMissing =
    settings.adapter_binding_mode === "manual" &&
    Boolean(settings.preferred_physical_adapter_guid) &&
    !selectedAdapter;

  return {
    status: manualAdapterMissing || !defaultAdapter ? "partial" : "checked",
    summary: manualAdapterMissing
      ? "Manual adapter selection points to an unavailable adapter."
      : defaultAdapter
        ? "Adapter routing checked."
        : "No default-route adapter was found.",
    nextStep: manualAdapterMissing
      ? "Switch adapter binding to Smart Auto or choose an available adapter."
      : "Copy this result for support if routing still looks wrong.",
    changed: false,
    reversible: false,
    ranAt: deps.now(),
    entries: [
      { label: "Binding mode", value: settings.adapter_binding_mode },
      {
        label: "Default adapter",
        value: adapterName(defaultAdapter) ?? "not found",
        tone: defaultAdapter ? "good" : "warn",
      },
      {
        label: "Selected adapter",
        value:
          adapterName(selectedAdapter) ??
          (settings.preferred_physical_adapter_guid ? "missing" : "auto"),
        tone: manualAdapterMissing ? "bad" : "default",
      },
      ...diagnosticEntriesFromResult(diagnosticsResult, diagnostics),
    ],
  };
}

async function repairTunnelCleanup(
  deps: RepairCenterDeps,
): Promise<RepairReport> {
  const [stateResult, diagnosticsBeforeResult] = await Promise.allSettled([
    deps.vpnGetState(),
    deps.vpnGetDiagnostics(),
  ]);
  const diagnosticsBefore = resultValueOrNull(diagnosticsBeforeResult);

  if (stateResult.status === "rejected") {
    return {
      status: "failed",
      summary: "Tunnel cleanup could not read VPN state.",
      nextStep: "Copy this result and the log file for support.",
      changed: false,
      reversible: false,
      ranAt: deps.now(),
      entries: [
        {
          label: "State",
          value: formatErrorMessage(stateResult.reason),
          tone: "bad",
        },
        ...diagnosticEntriesFromResult(
          diagnosticsBeforeResult,
          diagnosticsBefore,
        ),
      ],
    };
  }

  const state = stateResult.value;
  const cleanupNeeded =
    hasTunnelCleanupStateError(state) ||
    hasTunnelCleanupDiagnosticError(diagnosticsBefore);
  const baseEntries: RepairEntry[] = [
    { label: "State", value: state.state },
    {
      label: "Split tunnel active",
      value: state.split_tunnel_active ? "yes" : "no",
    },
    ...diagnosticEntriesFromResult(diagnosticsBeforeResult, diagnosticsBefore),
  ];

  if (!cleanupNeeded) {
    return {
      status: "checked",
      summary: "Tunnel cleanup skipped because no error state was detected.",
      nextStep: "No cleanup was needed.",
      changed: false,
      reversible: false,
      ranAt: deps.now(),
      entries: baseEntries,
    };
  }

  const repairEntries: RepairEntry[] = [];
  if (state.state !== "disconnected") {
    try {
      await deps.vpnDisconnect();
      repairEntries.push({ label: "Disconnect", value: "completed", tone: "good" });
    } catch (error) {
      repairEntries.push({
        label: "Disconnect",
        value: formatErrorMessage(error),
        tone: "bad",
      });
      return {
        status: "failed",
        summary: "Tunnel cleanup stopped because disconnect failed.",
        nextStep: "Disconnect manually, then run tunnel cleanup again.",
        changed: true,
        reversible: false,
        ranAt: deps.now(),
        entries: baseEntries.concat(repairEntries),
      };
    }
  }

  let cleanupError: unknown = null;
  try {
    await deps.systemCleanupTunnelState();
  } catch (error) {
    cleanupError = error;
  }
  const [stateAfterResult, diagnosticsAfterResult, driverAfterResult] =
    await Promise.allSettled([
      deps.vpnGetState(),
      deps.vpnGetDiagnostics(),
      deps.systemCheckDriver(),
    ]);
  const stateAfter = resultValueOrNull(stateAfterResult);
  const diagnosticsAfter = resultValueOrNull(diagnosticsAfterResult);
  const driverAfter = resultValueOrNull(driverAfterResult);
  const stateStillErrored =
    stateAfter !== null && hasTunnelCleanupStateError(stateAfter);
  const diagnosticsStillErrored =
    hasTunnelCleanupDiagnosticError(diagnosticsAfter);
  const driverNeedsRepair = driverAfter !== null && !driverAfter.ready;
  const verificationUnavailable =
    stateAfterResult.status === "rejected" ||
    diagnosticsAfterResult.status === "rejected" ||
    driverAfterResult.status === "rejected";
  const status: RepairStatus = cleanupError
    ? "failed"
    : stateStillErrored ||
        diagnosticsStillErrored ||
        driverNeedsRepair ||
        verificationUnavailable
      ? "partial"
      : "fixed";

  return {
    status,
    summary: cleanupError
      ? "Tunnel cleanup failed."
      : stateStillErrored
      ? "Tunnel cleanup completed, but VPN state still reports an error."
      : diagnosticsStillErrored
      ? "Tunnel cleanup completed, but diagnostics still show an error."
      : driverNeedsRepair
      ? "Tunnel cleanup completed, but the split tunnel driver needs repair."
      : verificationUnavailable
      ? "Tunnel cleanup completed, but verification could not finish."
      : "Tunnel cleanup completed.",
    nextStep: driverNeedsRepair
      ? "Run split tunnel driver repair next, then try connecting again."
      : cleanupError ||
          stateStillErrored ||
          diagnosticsStillErrored ||
          verificationUnavailable
        ? "Copy this result and the log file for support."
        : "Try connecting again. Copy this result for support if the error returns.",
    changed: true,
    reversible: false,
    ranAt: deps.now(),
    entries: baseEntries.concat(
      repairEntries,
      {
        label: "Cleanup",
        value: cleanupError
          ? formatErrorMessage(cleanupError)
          : stateStillErrored
          ? "completed; VPN state still reports error"
          : diagnosticsStillErrored
          ? "completed; diagnostics still show error"
          : driverNeedsRepair
          ? "completed; driver needs repair"
          : verificationUnavailable
          ? "completed; verification unavailable"
          : "completed",
        tone: cleanupError || driverNeedsRepair
          ? "bad"
          : stateStillErrored || diagnosticsStillErrored || verificationUnavailable
            ? "warn"
            : "good",
      },
      ...prefixEntries("After", stateEntriesFromResult(stateAfterResult, stateAfter)),
      ...prefixEntries(
        "After",
        diagnosticEntriesFromResult(diagnosticsAfterResult, diagnosticsAfter),
      ),
      ...prefixEntries("After driver", driverEntriesFromResult(driverAfterResult)),
    ),
  };
}

async function repairWindowsFirewall(
  deps: RepairCenterDeps,
): Promise<RepairReport> {
  const firewall = await deps.systemRepairWindowsFirewall();
  const changed =
    firewall.reset_attempted ||
    firewall.services.some((service) => service.start_attempted);

  return {
    status: windowsFirewallRepairStatus(firewall),
    summary: firewall.message,
    nextStep: windowsFirewallNextStep(firewall),
    changed,
    reversible: false,
    ranAt: deps.now(),
    entries: windowsFirewallEntries(firewall),
  };
}

async function checkRouteAssist(
  deps: RepairCenterDeps,
  settings: AppSettings,
): Promise<RepairReport> {
  const diagnostics = await deps.vpnGetDiagnostics().catch(() => null);
  const fullBypassActive = settings.enable_country_ban;
  const partialBypassActive = settings.enable_partial_country_ban;
  const routeAssistEffectivelyEnabled =
    settings.enable_api_tunneling && !partialBypassActive;
  const routeAssistValue = fullBypassActive
    ? "handled by Full Country Ban"
    : partialBypassActive
      ? "disabled by Partial Bypass"
      : routeAssistEffectivelyEnabled
        ? "enabled"
        : "disabled";
  const routeAssistNextStep = fullBypassActive
    ? "Full Country Ban already relays Roblox routing. Route Assist does not need to be enabled separately."
    : partialBypassActive
      ? "Partial Bypass already routes the Roblox join path and keeps gameplay direct."
      : routeAssistEffectivelyEnabled
        ? "Route Assist is enabled. Copy this result for support if browser login/API routing still fails."
        : "Route Assist is disabled. Enable it only when Roblox browser login or API routing needs relay help.";

  return {
    status: "checked",
    summary: "Route Assist state checked.",
    nextStep: routeAssistNextStep,
    changed: false,
    reversible: false,
    ranAt: deps.now(),
    entries: [
      {
        label: "Route Assist",
        value: routeAssistValue,
        tone:
          routeAssistEffectivelyEnabled || fullBypassActive
            ? "good"
            : "default",
      },
      ...diagnosticEntries(diagnostics),
    ],
  };
}

function checkBoostSettings(
  deps: RepairCenterDeps,
  summary: string,
  config: unknown,
): RepairReport {
  return {
    status: "checked",
    summary,
    nextStep: "No settings were changed. Copy this result for support if needed.",
    changed: false,
    reversible: false,
    ranAt: deps.now(),
    entries: [
      {
        label: "Config",
        value: formatJsonValue(config),
        mono: true,
      },
    ],
  };
}

async function repairStartupRegistration(
  deps: RepairCenterDeps,
  settings: AppSettings,
): Promise<RepairReport> {
  let before: StartupRegistrationSnapshot;
  try {
    before = await deps.systemGetStartupRegistration();
  } catch (error) {
    return {
      status: "failed",
      summary: "Startup registration repair could not capture a rollback snapshot.",
      nextStep: "Copy this result and the log file for support.",
      changed: false,
      reversible: false,
      ranAt: deps.now(),
      entries: [
        {
          label: "Snapshot",
          value: formatErrorMessage(error),
          tone: "bad",
        },
      ],
    };
  }

  let after: StartupRegistrationSnapshot;
  try {
    after = await deps.systemRepairStartupRegistration(settings.run_on_startup);
  } catch (error) {
    return {
      status: "failed",
      summary: "Startup registration repair failed.",
      nextStep: "Use Revert to restore the captured startup snapshot, or copy this result for support.",
      changed: true,
      reversible: true,
      rollback: { kind: "startup_registration", snapshot: before },
      ranAt: deps.now(),
      entries: [
        {
          label: "Run on startup",
          value: settings.run_on_startup ? "enabled" : "disabled",
        },
        {
          label: "Before",
          value: formatStartupRegistration(before),
          mono: true,
        },
        {
          label: "Repair",
          value: formatErrorMessage(error),
          tone: "bad",
        },
      ],
    };
  }

  const changed = !startupSnapshotsEqual(before, after);
  const expectedSatisfied = settings.run_on_startup ? after.exists : !after.exists;

  return {
    status: expectedSatisfied ? (changed ? "fixed" : "checked") : "failed",
    summary: expectedSatisfied
      ? changed
        ? "Startup registration repaired."
        : "Startup registration already matched settings."
      : "Startup registration still does not match settings.",
    nextStep: expectedSatisfied
      ? "Verify after the next Windows sign-in if startup behavior still looks wrong."
      : "Copy this result for support; the backend repair command completed but the registry state did not match settings.",
    changed,
    reversible: changed,
    rollback: changed
      ? { kind: "startup_registration", snapshot: before }
      : undefined,
    ranAt: deps.now(),
    entries: [
      {
        label: "Run on startup",
        value: settings.run_on_startup ? "enabled" : "disabled",
      },
      {
        label: "Before",
        value: formatStartupRegistration(before),
        mono: true,
      },
      {
        label: "After",
        value: formatStartupRegistration(after),
        tone: expectedSatisfied ? "good" : "bad",
        mono: true,
      },
    ],
  };
}

async function checkRelay(deps: RepairCenterDeps): Promise<RepairReport> {
  await deps.serverRefresh();
  const [latencies, ping] = await Promise.all([
    deps.serverGetLatencies(),
    deps.vpnGetPing().catch(() => null),
  ]);
  const best = latencies
    .filter(
      (entry): entry is LatencyEntry & { latency_ms: number } =>
        entry.latency_ms !== null,
    )
    .sort((a, b) => a.latency_ms - b.latency_ms)
    .slice(0, 5);

  return {
    status: best.length > 0 ? "checked" : "partial",
    summary: best.length > 0 ? "Relay latency refreshed." : "Relay latency data is unavailable.",
    nextStep: "Copy this result for support if the selected relay still feels wrong.",
    changed: false,
    reversible: false,
    ranAt: deps.now(),
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

async function checkInstaller(deps: RepairCenterDeps): Promise<RepairReport> {
  const driver = await deps.systemCheckDriver();
  return {
    status: driver.ready ? "checked" : driver.reboot_required ? "needs_reboot" : "partial",
    summary: "Installer/update driver state checked.",
    nextStep: driver.ready
      ? "Driver install state looks healthy."
      : "Copy this result and the log file for installer support.",
    changed: false,
    reversible: false,
    ranAt: deps.now(),
    entries: driverEntries(driver),
  };
}

type CommandOutcome<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

function commandOutcome<T>(
  result: PromiseSettledResult<T>,
): CommandOutcome<T> {
  if (result.status === "fulfilled") {
    return { ok: true, value: result.value };
  }
  return { ok: false, error: formatErrorMessage(result.reason) };
}

function resultValueOrNull<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

function diagnosticEntriesFromResult(
  result: PromiseSettledResult<DiagnosticsResponse | null>,
  diagnostics = resultValueOrNull(result),
): RepairEntry[] {
  if (result.status === "rejected") {
    return [
      {
        label: "Diagnostics",
        value: `read failed: ${formatErrorMessage(result.reason)}`,
        tone: "warn",
      },
    ];
  }

  return diagnosticEntries(diagnostics);
}

function stateEntriesFromResult(
  result: PromiseSettledResult<VpnStateResponse>,
  state = resultValueOrNull(result),
): RepairEntry[] {
  if (result.status === "rejected") {
    return [
      {
        label: "State",
        value: `read failed: ${formatErrorMessage(result.reason)}`,
        tone: "warn",
      },
    ];
  }

  if (!state) {
    return [{ label: "State", value: "not available", tone: "warn" }];
  }

  return [
    {
      label: "State",
      value: state.state,
      tone: hasTunnelCleanupStateError(state) ? "bad" : "good",
    },
    {
      label: "Error",
      value: state.error ?? "none",
      tone: state.error ? "bad" : "default",
    },
  ];
}

function driverEntriesFromResult(
  result: PromiseSettledResult<DriverCheckResponse>,
): RepairEntry[] {
  if (result.status === "rejected") {
    return [
      {
        label: "Check",
        value: `read failed: ${formatErrorMessage(result.reason)}`,
        tone: "warn",
      },
    ];
  }

  return driverEntries(result.value);
}

function driverRepairCommandFailedReport(
  deps: RepairCenterDeps,
  before: DriverCheckResponse,
  admin: { is_admin: boolean },
  error: string,
  afterCheck: CommandOutcome<DriverCheckResponse>,
): RepairReport {
  const afterReady = afterCheck.ok && afterCheck.value.ready;
  const afterEntries = afterCheck.ok
    ? prefixEntries("After", driverEntries(afterCheck.value))
    : [
        {
          label: "After check",
          value: afterCheck.error,
          tone: "warn" as const,
        },
      ];

  return {
    status: afterReady ? "partial" : "failed",
    summary: afterReady
      ? "Driver repair command failed, but the driver now reports ready."
      : "Driver repair command failed.",
    nextStep: afterReady
      ? "Try connecting once. If the issue continues, copy this result and the log file for support."
      : "Copy this result and the log file for support.",
    changed: true,
    reversible: false,
    ranAt: deps.now(),
    entries: [
      { label: "Admin", value: admin.is_admin ? "elevated" : "standard user" },
      ...prefixEntries("Before", driverEntries(before)),
      { label: "Repair error", value: error, tone: "bad" },
      ...afterEntries,
    ],
  };
}

function driverReport(
  deps: RepairCenterDeps,
  driver: DriverCheckResponse,
  status: RepairStatus,
  summary: string,
  changed: boolean,
  admin: { is_admin: boolean },
  before?: DriverCheckResponse,
): RepairReport {
  return {
    status,
    summary,
    nextStep: driverNextStep(driver, status),
    changed,
    reversible: false,
    ranAt: deps.now(),
    entries: [
      { label: "Admin", value: admin.is_admin ? "elevated" : "standard user" },
      ...(before ? prefixEntries("Before", driverEntries(before)) : []),
      ...(before ? prefixEntries("After", driverEntries(driver)) : driverEntries(driver)),
    ],
  };
}

function driverNextStep(
  driver: DriverCheckResponse,
  status: RepairStatus,
): string {
  if (status === "unsupported" || driver.status === "unsupported") {
    return "Split tunnel driver repair is only available on Windows.";
  }
  if (driver.ready) {
    return "Try connecting again. Copy this result for support if the issue continues.";
  }
  if (driver.reboot_required) {
    return "Restart Windows, then run the driver check again.";
  }
  return driver.message || "Copy this result and the log file for support.";
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

function windowsFirewallRepairStatus(
  firewall: WindowsFirewallRepairResponse,
): RepairStatus {
  if (!firewall.supported) return "unsupported";
  if (firewall.after_available) {
    return firewall.before_available && !firewall.reset_attempted ? "checked" : "fixed";
  }
  if (firewall.reboot_recommended) return "needs_reboot";
  return "failed";
}

function windowsFirewallNextStep(
  firewall: WindowsFirewallRepairResponse,
): string {
  if (!firewall.supported) {
    return "Windows Firewall repair is only available on Windows.";
  }
  if (firewall.after_available) {
    return "Try connecting again. Copy this result for support if the IPv6 block error returns.";
  }
  if (!firewall.is_admin) {
    return "Relaunch SwiftTunnel as Administrator, then run Windows Firewall repair again.";
  }
  if (firewall.reboot_recommended) {
    return "Restart Windows, then run Windows Firewall repair again. If it still fails, run DISM and SFC from an elevated Command Prompt.";
  }
  return "Run DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow from an elevated Command Prompt. Reboot, then try SwiftTunnel again.";
}

function windowsFirewallEntries(
  firewall: WindowsFirewallRepairResponse,
): RepairEntry[] {
  const entries: RepairEntry[] = [
    { label: "Admin", value: firewall.is_admin ? "elevated" : "standard user" },
    {
      label: "Before advfirewall",
      value: firewall.before_available ? "available" : "missing",
      tone: firewall.before_available ? "good" : "bad",
    },
    {
      label: "After advfirewall",
      value: firewall.after_available ? "available" : "missing",
      tone: firewall.after_available ? "good" : "bad",
    },
    {
      label: "Reset",
      value: firewall.reset_attempted
        ? firewall.reset_succeeded
          ? "completed"
          : "failed"
        : firewall.before_available
          ? "not needed"
          : "not attempted",
      tone: firewall.reset_attempted
        ? firewall.reset_succeeded
          ? "good"
          : "bad"
        : firewall.before_available
          ? "default"
          : "warn",
    },
  ];

  if (firewall.backup_path) {
    entries.push({
      label: "Firewall backup",
      value: firewall.backup_path,
      tone: "good",
      mono: true,
    });
  }

  for (const service of firewall.services) {
    entries.push({
      label: `Service ${service.name}`,
      value: service.start_attempted
        ? `${service.state}; start ${service.start_succeeded ? "completed" : "failed"}`
        : service.state,
      tone:
        service.state === "RUNNING"
          ? "good"
          : service.start_attempted
            ? "bad"
            : "warn",
    });
  }

  if (!firewall.after_available) {
    entries.push({
      label: "Probe before",
      value: firewall.probe_before,
      tone: "bad",
      mono: true,
    });
    entries.push({
      label: "Probe after",
      value: firewall.probe_after,
      tone: "bad",
      mono: true,
    });
    if (firewall.reset_output) {
      entries.push({
        label: "Reset output",
        value: firewall.reset_output,
        tone: firewall.reset_succeeded ? "warn" : "bad",
        mono: true,
      });
    }
  }

  return entries;
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

function hasTunnelCleanupDiagnosticError(
  diagnostics: DiagnosticsResponse | null,
): boolean {
  return (
    diagnostics?.last_validation_result === "error" ||
    diagnostics?.binding_stage === "error"
  );
}

function hasTunnelCleanupStateError(state: VpnStateResponse): boolean {
  return state.state === "error" || state.error !== null;
}

function errorReport(
  deps: Pick<RepairCenterDeps, "now">,
  summary: string,
  error: string,
): RepairReport {
  return {
    status: "failed",
    summary,
    nextStep: "Copy this result and the log file for support.",
    changed: false,
    reversible: false,
    ranAt: deps.now(),
    entries: [{ label: "Error", value: error, tone: "bad" }],
  };
}

function prefixEntries(prefix: string, entries: RepairEntry[]): RepairEntry[] {
  return entries.map((entry) => ({
    ...entry,
    label: `${prefix} ${entry.label.toLowerCase()}`,
  }));
}

function adapterName(adapter: NetworkAdapterInfo | null | undefined): string | null {
  if (!adapter) return null;
  return adapter.friendly_name || adapter.description || adapter.guid;
}

function startupSnapshotsEqual(
  a: StartupRegistrationSnapshot,
  b: StartupRegistrationSnapshot,
): boolean {
  return a.exists === b.exists && a.value === b.value;
}

function formatStartupRegistration(snapshot: StartupRegistrationSnapshot): string {
  if (!snapshot.exists) return "absent";
  return snapshot.value || "present with empty value";
}

function formatJsonValue(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "undefined";
  } catch (error) {
    return `Could not serialize config: ${formatErrorMessage(error)}`;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
