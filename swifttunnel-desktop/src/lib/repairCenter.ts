import type {
  AppSettings,
  DiagnosticsResponse,
  DriverCheckResponse,
  LatencyEntry,
  NetworkAdapterInfo,
  VpnStateResponse,
} from "./types";
import type { StartupRegistrationSnapshot } from "./commands";

export type RepairIssueId =
  | "driver"
  | "adapter"
  | "tunnel_cleanup"
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

export interface RepairContext {
  settings: AppSettings;
}

export interface RepairCenterDeps {
  now: () => number;
  serverGetLatencies: () => Promise<LatencyEntry[]>;
  serverRefresh: () => Promise<string>;
  systemCheckDriver: () => Promise<DriverCheckResponse>;
  systemCleanup: () => Promise<void>;
  systemGetStartupRegistration: () => Promise<StartupRegistrationSnapshot>;
  systemIsAdmin: () => Promise<{ is_admin: boolean }>;
  systemRepairDriver: () => Promise<DriverCheckResponse>;
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

export async function runRepairIssue(
  issue: RepairIssueId,
  deps: RepairCenterDeps,
  context: RepairContext,
): Promise<RepairReport> {
  try {
    switch (issue) {
      case "driver":
        return await repairDriver(deps);
      case "adapter":
        return await checkAdapterRouting(deps, context.settings);
      case "tunnel_cleanup":
        return await repairTunnelCleanup(deps);
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
    return errorReport(deps, "Repair failed", String(error));
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
    return errorReport(deps, "Revert failed", String(error));
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

  const after = await deps.systemRepairDriver();
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
  const [adapters, diagnostics] = await Promise.all([
    deps.vpnListNetworkAdapters(),
    deps.vpnGetDiagnostics().catch(() => null),
  ]);
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
      ...diagnosticEntries(diagnostics),
    ],
  };
}

async function repairTunnelCleanup(
  deps: RepairCenterDeps,
): Promise<RepairReport> {
  const [state, diagnosticsBefore] = await Promise.all([
    deps.vpnGetState(),
    deps.vpnGetDiagnostics().catch(() => null),
  ]);
  const cleanupNeeded =
    state.state === "error" ||
    state.error !== null ||
    hasTunnelCleanupDiagnosticError(diagnosticsBefore);
  const baseEntries: RepairEntry[] = [
    { label: "State", value: state.state },
    {
      label: "Split tunnel active",
      value: state.split_tunnel_active ? "yes" : "no",
    },
    ...diagnosticEntries(diagnosticsBefore),
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
      repairEntries.push({ label: "Disconnect", value: String(error), tone: "warn" });
    }
  }

  let cleanupError: unknown = null;
  try {
    await deps.systemCleanup();
  } catch (error) {
    cleanupError = error;
  }
  const diagnosticsAfter = await deps.vpnGetDiagnostics().catch(() => null);
  const diagnosticsStillErrored =
    hasTunnelCleanupDiagnosticError(diagnosticsAfter);
  const status: RepairStatus = cleanupError
    ? "failed"
    : diagnosticsStillErrored
      ? "partial"
      : "fixed";

  return {
    status,
    summary: cleanupError
      ? "Tunnel cleanup failed."
      : diagnosticsStillErrored
      ? "Tunnel cleanup completed, but diagnostics still show an error."
      : "Tunnel cleanup completed.",
    nextStep: cleanupError || diagnosticsStillErrored
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
          ? String(cleanupError)
          : diagnosticsStillErrored
          ? "completed; diagnostics still show error"
          : "completed",
        tone: cleanupError ? "bad" : diagnosticsStillErrored ? "warn" : "good",
      },
      ...diagnosticEntries(diagnosticsAfter),
    ),
  };
}

async function checkRouteAssist(
  deps: RepairCenterDeps,
  settings: AppSettings,
): Promise<RepairReport> {
  const diagnostics = await deps.vpnGetDiagnostics().catch(() => null);
  return {
    status: "checked",
    summary: "Route Assist state checked.",
    nextStep: settings.enable_api_tunneling
      ? "Route Assist is enabled. Copy this result for support if browser login/API routing still fails."
      : "Route Assist is disabled. Enable it only when Roblox browser login or API routing needs relay help.",
    changed: false,
    reversible: false,
    ranAt: deps.now(),
    entries: [
      {
        label: "Route Assist",
        value: settings.enable_api_tunneling ? "enabled" : "disabled",
        tone: settings.enable_api_tunneling ? "good" : "default",
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
        value: JSON.stringify(config),
        mono: true,
      },
    ],
  };
}

async function repairStartupRegistration(
  deps: RepairCenterDeps,
  settings: AppSettings,
): Promise<RepairReport> {
  const before = await deps.systemGetStartupRegistration();
  const after = await deps.systemRepairStartupRegistration(settings.run_on_startup);
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
    nextStep: driver.ready
      ? "Try connecting again. Copy this result for support if the issue continues."
      : driver.reboot_required
        ? "Restart Windows, then run the driver check again."
        : driver.message || "Copy this result and the log file for support.",
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
