import { describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "./settings";
import {
  parseSavedRepairResult,
  restoreRepairRollback,
  runRepairIssue,
  type RepairCenterDeps,
} from "./repairCenter";
import type {
  DiagnosticsResponse,
  DriverCheckResponse,
  VpnStateResponse,
  WindowsFirewallRepairResponse,
} from "./types";
import type { NetworkRepairResponse } from "./commands";

const readyDriver: DriverCheckResponse = {
  installed: true,
  version: "3.6.2",
  ready: true,
  status: "ready",
  message: "Windows Packet Filter driver is ready.",
  reboot_required: false,
  recommended_action: "none",
};

const missingDriver: DriverCheckResponse = {
  installed: false,
  version: null,
  ready: false,
  status: "not_installed",
  message: "Windows Packet Filter driver is missing.",
  reboot_required: false,
  recommended_action: "install",
};

const disconnectedState: VpnStateResponse = {
  state: "disconnected",
  region: null,
  server_endpoint: null,
  assigned_ip: null,
  split_tunnel_active: false,
  tunneled_processes: [],
  error: null,
};

const healthyDiagnostics: DiagnosticsResponse = {
  adapter_name: "Error-prone Wi-Fi name that is still healthy",
  adapter_guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  selected_if_index: 7,
  resolved_if_index: 7,
  has_default_route: true,
  route_resolution_source: "internet_fallback",
  route_resolution_target_ip: "8.8.8.8",
  manual_binding_active: false,
  binding_reason: "Selected by route",
  binding_stage: "exact_route_match",
  cached_override_used: false,
  network_signature: "sig",
  last_validation_result: "selected_exact_route_match",
  packets_tunneled: 10,
  packets_bypassed: 20,
};

const errorDiagnostics: DiagnosticsResponse = {
  ...healthyDiagnostics,
  binding_stage: "error",
  last_validation_result: "error",
};

const healthyFirewall: WindowsFirewallRepairResponse = {
  supported: true,
  is_admin: true,
  before_available: true,
  after_available: true,
  reset_attempted: false,
  reset_succeeded: false,
  reboot_recommended: false,
  backup_path: null,
  message: "Windows Firewall already accepts advfirewall commands.",
  probe_before: "Domain Profile Settings",
  probe_after: "not needed",
  reset_output: null,
  services: [
    {
      name: "BFE",
      display_name: "Base Filtering Engine",
      state: "RUNNING",
      start_attempted: false,
      start_succeeded: false,
      message: "service already running",
    },
    {
      name: "MpsSvc",
      display_name: "Windows Defender Firewall",
      state: "RUNNING",
      start_attempted: false,
      start_succeeded: false,
      message: "service already running",
    },
  ],
};

const healthyNetworkRepair: NetworkRepairResponse = {
  supported: true,
  is_admin: true,
  overall: "healthy",
  steps: [
    {
      id: "adapter_modes",
      label: "Adapter packet filter modes",
      status: "healthy",
      detail: "All 2 adapter(s) already had default packet filter modes.",
    },
    {
      id: "tunnel_marker",
      label: "Crash marker",
      status: "healthy",
      detail: "No crash marker present.",
    },
    {
      id: "dns",
      label: "DNS cache",
      status: "healthy",
      detail: "DNS cache flushed.",
    },
  ],
};

function makeDeps(overrides: Partial<RepairCenterDeps> = {}): RepairCenterDeps {
  return {
    now: () => 1_800_000_000_000,
    serverGetLatencies: vi.fn().mockResolvedValue([{ region: "Singapore", latency_ms: 18 }]),
    serverRefresh: vi.fn().mockResolvedValue("ok"),
    systemCheckDriver: vi.fn().mockResolvedValue(readyDriver),
    systemCleanupTunnelState: vi.fn().mockResolvedValue(undefined),
    systemGetStartupRegistration: vi.fn().mockResolvedValue({
      exists: false,
      value: null,
    }),
    systemIsAdmin: vi.fn().mockResolvedValue({ is_admin: true }),
    systemRepairDriver: vi.fn().mockResolvedValue(readyDriver),
    systemRepairNetwork: vi.fn().mockResolvedValue(healthyNetworkRepair),
    systemRepairWindowsFirewall: vi.fn().mockResolvedValue(healthyFirewall),
    systemRepairStartupRegistration: vi.fn().mockResolvedValue({
      exists: true,
      value: "\"C:\\Program Files\\SwiftTunnel\\SwiftTunnel.exe\" --startup",
    }),
    systemRestoreStartupRegistration: vi.fn().mockResolvedValue({
      exists: false,
      value: null,
    }),
    vpnDisconnect: vi.fn().mockResolvedValue(undefined),
    vpnGetDiagnostics: vi.fn().mockResolvedValue(healthyDiagnostics),
    vpnGetPing: vi.fn().mockResolvedValue(null),
    vpnGetState: vi.fn().mockResolvedValue(disconnectedState),
    vpnListNetworkAdapters: vi.fn().mockResolvedValue([
      {
        guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        friendly_name: "Wi-Fi",
        description: "Intel Wi-Fi",
        if_index: 7,
        is_up: true,
        is_default_route: true,
        kind: "wifi",
      },
    ]),
    ...overrides,
  };
}

describe("repair center logic", () => {
  it("runs internet recovery while disconnected even when no error state is present", async () => {
    const deps = makeDeps({
      systemRepairNetwork: vi.fn().mockResolvedValue({
        ...healthyNetworkRepair,
        overall: "fixed",
        steps: [
          {
            id: "adapter_modes",
            label: "Adapter packet filter modes",
            status: "fixed",
            detail: "1 adapter(s) were stuck — reset and verified.",
          },
        ],
      }),
    });

    const report = await runRepairIssue("no_internet", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("fixed");
    expect(report.changed).toBe(true);
    expect(deps.systemRepairNetwork).toHaveBeenCalledTimes(1);
  });

  it("reports healthy with no system change when internet recovery finds nothing", async () => {
    const deps = makeDeps();

    const report = await runRepairIssue("no_internet", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("healthy");
    expect(report.changed).toBe(false);
  });

  it("does not run internet recovery while a session is active", async () => {
    const deps = makeDeps({
      vpnGetState: vi.fn().mockResolvedValue({
        ...disconnectedState,
        state: "connected",
      }),
    });

    const report = await runRepairIssue("no_internet", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("partial");
    expect(report.changed).toBe(false);
    expect(deps.systemRepairNetwork).not.toHaveBeenCalled();
  });

  it("points failed adapter-mode recovery at driver repair", async () => {
    const deps = makeDeps({
      systemRepairNetwork: vi.fn().mockResolvedValue({
        ...healthyNetworkRepair,
        overall: "failed",
        steps: [
          {
            id: "adapter_modes",
            label: "Adapter packet filter modes",
            status: "failed",
            detail: "driver installed but could not be opened",
          },
        ],
      }),
    });

    const report = await runRepairIssue("no_internet", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("failed");
    expect(report.nextStep).toContain("split tunnel driver repair");
  });

  it("runs driver repair even when global health is ready so adapter bindings can be refreshed", async () => {
    const deps = makeDeps({
      systemRepairDriver: vi.fn().mockResolvedValue(readyDriver),
    });

    const report = await runRepairIssue("driver", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("fixed");
    expect(report.changed).toBe(true);
    expect(deps.systemRepairDriver).toHaveBeenCalledTimes(1);
  });

  it("does not run driver repair when Windows requires a reboot first", async () => {
    const deps = makeDeps({
      systemCheckDriver: vi.fn().mockResolvedValue({
        ...readyDriver,
        ready: false,
        status: "reboot_required",
        message: "Reboot required to finish driver installation.",
        reboot_required: true,
        recommended_action: "reboot",
      }),
    });

    const report = await runRepairIssue("driver", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("needs_reboot");
    expect(deps.systemRepairDriver).not.toHaveBeenCalled();
  });

  it("runs driver repair once and reports fixed when backend health becomes ready", async () => {
    const deps = makeDeps({
      systemCheckDriver: vi.fn().mockResolvedValue(missingDriver),
      systemRepairDriver: vi.fn().mockResolvedValue(readyDriver),
    });

    const report = await runRepairIssue("driver", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("fixed");
    expect(report.changed).toBe(true);
    expect(deps.systemRepairDriver).toHaveBeenCalledTimes(1);
  });

  it("keeps driver context when the repair command rejects", async () => {
    const systemCheckDriver = vi.fn().mockResolvedValue(readyDriver);
    const deps = makeDeps({
      systemCheckDriver,
      systemRepairDriver: vi.fn().mockRejectedValue(new Error("repair crashed")),
    });

    const report = await runRepairIssue("driver", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("partial");
    expect(report.summary).toContain("command failed");
    expect(report.entries).toContainEqual({
      label: "Repair error",
      value: "repair crashed",
      tone: "bad",
    });
    expect(systemCheckDriver).toHaveBeenCalledTimes(2);
  });

  it("reports failed when adapter inventory cannot be read", async () => {
    const deps = makeDeps({
      vpnListNetworkAdapters: vi
        .fn()
        .mockRejectedValue(new Error("adapter API unavailable")),
    });

    const report = await runRepairIssue("adapter", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("failed");
    expect(report.changed).toBe(false);
    expect(report.entries).toContainEqual({
      label: "Adapter inventory",
      value: "adapter API unavailable",
      tone: "bad",
    });
  });

  it("does not cleanup for superficially similar healthy diagnostic text", async () => {
    const deps = makeDeps();

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("checked");
    expect(deps.vpnDisconnect).not.toHaveBeenCalled();
    expect(deps.systemCleanupTunnelState).not.toHaveBeenCalled();
  });

  it("does not cleanup when VPN state cannot be read", async () => {
    const deps = makeDeps({
      vpnGetState: vi.fn().mockRejectedValue(new Error("state unavailable")),
      vpnGetDiagnostics: vi.fn().mockResolvedValue(errorDiagnostics),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("failed");
    expect(report.summary).toContain("could not read VPN state");
    expect(deps.systemCleanupTunnelState).not.toHaveBeenCalled();
  });

  it("runs cleanup for structured tunnel error state", async () => {
    const deps = makeDeps({
      vpnGetState: vi
        .fn()
        .mockResolvedValueOnce({
          ...disconnectedState,
          state: "error",
          error: "Split tunnel driver not available",
        })
        .mockResolvedValueOnce(disconnectedState),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("fixed");
    expect(deps.systemCleanupTunnelState).toHaveBeenCalledTimes(1);
  });

  it("stops cleanup when disconnect fails for an active error state", async () => {
    const deps = makeDeps({
      vpnGetState: vi.fn().mockResolvedValue({
        ...disconnectedState,
        state: "error",
        split_tunnel_active: true,
        error: "reader failed",
      }),
      vpnDisconnect: vi.fn().mockRejectedValue(new Error("disconnect denied")),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("failed");
    expect(report.summary).toContain("disconnect failed");
    expect(deps.systemCleanupTunnelState).not.toHaveBeenCalled();
  });

  it("reports partial when cleanup leaves structured diagnostic errors", async () => {
    const deps = makeDeps({
      vpnGetDiagnostics: vi
        .fn()
        .mockResolvedValueOnce(errorDiagnostics)
        .mockResolvedValueOnce(errorDiagnostics),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("partial");
    expect(report.summary).toContain("diagnostics still show an error");
    expect(deps.systemCleanupTunnelState).toHaveBeenCalledTimes(1);
  });

  it("reports partial when cleanup verification cannot read diagnostics", async () => {
    const deps = makeDeps({
      vpnGetDiagnostics: vi
        .fn()
        .mockResolvedValueOnce(errorDiagnostics)
        .mockRejectedValueOnce(new Error("diagnostics unavailable")),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("partial");
    expect(report.summary).toContain("verification could not finish");
  });

  it("reports partial when cleanup leaves the driver needing repair", async () => {
    const deps = makeDeps({
      systemCheckDriver: vi.fn().mockResolvedValue(missingDriver),
      vpnGetDiagnostics: vi
        .fn()
        .mockResolvedValueOnce(errorDiagnostics)
        .mockResolvedValueOnce(healthyDiagnostics),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("partial");
    expect(report.summary).toContain("driver needs repair");
    expect(report.nextStep).toContain("driver repair");
  });

  it("keeps cleanup context when system cleanup fails", async () => {
    const deps = makeDeps({
      systemCleanupTunnelState: vi.fn().mockRejectedValue(
        new Error("cleanup denied"),
      ),
      vpnGetDiagnostics: vi
        .fn()
        .mockResolvedValueOnce(errorDiagnostics)
        .mockResolvedValueOnce(errorDiagnostics),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("failed");
    expect(report.entries).toContainEqual({
      label: "Cleanup",
      value: "cleanup denied",
      tone: "bad",
    });
  });

  it("repairs Windows Firewall when advfirewall is restored after reset", async () => {
    const deps = makeDeps({
      systemRepairWindowsFirewall: vi.fn().mockResolvedValue({
        ...healthyFirewall,
        before_available: false,
        reset_attempted: true,
        reset_succeeded: true,
        backup_path:
          "C:\\ProgramData\\SwiftTunnel\\firewall-backups\\windows-firewall-before-reset.wfw",
        message: "Windows Firewall policy reset repaired advfirewall commands.",
        probe_before:
          "The following command was not found: advfirewall firewall add rule.",
        probe_after: "Domain Profile Settings",
        reset_output: "Ok.",
      }),
    });

    const report = await runRepairIssue("windows_firewall", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("fixed");
    expect(report.changed).toBe(true);
    expect(report.nextStep).toContain("Try connecting again");
    expect(report.entries).toContainEqual({
      label: "Reset",
      value: "completed",
      tone: "good",
    });
    expect(report.entries).toContainEqual({
      label: "After advfirewall",
      value: "available",
      tone: "good",
    });
  });

  it("does not report fixed for a superficially similar unrepaired advfirewall error", async () => {
    const deps = makeDeps({
      systemRepairWindowsFirewall: vi.fn().mockResolvedValue({
        ...healthyFirewall,
        before_available: false,
        after_available: false,
        reset_attempted: true,
        reset_succeeded: false,
        message: "Windows Firewall repair did not restore advfirewall commands.",
        probe_before:
          "The following command was not found: advfirewall firewall add rule.",
        probe_after:
          "The following command was not found: advfirewall firewall show rule.",
        reset_output:
          "The following command was not found: advfirewall reset export.",
      }),
    });

    const report = await runRepairIssue("windows_firewall", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("failed");
    expect(report.changed).toBe(true);
    expect(report.nextStep).toContain("DISM /Online /Cleanup-Image /RestoreHealth");
    expect(report.entries).toContainEqual({
      label: "After advfirewall",
      value: "missing",
      tone: "bad",
    });
  });

  it("captures startup rollback and can restore it", async () => {
    const settings = { ...DEFAULT_SETTINGS, run_on_startup: true };
    const deps = makeDeps();

    const report = await runRepairIssue("startup", deps, { settings });

    expect(report.status).toBe("fixed");
    expect(report.rollback).toEqual({
      kind: "startup_registration",
      snapshot: { exists: false, value: null },
    });

    const restored = await restoreRepairRollback(deps, report.rollback!);
    expect(restored.status).toBe("fixed");
    expect(deps.systemRestoreStartupRegistration).toHaveBeenCalledWith({
      exists: false,
      value: null,
    });
  });

  it("reports partial when startup rollback read-back differs from the snapshot", async () => {
    const deps = makeDeps({
      systemRestoreStartupRegistration: vi.fn().mockResolvedValue({
        exists: true,
        value: "\"C:\\Program Files\\SwiftTunnel\\SwiftTunnel.exe\" --startup",
      }),
    });

    const restored = await restoreRepairRollback(deps, {
      kind: "startup_registration",
      snapshot: { exists: false, value: null },
    });

    expect(restored.status).toBe("partial");
    expect(restored.summary).toContain("differs from the saved snapshot");
  });

  it("returns an error report for stale rollback kinds", async () => {
    const deps = makeDeps();

    const restored = await restoreRepairRollback(deps, {
      kind: "legacy_startup_registration",
      snapshot: { exists: true, value: "legacy" },
    } as never);

    expect(restored.status).toBe("failed");
    expect(restored.summary).toBe("Unknown rollback kind");
    expect(deps.systemRestoreStartupRegistration).not.toHaveBeenCalled();
  });

  it("parses a valid saved repair result", () => {
    const parsed = parseSavedRepairResult(
      JSON.stringify({
        issue: "driver",
        report: {
          status: "checked",
          summary: "ok",
          nextStep: "next",
          changed: false,
          reversible: false,
          ranAt: 1_800_000_000_000,
          entries: [],
        },
      }),
    );

    expect(parsed?.issue).toBe("driver");
    expect(parsed?.report.status).toBe("checked");
  });

  it("ignores stale saved repair statuses", () => {
    const parsed = parseSavedRepairResult(
      JSON.stringify({
        issue: "driver",
        report: {
          status: "legacy_success",
          summary: "ok",
          nextStep: "next",
          changed: false,
          reversible: false,
          ranAt: 1_800_000_000_000,
          entries: [],
        },
      }),
    );

    expect(parsed).toBeNull();
  });

  it("ignores stale saved rollback kinds", () => {
    const parsed = parseSavedRepairResult(
      JSON.stringify({
        issue: "startup",
        report: {
          status: "failed",
          summary: "failed",
          nextStep: "next",
          changed: true,
          reversible: true,
          ranAt: 1_800_000_000_000,
          entries: [],
          rollback: {
            kind: "legacy_startup_registration",
            snapshot: { exists: true, value: "legacy" },
          },
        },
      }),
    );

    expect(parsed).toBeNull();
  });
});
