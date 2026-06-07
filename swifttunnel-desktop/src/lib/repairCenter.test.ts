import { describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "./settings";
import {
  restoreRepairRollback,
  runRepairIssue,
  type RepairCenterDeps,
} from "./repairCenter";
import type {
  DiagnosticsResponse,
  DriverCheckResponse,
  VpnStateResponse,
} from "./types";

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

function makeDeps(overrides: Partial<RepairCenterDeps> = {}): RepairCenterDeps {
  return {
    now: () => 1_800_000_000_000,
    serverGetLatencies: vi.fn().mockResolvedValue([{ region: "Singapore", latency_ms: 18 }]),
    serverRefresh: vi.fn().mockResolvedValue("ok"),
    systemCheckDriver: vi.fn().mockResolvedValue(readyDriver),
    systemCleanup: vi.fn().mockResolvedValue(undefined),
    systemGetStartupRegistration: vi.fn().mockResolvedValue({
      exists: false,
      value: null,
    }),
    systemIsAdmin: vi.fn().mockResolvedValue({ is_admin: true }),
    systemRepairDriver: vi.fn().mockResolvedValue(readyDriver),
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

  it("does not cleanup for superficially similar healthy diagnostic text", async () => {
    const deps = makeDeps();

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("checked");
    expect(deps.vpnDisconnect).not.toHaveBeenCalled();
    expect(deps.systemCleanup).not.toHaveBeenCalled();
  });

  it("runs cleanup for structured tunnel error state", async () => {
    const deps = makeDeps({
      vpnGetState: vi.fn().mockResolvedValue({
        ...disconnectedState,
        state: "error",
        error: "Split tunnel driver not available",
      }),
    });

    const report = await runRepairIssue("tunnel_cleanup", deps, {
      settings: DEFAULT_SETTINGS,
    });

    expect(report.status).toBe("fixed");
    expect(deps.systemCleanup).toHaveBeenCalledTimes(1);
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
    expect(deps.systemCleanup).toHaveBeenCalledTimes(1);
  });

  it("keeps cleanup context when system cleanup fails", async () => {
    const deps = makeDeps({
      systemCleanup: vi.fn().mockRejectedValue(new Error("cleanup denied")),
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
      value: "Error: cleanup denied",
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
});
