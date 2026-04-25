import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  vpnGetState,
  vpnPreflightBinding,
  vpnConnect,
  vpnDisconnect,
  vpnGetThroughput,
  vpnGetPing,
  vpnGetDiagnostics,
  systemCheckDriver,
  systemInstallDriver,
  systemRepairDriver,
  systemResetDriver,
} = vi.hoisted(() => ({
  vpnGetState: vi.fn(),
  vpnPreflightBinding: vi.fn(),
  vpnConnect: vi.fn(),
  vpnDisconnect: vi.fn(),
  vpnGetThroughput: vi.fn(),
  vpnGetPing: vi.fn(),
  vpnGetDiagnostics: vi.fn(),
  systemCheckDriver: vi.fn(),
  systemInstallDriver: vi.fn(),
  systemRepairDriver: vi.fn(),
  systemResetDriver: vi.fn(),
}));

const { notify } = vi.hoisted(() => ({
  notify: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  vpnGetState,
  vpnPreflightBinding,
  vpnConnect,
  vpnDisconnect,
  vpnGetThroughput,
  vpnGetPing,
  vpnGetDiagnostics,
  systemCheckDriver,
  systemInstallDriver,
  systemRepairDriver,
  systemResetDriver,
}));

vi.mock("../lib/notifications", () => ({
  notify,
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./vpnStore")).useVpnStore;
}

function connectedState(region: string) {
  return {
    state: "connected" as const,
    region,
    server_endpoint: "1.2.3.4:51821",
    assigned_ip: "10.0.0.2",
    relay_auth_mode: "ticket",
    split_tunnel_active: true,
    tunneled_processes: ["RobloxPlayerBeta.exe"],
    error: null,
  };
}

function driverStatus(overrides = {}) {
  return {
    installed: true,
    version: "3.6.2",
    ready: true,
    status: "ready",
    message: "Windows Packet Filter driver is ready.",
    reboot_required: false,
    recommended_action: "none",
    ...overrides,
  };
}

describe("stores/vpnStore", () => {
  beforeEach(() => {
    vpnGetState.mockReset();
    vpnPreflightBinding.mockReset();
    vpnConnect.mockReset();
    vpnDisconnect.mockReset();
    vpnGetThroughput.mockReset();
    vpnGetPing.mockReset();
    vpnGetDiagnostics.mockReset();
    systemCheckDriver.mockReset();
    systemInstallDriver.mockReset();
    systemRepairDriver.mockReset();
    systemResetDriver.mockReset();
    notify.mockReset();

    vpnGetDiagnostics.mockResolvedValue(null);
    vpnPreflightBinding.mockResolvedValue({
      status: "ok",
      reason: "validated",
      network_signature: "sig",
      route_resolution_source: "internet_fallback",
      route_resolution_target_ip: "8.8.8.8",
      resolved_if_index: 7,
      recommended_guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      cached_override_used: false,
      binding_stage: "exact_route_match",
      candidates: [],
    });
    notify.mockResolvedValue(undefined);
  });

  it("repairs missing split tunnel driver before connecting", async () => {
    systemCheckDriver.mockResolvedValueOnce(
      driverStatus({
        installed: false,
        version: null,
        ready: false,
        status: "missing",
        message: "Split tunnel driver not available (Windows Packet Filter driver).",
        recommended_action: "install",
      }),
    );
    systemRepairDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemCheckDriver).toHaveBeenCalledTimes(1);
    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(systemInstallDriver).not.toHaveBeenCalled();
    expect(vpnConnect).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().driverSetupState).toBe("idle");
    expect(useVpnStore.getState().error).toBeNull();
  });

  it("stops connect and surfaces actionable error when repair cannot make driver ready", async () => {
    systemCheckDriver.mockResolvedValueOnce(
      driverStatus({
        installed: false,
        version: null,
        ready: false,
        status: "missing",
        message: "Split tunnel driver not available (Windows Packet Filter driver).",
        recommended_action: "install",
      }),
    );
    systemRepairDriver.mockResolvedValueOnce(
      driverStatus({
        installed: false,
        version: null,
        ready: false,
        status: "missing",
        message: "Driver repair failed: network timeout",
        recommended_action: "install",
      }),
    );

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().driverSetupState).toBe("error");
    expect(useVpnStore.getState().error).toContain("network timeout");
  });

  it("keeps adapter-choice preflight visible instead of returning to silent ready", async () => {
    systemCheckDriver.mockResolvedValueOnce(driverStatus());
    vpnPreflightBinding.mockResolvedValueOnce({
      status: "ambiguous",
      reason: "SwiftTunnel needs a one-time adapter choice for this network.",
      network_signature: "sig",
      route_resolution_source: "internet_fallback",
      route_resolution_target_ip: "8.8.8.8",
      resolved_if_index: 7,
      recommended_guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      cached_override_used: false,
      binding_stage: "smart_auto",
      candidates: [
        {
          guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
          friendly_name: "Ethernet",
          description: "Intel Ethernet",
          if_index: 7,
          is_up: true,
          is_default_route: true,
          kind: "ethernet",
          stage: "smart_auto",
          reason: "Candidate available for Smart Auto binding",
          score: 100,
        },
      ],
    });

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("disconnected");
    expect(useVpnStore.getState().error).toContain("adapter choice");
    expect(useVpnStore.getState().bindingPreflight?.status).toBe("ambiguous");
  });

  it("repairs driver bindings once when preflight cannot see WinpkFilter adapters", async () => {
    systemCheckDriver.mockResolvedValueOnce(driverStatus());
    vpnPreflightBinding
      .mockResolvedValueOnce({
        status: "unrecoverable",
        reason:
          "SwiftTunnel could not see any WinpkFilter-bound network adapters. Repair the split tunnel driver, then try again.",
        network_signature: "source=internet_fallback;if_index=8;next_hop=1;up=",
        route_resolution_source: "internet_fallback",
        route_resolution_target_ip: "128.116.1.1",
        resolved_if_index: 8,
        recommended_guid: null,
        cached_override_used: false,
        binding_stage: "unrecoverable",
        candidates: [],
      })
      .mockResolvedValueOnce({
        status: "ok",
        reason: "Split tunnel adapter binding validated.",
        network_signature:
          "source=internet_fallback;if_index=8;next_hop=1;up=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        route_resolution_source: "internet_fallback",
        route_resolution_target_ip: "128.116.1.1",
        resolved_if_index: 8,
        recommended_guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        cached_override_used: false,
        binding_stage: "exact_route_match",
        candidates: [],
      });
    systemRepairDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(vpnPreflightBinding).toHaveBeenCalledTimes(2);
    expect(vpnConnect).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(useVpnStore.getState().bindingPreflight).toBeNull();
    expect(useVpnStore.getState().state).toBe("connected");
  });

  it("ignores stale disconnected events while a connect attempt is pending", async () => {
    const useVpnStore = await loadStore();
    useVpnStore.setState({
      state: "fetching_config",
      error: null,
      connectAttemptInFlight: true,
    });

    useVpnStore.getState().handleStateEvent({
      state: "disconnected",
      region: null,
      server_endpoint: null,
      assigned_ip: null,
      error: null,
    });

    expect(useVpnStore.getState().state).toBe("fetching_config");
    expect(useVpnStore.getState().connectAttemptInFlight).toBe(true);
  });

  it("does not let stale disconnected events clear a visible connect error", async () => {
    const useVpnStore = await loadStore();
    useVpnStore.setState({
      state: "error",
      error: "Relay preflight enforcement blocked connection.",
      connectAttemptInFlight: false,
    });

    useVpnStore.getState().handleStateEvent({
      state: "disconnected",
      region: null,
      server_endpoint: null,
      assigned_ip: null,
      error: null,
    });

    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain("preflight enforcement");
  });

  it("manual repair action marks driver as installed", async () => {
    systemRepairDriver.mockResolvedValue(driverStatus());

    const useVpnStore = await loadStore();
    await useVpnStore.getState().repairDriver();

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().driverSetupState).toBe("installed");
    expect(useVpnStore.getState().driverSetupError).toBeNull();
  });

  it("reboot-required repair result latches one-shot flag without reconnecting", async () => {
    systemRepairDriver.mockResolvedValue(
      driverStatus({
        ready: false,
        status: "reboot_required",
        message: "Reboot required to finish driver installation.",
        reboot_required: true,
        recommended_action: "reboot",
      }),
    );

    const useVpnStore = await loadStore();
    await expect(useVpnStore.getState().repairDriver()).rejects.toThrow(
      "Reboot required to finish driver installation.",
    );

    expect(useVpnStore.getState().driverResetAttempted).toBe(true);
    expect(useVpnStore.getState().driverStatus?.recommended_action).toBe("reboot");
    expect(useVpnStore.getState().driverSetupError).toContain("Reboot required");
  });

  it("does not run repair when driver check already requires reboot", async () => {
    systemCheckDriver.mockResolvedValueOnce(
      driverStatus({
        ready: false,
        status: "reboot_required",
        message: "Reboot required to finish driver installation.",
        reboot_required: true,
        recommended_action: "reboot",
      }),
    );

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().driverResetAttempted).toBe(true);
    expect(useVpnStore.getState().driverSetupError).toContain("Reboot required");
  });

  it("failed reset preserves reboot-required context and latches the one-shot flag", async () => {
    systemResetDriver.mockRejectedValue(
      new Error("Administrator privileges required to restart the driver service."),
    );

    const useVpnStore = await loadStore();
    useVpnStore.setState({
      state: "error",
      error:
        "Reboot required to finish driver installation. Windows signaled exit 3010.",
      driverSetupState: "error",
      driverSetupError:
        "Reboot required to finish driver installation. Windows signaled exit 3010.",
    });

    await expect(useVpnStore.getState().resetDriver()).rejects.toThrow(
      "Administrator privileges required to restart the driver service.",
    );

    expect(useVpnStore.getState().driverResetAttempted).toBe(true);
    expect(useVpnStore.getState().driverSetupError).toContain(
      "Reboot required to finish driver installation. Windows signaled exit 3010.",
    );
    expect(useVpnStore.getState().driverSetupError).toContain(
      "Reset driver service failed: Administrator privileges required to restart the driver service.",
    );
  });
});
