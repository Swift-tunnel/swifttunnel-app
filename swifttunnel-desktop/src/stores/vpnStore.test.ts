import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
  systemRepairWindowsFirewall,
  systemResetDriver,
  boostGetMetrics,
  boostCloseRoblox,
  settingsLoad,
  settingsSave,
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
  systemRepairWindowsFirewall: vi.fn(),
  systemResetDriver: vi.fn(),
  boostGetMetrics: vi.fn(),
  boostCloseRoblox: vi.fn(),
  settingsLoad: vi.fn(),
  settingsSave: vi.fn(),
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
  systemRepairWindowsFirewall,
  systemResetDriver,
  boostGetMetrics,
  boostCloseRoblox,
  settingsLoad,
  settingsSave,
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
    vi.useRealTimers();
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
    systemRepairWindowsFirewall.mockReset();
    systemResetDriver.mockReset();
    boostGetMetrics.mockReset();
    boostCloseRoblox.mockReset();
    settingsLoad.mockReset();
    settingsSave.mockReset();
    notify.mockReset();

    vpnDisconnect.mockResolvedValue(undefined);
    vpnGetDiagnostics.mockResolvedValue(null);
    boostGetMetrics.mockResolvedValue({
      fps: 0,
      cpu_usage: 0,
      ram_usage: 0,
      ram_total: 0,
      ping: 0,
      roblox_running: false,
      roblox_foreground: false,
      process_id: null,
    });
    boostCloseRoblox.mockResolvedValue(undefined);
    systemRepairWindowsFirewall.mockResolvedValue({
      supported: true,
      is_admin: true,
      before_available: false,
      after_available: true,
      reset_attempted: true,
      reset_succeeded: true,
      reboot_recommended: false,
      backup_path: null,
      message: "Windows Firewall policy reset repaired advfirewall commands.",
      probe_before: "The following command was not found: advfirewall.",
      probe_after: "advfirewall available",
      reset_output: "Ok.",
      services: [],
    });
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
    settingsSave.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
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

  it("repairs resettable driver exposure failures before connecting", async () => {
    systemCheckDriver.mockResolvedValueOnce(
      driverStatus({
        ready: false,
        status: "no_adapters",
        message:
          "Split tunnel driver not available (Windows Packet Filter driver): no TCP/IP-bound network adapters were enumerated. Reset the driver service, then try again.",
        recommended_action: "reset_service",
      }),
    );
    systemRepairDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().driverSetupError).toBeNull();
    expect(useVpnStore.getState().error).toBeNull();
  });

  it("blocks Full Country Ban connect while Roblox is already running", async () => {
    systemCheckDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));
    boostGetMetrics.mockResolvedValueOnce({
      fps: 0,
      cpu_usage: 0,
      ram_usage: 0,
      ram_total: 0,
      ping: 0,
      roblox_running: true,
      roblox_foreground: false,
      process_id: 1234,
    });

    const useVpnStore = await loadStore();
    const { useSettingsStore } = await import("./settingsStore");
    useSettingsStore.getState().update({ enable_country_ban: true });

    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(vpnConnect).not.toHaveBeenCalled();
    expect(boostCloseRoblox).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain(
      "Close Roblox before connecting with Full Country Ban",
    );
    expect(notify).toHaveBeenCalledWith(
      "SwiftTunnel",
      "Close Roblox first, then connect Full Country Ban.",
    );
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
    expect(vpnDisconnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().driverSetupState).toBe("error");
    expect(useVpnStore.getState().error).toContain("network timeout");
  });

  it("cleans Windows driver installer failures before showing them in the app", async () => {
    const uglyInstallerError =
      "Split tunnel driver not available (Windows Packet Filter driver): failed to open \\\\.\\NDISRD: The system cannot find the file specified. (0x80070002) Repair failed: Driver service reset failed: Driver file not found, cannot create NDISRD service bundled package repair failed: netcfg binding install failed: netcfg failed with code 1753: Trying to install nt_ndisrd ... C:\\Program Files\\SwiftTunnel\\resources\\drivers\\winpkfilter\\x64\\win10\\ndisrd_lwf.inf was copied to C:\\Windows\\INF\\oem21.inf. failed. Error code: 0x800106d9. MSI repair failed: Driver install failed (msiexec code 1603). Installer log: C:\\ProgramData\\SwiftTunnel\\driver-work\\install-e6636099c08eb00d408c1ba2faa67f30\\install.log.";

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
        message: uglyInstallerError,
        recommended_action: "install",
      }),
    );

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain(
      "Windows could not install SwiftTunnel's split-tunnel driver",
    );
    expect(useVpnStore.getState().error).toContain("contact support");
    expect(useVpnStore.getState().error).not.toContain("oem21.inf");
    expect(useVpnStore.getState().error).not.toContain("ProgramData");
    expect(useVpnStore.getState().driverSetupError).toBe(
      useVpnStore.getState().error,
    );
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

  it("stops safely when preflight cannot see WinpkFilter adapters", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnPreflightBinding
      .mockResolvedValueOnce({
        status: "unrecoverable",
        reason:
          "SwiftTunnel could not see any WinpkFilter-bound network adapters. SwiftTunnel will repair the binding automatically, then try again.",
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
    expect(vpnConnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().bindingPreflight).toBeNull();
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().driverSetupError).toBeNull();
  });

  it("stops safely on missing WinpkFilter binding marker during preflight", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnPreflightBinding
      .mockResolvedValueOnce({
        status: "unrecoverable",
        reason:
          "winpkfilter_binding_missing: nt_ndisrd is not bound to adapter 'Realtek Gaming GbE Family Controller'.",
        network_signature: "source=internet_fallback;if_index=20;next_hop=1;up=",
        route_resolution_source: "internet_fallback",
        route_resolution_target_ip: "8.8.8.8",
        resolved_if_index: 20,
        recommended_guid: null,
        cached_override_used: false,
        binding_stage: "winpkfilter_binding_missing",
        candidates: [],
      })
      .mockResolvedValueOnce({
        status: "ok",
        reason: "Split tunnel adapter binding validated.",
        network_signature:
          "source=internet_fallback;if_index=20;next_hop=1;up=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        route_resolution_source: "internet_fallback",
        route_resolution_target_ip: "8.8.8.8",
        resolved_if_index: 20,
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
    expect(vpnConnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().driverSetupError).toBeNull();
  });

  it("does not auto-repair unrelated nt_ndisrd validation errors", async () => {
    systemCheckDriver.mockResolvedValueOnce(driverStatus());
    vpnPreflightBinding.mockResolvedValueOnce({
      status: "unrecoverable",
      reason: "nt_ndisrd adapter validation error: access denied",
      network_signature: "source=internet_fallback;if_index=20;next_hop=1;up=",
      route_resolution_source: "internet_fallback",
      route_resolution_target_ip: "8.8.8.8",
      resolved_if_index: 20,
      recommended_guid: null,
      cached_override_used: false,
      binding_stage: "unrecoverable",
      candidates: [],
    });

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain("access denied");
  });

  it("stops safely when connect races a missing WinpkFilter binding", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    systemRepairDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect
      .mockRejectedValueOnce(
        new Error(
          "Split tunnel driver binding is missing on the active network adapter.",
        ),
      )
      .mockResolvedValueOnce(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledTimes(2);
    expect(vpnPreflightBinding).toHaveBeenCalledTimes(2);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().driverSetupError).toBeNull();
  });

  it("stops safely when connect cannot ensure the WinpkFilter binding", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    systemRepairDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect
      .mockRejectedValueOnce(
        new Error(
          "Split tunnel setup failed. Failed to configure V3 split tunnel: Split tunnel driver error: Failed to ensure WinpkFilter binding on adapter 'Ethernet': PowerShell failed.",
        ),
      )
      .mockResolvedValueOnce(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledTimes(2);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().driverSetupError).toBeNull();
  });

  it("shows restart-required status when WinpkFilter binding cannot be ensured", async () => {
    const bindingError =
      "Split tunnel setup failed. Failed to configure V3 split tunnel: Split tunnel driver error: Failed to ensure WinpkFilter binding on adapter 'Ethernet': PowerShell failed.";

    systemCheckDriver.mockResolvedValue(driverStatus());
    systemRepairDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect.mockRejectedValue(new Error(bindingError));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(vpnDisconnect).toHaveBeenCalledTimes(2);
    expect(vpnConnect).toHaveBeenCalledTimes(2);
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().driverStatus?.recommended_action).toBe(
      "reboot",
    );
    expect(useVpnStore.getState().driverSetupError).toContain(
      "Windows still has not attached the network filter",
    );
    expect(useVpnStore.getState().driverSetupError).toContain(
      "Failed to ensure WinpkFilter binding",
    );
  });

  const repairableDriverConnectErrors = [
    {
      name: "no TCP/IP-bound adapters",
      message:
        "Split tunnel driver not available (Windows Packet Filter driver): no TCP/IP-bound network adapters were enumerated. Reset the driver service, then try again.",
    },
    {
      name: "adapter IOCTL failure",
      message:
        "Split tunnel driver not available (Windows Packet Filter driver): installed but IOCTL failed (get_tcpip_bound_adapters_info: bad state). Reset the driver service, then try again.",
    },
    {
      name: "driver version query failure",
      message:
        "Split tunnel driver not available (Windows Packet Filter driver): version query failed (invalid function). Reset the driver service, then try again.",
    },
    {
      name: "NDISRD open failure",
      message:
        "Split tunnel driver not available (Windows Packet Filter driver): failed to open \\\\.\\NDISRD: The system cannot find the file specified.",
    },
  ];

  for (const { name, message } of repairableDriverConnectErrors) {
    it(`stops safely for connect-time ${name}`, async () => {
      systemCheckDriver.mockResolvedValue(driverStatus());
      systemRepairDriver.mockResolvedValueOnce(driverStatus());
      vpnConnect
        .mockRejectedValueOnce(new Error(message))
        .mockResolvedValueOnce(undefined);
      vpnGetState.mockResolvedValue(connectedState("singapore"));

      const useVpnStore = await loadStore();
      await useVpnStore.getState().connect("singapore", ["roblox"]);

      expect(systemRepairDriver).toHaveBeenCalledTimes(1);
      expect(systemRepairWindowsFirewall).not.toHaveBeenCalled();
      expect(vpnDisconnect).toHaveBeenCalledTimes(1);
      expect(vpnConnect).toHaveBeenCalledTimes(2);
      expect(useVpnStore.getState().state).toBe("connected");
      expect(useVpnStore.getState().driverSetupError).toBeNull();
    });
  }

  it("shows restart-required status instead of reinstalling on connect-time reboot-required driver errors", async () => {
    const rebootError =
      "Reboot required to finish driver installation. Windows signaled exit 3010 and the post-install self-test failed.";

    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockRejectedValueOnce(new Error(rebootError));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(systemRepairWindowsFirewall).not.toHaveBeenCalled();
    expect(vpnDisconnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().driverStatus?.recommended_action).toBe(
      "reboot",
    );
    expect(useVpnStore.getState().driverSetupError).toContain(
      "Restart Windows once to finish setting up",
    );
  });

  it("repairs Windows Firewall and retries once for advfirewall setup errors", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect
      .mockRejectedValueOnce(
        new Error(
          "Split tunnel setup failed. Failed to install IPv6 block firewall rule: The following command was not found: advfirewall firewall add rule.",
        ),
      )
      .mockResolvedValueOnce(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairWindowsFirewall).toHaveBeenCalledTimes(1);
    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledTimes(2);
    expect(useVpnStore.getState().state).toBe("connected");
  });

  it("does not pretend admin permission errors are driver-repairable", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockRejectedValueOnce(
      new Error(
        "Administrator privileges required. Please run SwiftTunnel as Administrator.",
      ),
    );

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(systemRepairWindowsFirewall).not.toHaveBeenCalled();
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain(
      "Administrator privileges required",
    );
  });

  it("repairs elevated Windows driver-access blocks once before failing", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    systemRepairDriver.mockResolvedValueOnce(driverStatus());
    vpnConnect
      .mockRejectedValueOnce(
        new Error(
          "Windows blocked SwiftTunnel's split-tunnel driver access even though SwiftTunnel is elevated. Restart Windows once so the driver service can reload cleanly.",
        ),
      )
      .mockResolvedValueOnce(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(systemRepairWindowsFirewall).not.toHaveBeenCalled();
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledTimes(2);
    expect(useVpnStore.getState().state).toBe("connected");
  });

  it("treats an exact backend already-connected marker as connect success", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockRejectedValueOnce(new Error("Already connected."));
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(vpnConnect).toHaveBeenCalledTimes(1);
    expect(vpnGetState).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().error).toBeNull();
    expect(useVpnStore.getState().connectAttemptInFlight).toBe(false);
  });

  it("does not treat similar already-connected failures as idempotent success", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockRejectedValueOnce(
      new Error("Already connected to a different relay account"),
    );

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(vpnGetState).not.toHaveBeenCalled();
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain("different relay account");
    expect(useVpnStore.getState().connectAttemptInFlight).toBe(false);
  });

  it("preserves the connect failure when cleanup also fails", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockRejectedValueOnce(
      new Error("Relay preflight enforcement blocked connection."),
    );
    vpnDisconnect.mockRejectedValueOnce(new Error("cleanup unavailable"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain(
      "Relay preflight enforcement blocked connection.",
    );
    expect(useVpnStore.getState().error).toContain(
      "Cleanup after failed connect also failed: cleanup unavailable",
    );
  });

  it("times out a hung backend connect instead of spinning forever", async () => {
    vi.useFakeTimers();
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockReturnValue(new Promise(() => {}));

    const useVpnStore = await loadStore();
    const connectPromise = useVpnStore
      .getState()
      .connect("singapore", ["roblox"]);

    await vi.waitFor(() => {
      expect(vpnConnect).toHaveBeenCalledTimes(1);
    });
    await vi.advanceTimersByTimeAsync(90_000);
    await connectPromise;

    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().connectAttemptInFlight).toBe(false);
    expect(useVpnStore.getState().error).toContain("VPN connection timed out");
  });

  it("does not repair a superficially similar nt_ndisrd timeout", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockRejectedValueOnce(
      new Error("nt_ndisrd adapter validation timed out while reading status"),
    );

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain("timed out");
  });

  it("shows restart-required status when binding preflight is repairable", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    const failedPreflight = {
      status: "unrecoverable" as const,
      reason:
        "SwiftTunnel could not see any WinpkFilter-bound network adapters. SwiftTunnel will repair the binding automatically, then try again.",
      network_signature: "source=internet_fallback;if_index=8;next_hop=1;up=",
      route_resolution_source: "internet_fallback",
      route_resolution_target_ip: "128.116.1.1",
      resolved_if_index: 8,
      recommended_guid: null,
      cached_override_used: false,
      binding_stage: "unrecoverable",
      candidates: [],
    };
    vpnPreflightBinding.mockResolvedValue(failedPreflight);
    systemRepairDriver.mockResolvedValue(driverStatus());

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemRepairDriver).toHaveBeenCalledTimes(1);
    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().driverSetupState).toBe("error");
    expect(useVpnStore.getState().driverStatus?.recommended_action).toBe(
      "reboot",
    );
    expect(useVpnStore.getState().driverSetupError).toContain(
      "Windows still has not attached the network filter",
    );
  });

  it("does not start a stale auto-repair continuation after binding preflight failure", async () => {
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnPreflightBinding.mockResolvedValue({
      status: "unrecoverable",
      reason:
        "SwiftTunnel could not see any WinpkFilter-bound network adapters. SwiftTunnel will repair the binding automatically, then try again.",
      network_signature: "source=internet_fallback;if_index=8;next_hop=1;up=",
      route_resolution_source: "internet_fallback",
      route_resolution_target_ip: "128.116.1.1",
      resolved_if_index: 8,
      recommended_guid: null,
      cached_override_used: false,
      binding_stage: "unrecoverable",
      candidates: [],
    });
    let finishRepair: ((value: ReturnType<typeof driverStatus>) => void) | undefined;
    systemRepairDriver.mockReturnValue(
      new Promise((resolve) => {
        finishRepair = resolve;
      }),
    );
    vpnDisconnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue({
      state: "disconnected",
      region: null,
      server_endpoint: null,
      assigned_ip: null,
      relay_auth_mode: "ticket",
      split_tunnel_active: false,
      tunneled_processes: [],
      error: null,
    });

    const useVpnStore = await loadStore();
    const connectPromise = useVpnStore
      .getState()
      .connect("singapore", ["roblox"]);
    for (let i = 0; i < 5 && systemRepairDriver.mock.calls.length === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    expect(systemRepairDriver).toHaveBeenCalledTimes(1);

    await useVpnStore.getState().disconnect();
    if (finishRepair) {
      finishRepair(driverStatus());
    }
    await connectPromise;

    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("disconnected");
    expect(useVpnStore.getState().connectAttemptInFlight).toBe(false);
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

  it("ignores stale disconnected polls while a connect attempt is pending", async () => {
    vpnGetState.mockResolvedValue({
      state: "disconnected",
      region: null,
      server_endpoint: null,
      assigned_ip: null,
      relay_auth_mode: null,
      split_tunnel_active: false,
      tunneled_processes: [],
      error: null,
    });

    const useVpnStore = await loadStore();
    useVpnStore.setState({
      state: "fetching_config",
      error: null,
      connectAttemptInFlight: true,
    });

    await useVpnStore.getState().fetchState();

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

  it("does not let late transition events hide a timed-out connect error", async () => {
    const useVpnStore = await loadStore();
    useVpnStore.setState({
      state: "error",
      error: "VPN connection timed out after 90s.",
      connectAttemptInFlight: false,
    });

    useVpnStore.getState().handleStateEvent({
      state: "configuring_split_tunnel",
      region: null,
      server_endpoint: null,
      assigned_ip: null,
      error: null,
    });

    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().error).toContain("timed out");

    useVpnStore.getState().handleStateEvent({
      state: "connected",
      region: "singapore",
      server_endpoint: "1.2.3.4:51821",
      assigned_ip: "10.0.0.2",
      error: null,
    });

    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().region).toBe("singapore");
  });

  it("pins the next relay and reconnects when a relay stops returning traffic", async () => {
    const useVpnStore = await loadStore();
    const { useServerStore } = await import("./serverStore");
    const { useSettingsStore } = await import("./settingsStore");

    useServerStore.setState({
      regions: [
        {
          id: "singapore",
          name: "Singapore",
          description: "SG",
          country_code: "SG",
          servers: ["singapore", "singapore-02", "singapore-03"],
        },
      ],
      servers: [],
      latencies: new Map(),
      source: "test",
      isLoading: false,
      error: null,
    });
    useSettingsStore.getState().update({
      selected_region: "singapore",
      selected_game_presets: ["roblox"],
      auto_routing_enabled: false,
      forced_servers: {},
    });
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    useVpnStore.getState().handleStateEvent({
      state: "error",
      region: "Singapore",
      server_endpoint: "1.2.3.4:51821",
      assigned_ip: null,
      error:
        "Relay connection failed - SwiftTunnel stopped the session because the relay stopped returning traffic. Please reconnect or choose another relay.",
    });

    for (let i = 0; i < 10 && vpnConnect.mock.calls.length === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    expect(useSettingsStore.getState().settings.forced_servers.singapore).toBe(
      "singapore-02",
    );
    expect(settingsSave).toHaveBeenCalled();
    expect(vpnConnect).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(notify).toHaveBeenCalledWith(
      "SwiftTunnel",
      "Relay stopped responding. Switching singapore to singapore-02 and reconnecting.",
    );
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
