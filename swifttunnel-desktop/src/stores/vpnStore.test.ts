import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  vpnGetState,
  vpnPreflightBinding,
  vpnConnect,
  vpnDisconnect,
  vpnGetThroughput,
  vpnGetPing,
  vpnGetFreeTier,
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
  vpnGetFreeTier: vi.fn(),
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
  vpnGetFreeTier,
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

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function disconnectedState() {
  return { ...connectedState("singapore"), state: "disconnected", region: null,
    server_endpoint: null, assigned_ip: null, split_tunnel_active: false, tunneled_processes: [] };
}

describe("stores/vpnStore", () => {
  it("discards game route details when disconnected or moved to another relay", async () => {
    const store = await loadStore();
    vpnGetState.mockResolvedValue({ ...connectedState("mumbai"), game_route: {
      game_location: "Singapore", relay: "mumbai", estimated_path_ms: 50, bypassed: false,
    } });
    await store.getState().fetchState();
    expect(store.getState().gameRoute?.estimated_path_ms).toBe(50);
    vpnGetState.mockResolvedValue(connectedState("tokyo"));
    await store.getState().fetchState();
    expect(store.getState().gameRoute).toBeNull();
    vpnGetState.mockResolvedValue(disconnectedState());
    await store.getState().fetchState();
    expect(store.getState().gameRoute).toBeNull();
  });
  beforeEach(() => {
    vi.useRealTimers();
    vpnGetState.mockReset();
    vpnPreflightBinding.mockReset();
    vpnConnect.mockReset();
    vpnDisconnect.mockReset();
    vpnGetThroughput.mockReset();
    vpnGetPing.mockReset();
    vpnGetFreeTier.mockReset();
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

  it("keeps a cancelled Roblox check from restarting connection setup", async () => {
    const metrics = deferred<{ roblox_running: boolean }>();
    boostGetMetrics.mockReturnValueOnce(metrics.promise);
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(disconnectedState());
    const useVpnStore = await loadStore();
    const { useSettingsStore } = await import("./settingsStore");
    useSettingsStore.getState().update({ enable_country_ban: true });
    const connecting = useVpnStore.getState().connect("singapore", ["roblox"]);
    await useVpnStore.getState().disconnect();
    metrics.resolve({ roblox_running: false });
    await connecting;
    expect(systemCheckDriver).not.toHaveBeenCalled();
    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("disconnected");
  });

  it("does not repair a driver after the user cancelled its readiness check", async () => {
    const check = deferred<ReturnType<typeof driverStatus>>();
    systemCheckDriver.mockReturnValueOnce(check.promise);
    systemRepairDriver.mockResolvedValue(driverStatus());
    vpnGetState.mockResolvedValue(disconnectedState());
    const useVpnStore = await loadStore();
    const connecting = useVpnStore.getState().connect("singapore", ["roblox"]);
    await vi.waitFor(() => expect(systemCheckDriver).toHaveBeenCalledOnce());
    await useVpnStore.getState().disconnect();
    check.resolve(driverStatus({ ready: false, recommended_action: "reinstall" }));
    await connecting;
    expect(systemRepairDriver).not.toHaveBeenCalled();
    expect(useVpnStore.getState().driverStatus).toBeNull();
  });

  it("does not let a superseded connect failure disconnect the new session", async () => {
    const old = deferred<void>();
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockReturnValueOnce(old.promise).mockResolvedValueOnce(undefined);
    vpnGetState.mockResolvedValueOnce(disconnectedState()).mockResolvedValue(connectedState("tokyo"));
    const useVpnStore = await loadStore();
    const first = useVpnStore.getState().connect("singapore", ["roblox"]);
    await vi.waitFor(() => expect(vpnConnect).toHaveBeenCalledOnce());
    await useVpnStore.getState().disconnect();
    await useVpnStore.getState().connect("tokyo", ["roblox"]);
    old.reject(new Error("connection failed"));
    await first;
    expect(vpnDisconnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().region).toBe("tokyo");
  });

  it("ignores a state poll from before disconnect", async () => {
    const poll = deferred<ReturnType<typeof connectedState>>();
    vpnGetState.mockReturnValueOnce(poll.promise).mockResolvedValue(disconnectedState());
    const useVpnStore = await loadStore();
    const fetching = useVpnStore.getState().fetchState();
    await useVpnStore.getState().disconnect();
    poll.resolve(connectedState("singapore"));
    await fetching;
    expect(useVpnStore.getState().state).toBe("disconnected");
    expect(useVpnStore.getState().connectedAt).toBeNull();
  });

  it("does not clear a new session when an older disconnect response arrives", async () => {
    const old = deferred<void>();
    vpnDisconnect.mockReturnValueOnce(old.promise);
    systemCheckDriver.mockResolvedValue(driverStatus());
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(connectedState("tokyo"));
    const useVpnStore = await loadStore();
    const disconnecting = useVpnStore.getState().disconnect();
    await useVpnStore.getState().connect("tokyo", ["roblox"]);
    old.resolve(undefined);
    await disconnecting;
    expect(useVpnStore.getState().region).toBe("tokyo");
    expect(useVpnStore.getState().connectedAt).not.toBeNull();
    expect(notify).not.toHaveBeenCalledWith("SwiftTunnel", "VPN disconnected.");
  });

  it("does not reconnect after dismissing an adapter choice while it saves", async () => {
    const saving = deferred<void>();
    settingsSave.mockReturnValueOnce(saving.promise);
    const preflight = { ...await vpnPreflightBinding(), status: "ambiguous" };
    const useVpnStore = await loadStore();
    useVpnStore.setState({ bindingPreflight: preflight, pendingConnectIntent: { region: "singapore", gamePresets: ["roblox"] } });
    const resuming = useVpnStore.getState().resumeConnectWithAdapter("adapter-guid");
    useVpnStore.getState().dismissBindingChooser();
    saving.resolve(undefined);
    await resuming;
    expect(systemCheckDriver).not.toHaveBeenCalled();
    expect(vpnConnect).not.toHaveBeenCalled();
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

  it.each([true, false])("ignores a cancelled binding repair result (ready=%s)", async (ready) => {
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
      finishRepair(driverStatus({ ready }));
    }
    await connectPromise;

    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("disconnected");
    expect(useVpnStore.getState().connectAttemptInFlight).toBe(false);
    expect(useVpnStore.getState().driverStatus).toBeNull();
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

  it("reconnects the location without pinning when a relay stops returning traffic", async () => {
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
      auto_routing_enabled: true,
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
        "Relay connection failed - SwiftTunnel stopped the session because the relay stopped returning traffic. Reconnect to continue; SwiftTunnel skips this relay for a few minutes when another is available.",
    });

    for (let i = 0; i < 10 && vpnConnect.mock.calls.length === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    // Nothing is pinned and the player's own settings are left alone: the
    // core skips the dead relay on the reconnect.
    expect(useSettingsStore.getState().settings.auto_routing_enabled).toBe(true);
    expect("forced_servers" in useSettingsStore.getState().settings).toBe(false);
    expect(vpnConnect).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(notify).toHaveBeenCalledWith(
      "SwiftTunnel",
      "Relay stopped responding. Reconnecting to another Singapore relay.",
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

  // Enforcement is relay-side: the backend stops renewing the lease and the
  // relay drops the session. The client's job is to warn, not to hang up —
  // the backend grants a grace window past the allowance and keeps the lease
  // alive through it, so a client that disconnected at zero would cut a session
  // the server was deliberately still carrying.
  describe("free tier enforcement", () => {
    async function connectedWithRemaining(remaining: number) {
      const useVpnStore = await loadStore();
      useVpnStore.setState({
        state: "connected",
        freeTierRemaining: remaining,
        freeTierGraceRemaining: null,
      });
      return useVpnStore;
    }

    it("warns at zero but leaves the session to the relay", async () => {
      const useVpnStore = await connectedWithRemaining(1);

      useVpnStore.getState().tickFreeTier();

      expect(useVpnStore.getState().freeTierRemaining).toBe(0);
      expect(notify).toHaveBeenCalledWith(
        "Time limit reached",
        expect.stringContaining("extra minutes"),
      );
      expect(vpnDisconnect).not.toHaveBeenCalled();
    });

    it("does not re-warn on every tick once the allowance is spent", async () => {
      const useVpnStore = await connectedWithRemaining(1);

      useVpnStore.getState().tickFreeTier();
      useVpnStore.getState().tickFreeTier();
      useVpnStore.getState().tickFreeTier();

      expect(notify).toHaveBeenCalledTimes(1);
    });

    it("counts the backend-granted grace down and warns as it ends", async () => {
      const useVpnStore = await loadStore();
      useVpnStore.setState({
        state: "connected",
        freeTierRemaining: 0,
        freeTierGraceRemaining: 2,
      });

      useVpnStore.getState().tickFreeTier();
      expect(useVpnStore.getState().freeTierGraceRemaining).toBe(1);
      expect(notify).not.toHaveBeenCalled();

      useVpnStore.getState().tickFreeTier();
      expect(useVpnStore.getState().freeTierGraceRemaining).toBe(0);
      expect(notify).toHaveBeenCalledWith(
        "Free time used up",
        expect.stringContaining("disconnecting"),
      );
      // Still not the client's call — the relay drops the expired lease.
      expect(vpnDisconnect).not.toHaveBeenCalled();
    });

    it("ignores ticks while not connected", async () => {
      const useVpnStore = await loadStore();
      useVpnStore.setState({
        state: "disconnected",
        freeTierRemaining: 1,
      });

      useVpnStore.getState().tickFreeTier();

      expect(useVpnStore.getState().freeTierRemaining).toBe(1);
      expect(notify).not.toHaveBeenCalled();
    });

    // The backend value is frozen at the moment the last ticket was issued, so
    // a minute-by-minute resync used to reset the local countdown to the
    // connect-time number. A user reported "1h 54m free" while the session
    // timer read 4:46:57.
    it("accepts the latest server-authoritative lease snapshot", async () => {
      vpnGetFreeTier.mockResolvedValue({
        remaining_seconds: 6840, // connect-time snapshot
        limit_seconds: 10800,
      });

      const useVpnStore = await loadStore();
      useVpnStore.setState({ state: "connected", freeTierRemaining: 120 });

      await useVpnStore.getState().fetchFreeTier();

      expect(useVpnStore.getState().freeTierRemaining).toBe(6840);
      expect(useVpnStore.getState().freeTierLimit).toBe(10800);
    });

    it("accepts a lower backend value, which means usage we had not counted", async () => {
      // Same account connected on a second machine spends the shared allowance.
      vpnGetFreeTier.mockResolvedValue({
        remaining_seconds: 45,
        limit_seconds: 10800,
      });

      const useVpnStore = await loadStore();
      useVpnStore.setState({ state: "connected", freeTierRemaining: 600 });

      await useVpnStore.getState().fetchFreeTier();

      expect(useVpnStore.getState().freeTierRemaining).toBe(45);
    });

    it("takes the backend value verbatim when not connected", async () => {
      // Between sessions there is no local countdown worth preserving, and the
      // window may well have refilled.
      vpnGetFreeTier.mockResolvedValue({
        remaining_seconds: 10800,
        limit_seconds: 10800,
      });

      const useVpnStore = await loadStore();
      useVpnStore.setState({ state: "disconnected", freeTierRemaining: 30 });

      await useVpnStore.getState().fetchFreeTier();

      expect(useVpnStore.getState().freeTierRemaining).toBe(10800);
    });

    it("leaves an unlimited account alone", async () => {
      // freeTierRemaining is null when the backend has no limit configured.
      const useVpnStore = await loadStore();
      useVpnStore.setState({
        state: "connected",
        freeTierRemaining: null,
      });

      useVpnStore.getState().tickFreeTier();

      expect(vpnDisconnect).not.toHaveBeenCalled();
    });
  });

  describe("session clock", () => {
    // A user reported a 31h session while no relay in the fleet had held a
    // session longer than ~7h, and the recorded usage disagreed too. The clock
    // was only ever reset by the disconnect action, so a drop the user did not
    // click through left it running across the outage.
    it('clears connectedAt when the backend reports the tunnel is no longer up', async () => {
      const useVpnStore = await loadStore();
      const startedLongAgo = Date.now() - 31 * 60 * 60 * 1000;
      useVpnStore.setState({ state: 'connected', connectedAt: startedLongAgo });

      vpnGetState.mockResolvedValue({
        state: "disconnected" as const,
        region: null,
        server_endpoint: null,
        assigned_ip: null,
        relay_auth_mode: "ticket",
        split_tunnel_active: false,
        tunneled_processes: [],
        error: null,
      });
      await useVpnStore.getState().fetchState();

      expect(useVpnStore.getState().connectedAt).toBeNull();
    });

    it('keeps counting from the original connect while the tunnel stays up', async () => {
      const useVpnStore = await loadStore();
      const startedAt = Date.now() - 5 * 60 * 1000;
      useVpnStore.setState({ state: 'connected', connectedAt: startedAt });

      vpnGetState.mockResolvedValue(connectedState('singapore'));
      await useVpnStore.getState().fetchState();

      // Must not restart on every poll, or the timer would sit near zero.
      expect(useVpnStore.getState().connectedAt).toBe(startedAt);
    });

    it('starts the clock when it finds a tunnel already connected', async () => {
      const useVpnStore = await loadStore();
      useVpnStore.setState({ state: 'disconnected', connectedAt: null });

      vpnGetState.mockResolvedValue(connectedState('singapore'));
      await useVpnStore.getState().fetchState();

      expect(useVpnStore.getState().connectedAt).not.toBeNull();
    });
  });
});
