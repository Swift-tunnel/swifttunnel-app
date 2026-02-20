import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  vpnGetState,
  vpnConnect,
  vpnDisconnect,
  vpnGetThroughput,
  vpnGetPing,
  vpnGetDiagnostics,
  systemCheckDriver,
  systemInstallDriver,
} = vi.hoisted(() => ({
  vpnGetState: vi.fn(),
  vpnConnect: vi.fn(),
  vpnDisconnect: vi.fn(),
  vpnGetThroughput: vi.fn(),
  vpnGetPing: vi.fn(),
  vpnGetDiagnostics: vi.fn(),
  systemCheckDriver: vi.fn(),
  systemInstallDriver: vi.fn(),
}));

const { notify } = vi.hoisted(() => ({
  notify: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  vpnGetState,
  vpnConnect,
  vpnDisconnect,
  vpnGetThroughput,
  vpnGetPing,
  vpnGetDiagnostics,
  systemCheckDriver,
  systemInstallDriver,
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

describe("stores/vpnStore", () => {
  beforeEach(() => {
    vpnGetState.mockReset();
    vpnConnect.mockReset();
    vpnDisconnect.mockReset();
    vpnGetThroughput.mockReset();
    vpnGetPing.mockReset();
    vpnGetDiagnostics.mockReset();
    systemCheckDriver.mockReset();
    systemInstallDriver.mockReset();
    notify.mockReset();

    vpnGetDiagnostics.mockResolvedValue(null);
    notify.mockResolvedValue(undefined);
  });

  it("auto-installs missing split tunnel driver before connecting", async () => {
    systemCheckDriver
      .mockResolvedValueOnce({ installed: false, version: null })
      .mockResolvedValueOnce({
        installed: true,
        version: "Windows Packet Filter",
      });
    systemInstallDriver.mockResolvedValue(undefined);
    vpnConnect.mockResolvedValue(undefined);
    vpnGetState.mockResolvedValue(connectedState("singapore"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(systemCheckDriver).toHaveBeenCalledTimes(2);
    expect(systemInstallDriver).toHaveBeenCalledTimes(1);
    expect(vpnConnect).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(useVpnStore.getState().state).toBe("connected");
    expect(useVpnStore.getState().driverSetupState).toBe("idle");
    expect(useVpnStore.getState().error).toBeNull();
  });

  it("stops connect and surfaces actionable error when auto-install fails", async () => {
    systemCheckDriver.mockResolvedValueOnce({ installed: false, version: null });
    systemInstallDriver.mockRejectedValue(new Error("network timeout"));

    const useVpnStore = await loadStore();
    await useVpnStore.getState().connect("singapore", ["roblox"]);

    expect(vpnConnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().state).toBe("error");
    expect(useVpnStore.getState().driverSetupState).toBe("error");
    expect(useVpnStore.getState().error).toContain("Automatic installation failed");
    expect(useVpnStore.getState().error).toContain("network timeout");
  });

  it("manual install action marks driver as installed", async () => {
    systemInstallDriver.mockResolvedValue(undefined);
    systemCheckDriver.mockResolvedValue({
      installed: true,
      version: "Windows Packet Filter",
    });

    const useVpnStore = await loadStore();
    await useVpnStore.getState().installDriver();

    expect(systemInstallDriver).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().driverSetupState).toBe("installed");
    expect(useVpnStore.getState().driverSetupError).toBeNull();
  });
});
