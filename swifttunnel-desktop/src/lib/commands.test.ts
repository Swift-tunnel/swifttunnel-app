import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke,
}));

import {
  settingsLoad,
  settingsSave,
  settingsGenerateNetworkDiagnosticsBundle,
  systemRestartAsAdmin,
  systemInstallDriver,
  systemRepairDriver,
  updaterCheckChannel,
  updaterInstallChannel,
  vpnPreflightBinding,
  vpnGetPing,
  vpnListNetworkAdapters,
} from "./commands";
import { DEFAULT_SETTINGS } from "./settings";

describe("lib/commands", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("updaterCheckChannel invokes backend with expected args", async () => {
    const resp = {
      current_version: "1.0.0",
      available_version: null,
      release_tag: null,
      channel: "Stable",
    };
    invoke.mockResolvedValue(resp);

    await expect(updaterCheckChannel("Stable")).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("updater_check_channel", {
      channel: "Stable",
    });
  });

  it("updaterInstallChannel invokes backend with expected args", async () => {
    const resp = { installed_version: "1.5.1", release_tag: "v1.5.1" };
    invoke.mockResolvedValue(resp);

    await expect(updaterInstallChannel("Live", "1.5.1")).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("updater_install_channel", {
      channel: "Live",
      expectedVersion: "1.5.1",
    });
  });

  it("systemInstallDriver invokes backend with force=false by default", async () => {
    invoke.mockResolvedValue(undefined);
    await expect(systemInstallDriver()).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("system_install_driver", { force: false });
  });

  it("systemInstallDriver passes force=true when recovery flow invokes repair", async () => {
    invoke.mockReset();
    invoke.mockResolvedValue(undefined);
    await expect(systemInstallDriver(true)).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("system_install_driver", { force: true });
  });

  it("systemRepairDriver invokes backend", async () => {
    const resp = {
      installed: true,
      version: "3.6.2",
      ready: true,
      status: "ready",
      message: "ready",
      reboot_required: false,
      recommended_action: "none",
    };
    invoke.mockResolvedValue(resp);
    await expect(systemRepairDriver()).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("system_repair_driver");
  });

  it("systemRestartAsAdmin invokes backend with expected args", async () => {
    invoke.mockResolvedValue(undefined);
    await expect(systemRestartAsAdmin()).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("system_restart_as_admin");
  });

  it("vpnGetPing invokes backend with expected args", async () => {
    invoke.mockResolvedValue(42);
    await expect(vpnGetPing()).resolves.toEqual(42);
    expect(invoke).toHaveBeenCalledWith("vpn_get_ping");
  });

  it("vpnListNetworkAdapters invokes backend with expected args", async () => {
    const resp = [
      {
        guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        friendly_name: "Wi-Fi",
        description: "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter",
        if_index: 12,
        is_up: true,
        is_default_route: true,
        kind: "wifi",
      },
    ];
    invoke.mockResolvedValue(resp);

    await expect(vpnListNetworkAdapters()).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("vpn_list_network_adapters");
  });

  it("vpnPreflightBinding invokes backend with expected args", async () => {
    const resp = {
      status: "ok",
      reason: "Split tunnel adapter binding validated.",
      network_signature: "sig",
      route_resolution_source: "internet_fallback",
      route_resolution_target_ip: "8.8.8.8",
      resolved_if_index: 7,
      recommended_guid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      cached_override_used: false,
      binding_stage: "exact_route_match",
      candidates: [],
    };
    invoke.mockResolvedValue(resp);

    await expect(vpnPreflightBinding("singapore", ["roblox"])).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("vpn_preflight_binding", {
      region: "singapore",
      gamePresets: ["roblox"],
    });
  });

  it("settingsGenerateNetworkDiagnosticsBundle invokes backend with expected args", async () => {
    const resp = {
      file_path: "C:\\Users\\test\\Desktop\\SwiftTunnel_NetworkDiagnostics_20260219_160000.txt",
      folder_path: "C:\\Users\\test\\Desktop",
    };
    invoke.mockResolvedValue(resp);

    await expect(settingsGenerateNetworkDiagnosticsBundle()).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith(
      "settings_generate_network_diagnostics_bundle",
    );
  });

  it("settingsLoad invokes backend with typed settings payload", async () => {
    invoke.mockResolvedValue(DEFAULT_SETTINGS);

    await expect(settingsLoad()).resolves.toEqual(DEFAULT_SETTINGS);
    expect(invoke).toHaveBeenCalledWith("settings_load");
  });

  it("settingsSave invokes backend with typed settings payload", async () => {
    invoke.mockResolvedValue(undefined);

    await expect(settingsSave(DEFAULT_SETTINGS)).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("settings_save", {
      settings: DEFAULT_SETTINGS,
    });
  });
});
