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
  systemCopyLogToClipboard,
  systemCleanup,
  systemCleanupTunnelState,
  systemGetStartupRegistration,
  systemRestartAsAdmin,
  systemInstallDriver,
  systemRepairDriver,
  systemRepairNetwork,
  systemRepairWindowsFirewall,
  systemRepairStartupRegistration,
  systemRestoreStartupRegistration,
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
      release_notes: null,
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

  it("systemRepairWindowsFirewall invokes backend", async () => {
    const resp = {
      supported: true,
      is_admin: true,
      before_available: false,
      after_available: true,
      reset_attempted: true,
      reset_succeeded: true,
      reboot_recommended: false,
      backup_path: "C:\\ProgramData\\SwiftTunnel\\firewall-backups\\before.wfw",
      message: "Windows Firewall policy reset repaired advfirewall commands.",
      probe_before: "The following command was not found: advfirewall.",
      probe_after: "Domain Profile Settings",
      reset_output: "Ok.",
      services: [],
    };
    invoke.mockResolvedValue(resp);
    await expect(systemRepairWindowsFirewall()).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("system_repair_windows_firewall");
  });

  it("systemCleanup invokes backend", async () => {
    invoke.mockResolvedValue(undefined);
    await expect(systemCleanup()).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("system_cleanup");
  });

  it("systemCleanupTunnelState invokes backend", async () => {
    invoke.mockResolvedValue(undefined);
    await expect(systemCleanupTunnelState()).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("system_cleanup_tunnel_state");
  });

  it("systemRepairNetwork invokes backend", async () => {
    const resp = {
      supported: true,
      is_admin: true,
      overall: "fixed",
      steps: [
        {
          id: "adapter_modes",
          label: "Adapter packet filter modes",
          status: "fixed",
          detail: "1 adapter(s) were stuck — reset and verified.",
        },
      ],
    };
    invoke.mockResolvedValue(resp);
    await expect(systemRepairNetwork()).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("system_repair_network");
  });

  it("startup registration commands invoke backend with expected args", async () => {
    const snapshot = {
      exists: true,
      value: "\"C:\\Program Files\\SwiftTunnel\\SwiftTunnel.exe\" --startup",
    };

    invoke.mockResolvedValueOnce(snapshot);
    await expect(systemGetStartupRegistration()).resolves.toEqual(snapshot);
    expect(invoke).toHaveBeenLastCalledWith("system_get_startup_registration");

    invoke.mockResolvedValueOnce(snapshot);
    await expect(systemRepairStartupRegistration(true)).resolves.toEqual(snapshot);
    expect(invoke).toHaveBeenLastCalledWith(
      "system_repair_startup_registration",
      { enabled: true },
    );

    invoke.mockResolvedValueOnce({ exists: false, value: null });
    await expect(systemRestoreStartupRegistration(snapshot)).resolves.toEqual({
      exists: false,
      value: null,
    });
    expect(invoke).toHaveBeenLastCalledWith(
      "system_restore_startup_registration",
      { snapshot },
    );
  });

  it("systemRestartAsAdmin invokes backend with expected args", async () => {
    invoke.mockResolvedValue(undefined);
    await expect(systemRestartAsAdmin()).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("system_restart_as_admin");
  });

  it("systemCopyLogToClipboard invokes backend", async () => {
    const resp = {
      file_path: "C:\\Users\\test\\AppData\\Roaming\\SwiftTunnel\\logs\\swifttunnel.log",
    };
    invoke.mockResolvedValue(resp);

    await expect(systemCopyLogToClipboard()).resolves.toEqual(resp);
    expect(invoke).toHaveBeenCalledWith("system_copy_log_to_clipboard");
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
