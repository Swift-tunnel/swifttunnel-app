import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke,
}));

import {
  settingsGenerateNetworkDiagnosticsBundle,
  systemRestartAsAdmin,
  systemInstallDriver,
  updaterCheckChannel,
  updaterInstallChannel,
  vpnGetPing,
} from "./commands";

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

  it("systemInstallDriver invokes backend with expected args", async () => {
    invoke.mockResolvedValue(undefined);
    await expect(systemInstallDriver()).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("system_install_driver");
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
});
