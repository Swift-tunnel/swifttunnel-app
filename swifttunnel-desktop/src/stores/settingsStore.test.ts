import { beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "../lib/settings";
import type { AppSettings } from "../lib/types";

const { settingsLoad, settingsSave } = vi.hoisted(() => ({
  settingsLoad: vi.fn(),
  settingsSave: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  settingsLoad,
  settingsSave,
}));

const { reportError } = vi.hoisted(() => ({
  reportError: vi.fn(),
}));

vi.mock("../lib/errors", () => ({
  reportError,
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./settingsStore")).useSettingsStore;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

describe("stores/settingsStore", () => {
  beforeEach(() => {
    settingsLoad.mockReset();
    settingsSave.mockReset();
    reportError.mockReset();
  });

  it("loads settings and sets activeTab from current_tab", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      theme: "light",
      config: {},
      current_tab: "boost",
      minimize_to_tray: true,
      game_process_performance: {
        high_performance_gpu_binding: true,
        prefer_performance_cores: false,
        unbind_cpu0: true,
      },
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(settingsLoad).toHaveBeenCalled();
    expect(useSettingsStore.getState().isLoaded).toBe(true);
    expect(useSettingsStore.getState().settings.theme).toBe("light");
    expect(
      useSettingsStore.getState().settings.game_process_performance
        .high_performance_gpu_binding,
    ).toBe(true);
    expect(
      useSettingsStore.getState().settings.game_process_performance.unbind_cpu0,
    ).toBe(true);
    expect(useSettingsStore.getState().activeTab).toBe("boost");
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.window_width,
    ).toBe(1280);
    expect(
      useSettingsStore.getState().settings.config.roblox_settings
        .graphics_quality,
    ).toBe("Automatic");
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.unlock_fps,
    ).toBe(false);
  });

  it("migrates legacy master network boost into current per-toggle boosts", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      config: {
        ...DEFAULT_SETTINGS.config,
        network_settings: {
          enable_network_boost: true,
        },
      },
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    const network =
      useSettingsStore.getState().settings.config.network_settings;
    expect(network.enable_network_boost).toBe(true);
    expect(network.disable_nagle).toBe(true);
    expect(network.disable_network_throttling).toBe(true);
    expect(network.gaming_qos).toBe(false);
    expect(network.firewall_fix).toBe(false);
  });

  it("preserves explicit all-off network boosts even with a stale master flag", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      config: {
        ...DEFAULT_SETTINGS.config,
        network_settings: {
          ...DEFAULT_SETTINGS.config.network_settings,
          enable_network_boost: true,
          disable_nagle: false,
          disable_network_throttling: false,
          gaming_qos: false,
          prioritize_roblox_traffic: false,
          firewall_fix: false,
        },
      },
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    const network =
      useSettingsStore.getState().settings.config.network_settings;
    expect(network.enable_network_boost).toBe(false);
    expect(network.disable_nagle).toBe(false);
    expect(network.disable_network_throttling).toBe(false);
    expect(network.gaming_qos).toBe(false);
  });

  it("does not enable network boosts when legacy master is off", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      config: {
        ...DEFAULT_SETTINGS.config,
        network_settings: {
          ...DEFAULT_SETTINGS.config.network_settings,
          enable_network_boost: false,
        },
      },
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    const network =
      useSettingsStore.getState().settings.config.network_settings;
    expect(network.enable_network_boost).toBe(false);
    expect(network.disable_nagle).toBe(false);
    expect(network.disable_network_throttling).toBe(false);
    expect(network.gaming_qos).toBe(false);
  });

  it("defaults minimize_to_tray to true when load fails", async () => {
    settingsLoad.mockRejectedValue(new Error("boom"));

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(useSettingsStore.getState().isLoaded).toBe(true);
    expect(useSettingsStore.getState().settings.minimize_to_tray).toBe(true);
    expect(useSettingsStore.getState().settings.run_on_startup).toBe(false);
    expect(useSettingsStore.getState().settings.auto_reconnect).toBe(false);
    expect(useSettingsStore.getState().settings.resume_vpn_on_startup).toBe(
      false,
    );
    expect(
      useSettingsStore.getState().settings.preferred_physical_adapter_guid,
    ).toBe(null);
    expect(useSettingsStore.getState().settings.adapter_binding_mode).toBe(
      "smart_auto",
    );
    expect(
      useSettingsStore.getState().settings.game_process_performance
        .high_performance_gpu_binding,
    ).toBe(false);
    expect(
      useSettingsStore.getState().settings.game_process_performance
        .prefer_performance_cores,
    ).toBe(false);
    expect(
      useSettingsStore.getState().settings.game_process_performance.unbind_cpu0,
    ).toBe(false);
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.window_width,
    ).toBe(1280);
    expect(
      useSettingsStore.getState().settings.config.roblox_settings
        .graphics_quality,
    ).toBe("Automatic");
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.unlock_fps,
    ).toBe(false);
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.window_height,
    ).toBe(720);
    expect(
      useSettingsStore.getState().settings.config.roblox_settings
        .window_fullscreen,
    ).toBe(false);
  });

  it("migrates legacy saved minimize_to_tray false to true", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      minimize_to_tray: false,
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(useSettingsStore.getState().settings.minimize_to_tray).toBe(true);
  });

  it("save persists activeTab into current_tab", async () => {
    const useSettingsStore = await loadStore();

    useSettingsStore.setState((s) => ({
      ...s,
      activeTab: "connect",
      settings: { ...s.settings, theme: "dark" },
    }));

    await useSettingsStore.getState().save();

    expect(settingsSave).toHaveBeenCalledTimes(1);
    const payload = settingsSave.mock.calls[0]?.[0] as AppSettings;
    expect(payload.current_tab).toBe("connect");
    expect(payload.theme).toBe("dark");
    expect(payload.config.roblox_settings.window_width).toBe(1280);
    expect(payload.config.roblox_settings.window_height).toBe(720);
    expect(payload.config.roblox_settings.window_fullscreen).toBe(false);
  });

  it("serializes overlapping saves so the later payload writes last", async () => {
    const firstWrite = deferred<void>();
    settingsSave
      .mockReturnValueOnce(firstWrite.promise)
      .mockResolvedValueOnce(undefined);

    const useSettingsStore = await loadStore();
    useSettingsStore.setState((s) => ({
      ...s,
      activeTab: "connect",
      settings: { ...s.settings, theme: "light" },
    }));
    const firstSave = useSettingsStore.getState().save();
    await Promise.resolve();

    useSettingsStore.setState((s) => ({
      ...s,
      activeTab: "boost",
      settings: { ...s.settings, theme: "dark" },
    }));
    const secondSave = useSettingsStore.getState().save();
    await Promise.resolve();

    expect(settingsSave).toHaveBeenCalledTimes(1);
    expect((settingsSave.mock.calls[0]?.[0] as AppSettings).theme).toBe(
      "light",
    );

    firstWrite.resolve();
    await Promise.all([firstSave, secondSave]);

    expect(settingsSave).toHaveBeenCalledTimes(2);
    const secondPayload = settingsSave.mock.calls[1]?.[0] as AppSettings;
    expect(secondPayload.theme).toBe("dark");
    expect(secondPayload.current_tab).toBe("boost");
  });

  it("continues queued saves after an earlier write fails", async () => {
    const firstWrite = deferred<void>();
    settingsSave
      .mockReturnValueOnce(firstWrite.promise)
      .mockResolvedValueOnce(undefined);

    const useSettingsStore = await loadStore();
    useSettingsStore.setState((s) => ({
      ...s,
      settings: { ...s.settings, theme: "light" },
    }));
    const firstSave = useSettingsStore.getState().save();
    await Promise.resolve();

    useSettingsStore.setState((s) => ({
      ...s,
      settings: { ...s.settings, theme: "dark" },
    }));
    const secondSave = useSettingsStore.getState().save();
    await Promise.resolve();

    expect(settingsSave).toHaveBeenCalledTimes(1);
    firstWrite.reject(new Error("disk full"));
    await Promise.all([firstSave, secondSave]);

    expect(settingsSave).toHaveBeenCalledTimes(2);
    expect((settingsSave.mock.calls[1]?.[0] as AppSettings).theme).toBe(
      "dark",
    );
    expect(reportError).toHaveBeenCalledWith(
      "Failed to save settings",
      expect.any(Error),
    );
  });
});
