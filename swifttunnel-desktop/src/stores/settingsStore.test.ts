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

async function loadStore() {
  vi.resetModules();
  return (await import("./settingsStore")).useSettingsStore;
}

describe("stores/settingsStore", () => {
  beforeEach(() => {
    settingsLoad.mockReset();
    settingsSave.mockReset();
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
      useSettingsStore.getState().settings.config.roblox_settings.graphics_quality,
    ).toBe("Automatic");
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.unlock_fps,
    ).toBe(false);
  });

  it("defaults minimize_to_tray to true when load fails", async () => {
    settingsLoad.mockRejectedValue(new Error("boom"));

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(useSettingsStore.getState().isLoaded).toBe(true);
    expect(useSettingsStore.getState().settings.minimize_to_tray).toBe(true);
    expect(useSettingsStore.getState().settings.run_on_startup).toBe(false);
    expect(useSettingsStore.getState().settings.auto_reconnect).toBe(false);
    expect(useSettingsStore.getState().settings.resume_vpn_on_startup).toBe(false);
    expect(useSettingsStore.getState().settings.preferred_physical_adapter_guid).toBe(
      null,
    );
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
    expect(useSettingsStore.getState().settings.config.roblox_settings.window_width).toBe(
      1280,
    );
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.graphics_quality,
    ).toBe("Automatic");
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.unlock_fps,
    ).toBe(false);
    expect(useSettingsStore.getState().settings.config.roblox_settings.window_height).toBe(
      720,
    );
    expect(
      useSettingsStore.getState().settings.config.roblox_settings.window_fullscreen,
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
});
