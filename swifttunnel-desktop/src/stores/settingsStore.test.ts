import { beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "../lib/settings";
import type { AppSettings } from "../lib/types";

const { settingsLoad, settingsSave, boostResetRobloxSettings } = vi.hoisted(() => ({
  settingsLoad: vi.fn(),
  settingsSave: vi.fn(),
  boostResetRobloxSettings: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  settingsLoad,
  settingsSave,
  boostResetRobloxSettings,
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./settingsStore")).useSettingsStore;
}

describe("stores/settingsStore", () => {
  it("keeps an explicit relay until changing city or enabling Auto Route", async () => {
    const store = await loadStore();
    const manual = { region: "singapore", server_id: "singapore-02", ip: "192.0.2.2", port: 51821 };
    store.getState().update({ manual_relay: manual });
    expect(store.getState().settings.auto_routing_enabled).toBe(false);
    store.getState().update({ enable_api_tunneling: true });
    expect(store.getState().settings.manual_relay).toEqual(manual);
    store.getState().update({ selected_region: "tokyo" });
    expect(store.getState().settings.manual_relay).toBeNull();
    store.getState().update({ manual_relay: manual });
    store.getState().update({ auto_routing_enabled: true });
    expect(store.getState().settings.manual_relay).toBeNull();
  });
  it("keeps a save failure visible until a later save actually succeeds", async () => {
    settingsSave.mockRejectedValueOnce({ message: "Disk full" });
    const store = await loadStore();
    await store.getState().save();
    expect(store.getState().saveError).toBe("Disk full");
    let finish!: () => void;
    settingsSave.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
    const retry = store.getState().save(true);
    await Promise.resolve();
    expect(store.getState().saveError).toBe("Disk full");
    finish();
    await retry;
    expect(store.getState().saveError).toBeNull();
  });

  it("retains the newest failure after a successful earlier queued save", async () => {
    settingsSave.mockResolvedValueOnce(undefined).mockRejectedValueOnce({ message: "Access denied" });
    const store = await loadStore();
    await Promise.all([store.getState().save(), store.getState().save()]);
    expect(store.getState().saveError).toBe("Access denied");
  });

  it("makes Auto and Route Assist exclusive in either toggle order", async () => {
    const store = await loadStore();
    store.getState().update({ enable_api_tunneling: true });
    expect(store.getState().settings.auto_routing_enabled).toBe(false);
    store.getState().update({ auto_routing_enabled: true });
    expect(store.getState().settings.enable_api_tunneling).toBe(false);
    store.getState().update({ enable_api_tunneling: true });
    expect(store.getState().settings.auto_routing_enabled).toBe(false);
  });

  it("preserves a saved Route Assist choice when migrating Auto defaults", async () => {
    settingsLoad.mockResolvedValue({ ...DEFAULT_SETTINGS, auto_routing_enabled: true, enable_api_tunneling: true });
    const store = await loadStore();
    await store.getState().load();
    expect(store.getState().settings.enable_api_tunneling).toBe(true);
    expect(store.getState().settings.auto_routing_enabled).toBe(false);
  });
  beforeEach(() => {
    settingsLoad.mockReset();
    settingsSave.mockReset();
    boostResetRobloxSettings.mockReset();
  });

  it("loads settings and sets activeTab from current_tab", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      theme: "light",
      config: {},
      current_tab: "network",
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
    expect(useSettingsStore.getState().activeTab).toBe("network");
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

  it("migrates the renamed 'boost' tab onto 'games'", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      current_tab: "boost",
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(useSettingsStore.getState().activeTab).toBe("games");
  });

  it("keeps a slow earlier save from overwriting the latest preference", async () => {
    let finishFirst!: () => void;
    const firstWrite = new Promise<void>((resolve) => { finishFirst = resolve; });
    let persisted = false;
    settingsSave.mockImplementation(async (settings: AppSettings) => {
      if (!settings.minimize_to_tray) await firstWrite;
      persisted = settings.minimize_to_tray;
    });
    const useSettingsStore = await loadStore();
    useSettingsStore.getState().update({ minimize_to_tray: false });
    const first = useSettingsStore.getState().save();
    await Promise.resolve(); // Let the first write enter IPC before the next edit.
    useSettingsStore.getState().update({ minimize_to_tray: true });
    const second = useSettingsStore.getState().save();
    await Promise.resolve();
    finishFirst();
    await Promise.all([first, second]);
    expect(persisted).toBe(true);
    expect(settingsSave).toHaveBeenCalledTimes(2);
  });

  it("still saves a later preference after an earlier save fails", async () => {
    settingsSave.mockRejectedValueOnce(new Error("disk unavailable")).mockResolvedValueOnce(undefined);
    const useSettingsStore = await loadStore();
    const first = useSettingsStore.getState().save();
    useSettingsStore.getState().update({ minimize_to_tray: true });
    const second = useSettingsStore.getState().save();
    await Promise.all([first, second]);
    expect(settingsSave).toHaveBeenCalledTimes(2);
    expect(settingsSave.mock.calls[1][0].minimize_to_tray).toBe(true);
  });

  it("does not let a save queued during repair restore the old Roblox config", async () => {
    let finishReset!: () => void;
    const gate = new Promise<void>((resolve) => { finishReset = resolve; });
    boostResetRobloxSettings.mockImplementation(async () => {
      await gate;
      return structuredClone(DEFAULT_SETTINGS.config.roblox_settings);
    });
    settingsSave.mockResolvedValue(undefined);
    const store = await loadStore();
    store.getState().update({ config: {
      ...DEFAULT_SETTINGS.config,
      roblox_settings: { ...DEFAULT_SETTINGS.config.roblox_settings, ultraboost: true },
    } });
    store.getState().setTab("repair");
    const reset = store.getState().resetRobloxSettings();
    await Promise.resolve();
    store.getState().update({ minimize_to_tray: false });
    const save = store.getState().save();
    await Promise.resolve();
    expect(settingsSave).not.toHaveBeenCalled();
    finishReset();
    await Promise.all([reset, save]);
    expect(store.getState().settings.config.roblox_settings.ultraboost).toBe(false);
    expect(store.getState().activeTab).toBe("repair");
    expect(settingsSave.mock.calls[0][0].config.roblox_settings.ultraboost).toBe(false);
    expect(settingsSave.mock.calls[0][0].minimize_to_tray).toBe(false);
  });

  it("surfaces native reset failure and keeps preferences retryable", async () => {
    boostResetRobloxSettings.mockRejectedValue(new Error("FFlag file is locked"));
    settingsSave.mockResolvedValue(undefined);
    const store = await loadStore();
    store.getState().update({ config: {
      ...DEFAULT_SETTINGS.config,
      roblox_settings: { ...DEFAULT_SETTINGS.config.roblox_settings, ultraboost: true },
    } });
    await expect(store.getState().resetRobloxSettings()).rejects.toThrow("FFlag file is locked");
    expect(store.getState().settings.config.roblox_settings.ultraboost).toBe(true);
    await store.getState().save();
    expect(settingsSave).toHaveBeenCalledTimes(1);
  });

  it("lets Repair observe a failed settings save without poisoning subsequent saves", async () => {
    settingsSave.mockRejectedValueOnce(new Error("settings disk full")).mockResolvedValueOnce(undefined);
    const store = await loadStore();
    await expect(store.getState().save(true)).rejects.toThrow("settings disk full");
    await expect(store.getState().save(true)).resolves.toBeUndefined();
    expect(settingsSave).toHaveBeenCalledTimes(2);
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
    expect(network.firewall_fix).toBe(false);
  });

  it("drops removed QoS fields without enabling replacement boosts", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      config: {
        ...DEFAULT_SETTINGS.config,
        network_settings: {
          ...DEFAULT_SETTINGS.config.network_settings,
          enable_network_boost: true,
          disable_nagle: false,
          disable_network_throttling: false,
          gaming_qos: true,
          prioritize_roblox_traffic: true,
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
    expect("gaming_qos" in network).toBe(false);
    expect("prioritize_roblox_traffic" in network).toBe(false);
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
      "manual",
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

  it("defaults minimize_to_tray to true when the save has no value", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      minimize_to_tray: undefined,
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(useSettingsStore.getState().settings.minimize_to_tray).toBe(true);
  });

  // Settings → General exposes this now, so a saved false is a real choice.
  it("honors an explicit minimize_to_tray opt-out", async () => {
    settingsLoad.mockResolvedValue({
      ...DEFAULT_SETTINGS,
      minimize_to_tray: false,
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(useSettingsStore.getState().settings.minimize_to_tray).toBe(false);
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
