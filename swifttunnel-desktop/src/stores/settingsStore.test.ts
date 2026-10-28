import { beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "../lib/settings";
import type { AppSettings } from "../lib/types";

const { settingsLoad, settingsSave, boostResetRobloxClient, boostResetRobloxSettings, gamesSaveFlags, boostUpdateConfig, boostSyncEffectiveConfig } = vi.hoisted(() => ({
  settingsLoad: vi.fn(),
  settingsSave: vi.fn(),
  boostResetRobloxSettings: vi.fn(),
  boostResetRobloxClient: vi.fn(),
  gamesSaveFlags: vi.fn(),
  boostUpdateConfig: vi.fn(),
  boostSyncEffectiveConfig: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  settingsLoad,
  settingsSave,
  boostResetRobloxSettings,
  boostResetRobloxClient,
  gamesSaveFlags,
  boostUpdateConfig,
  boostSyncEffectiveConfig,
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./settingsStore")).useSettingsStore;
}

describe("stores/settingsStore", () => {
  it("retains a load failure for the persistent notice and clears it after a successful load", async () => {
    settingsLoad.mockRejectedValueOnce(new Error("Restart SwiftTunnel to reload your saved settings."));
    const store = await loadStore();
    await store.getState().load();
    expect(store.getState().loadError).toBe("Restart SwiftTunnel to reload your saved settings.");
    settingsLoad.mockResolvedValueOnce(structuredClone(DEFAULT_SETTINGS));
    await store.getState().load();
    expect(store.getState().loadError).toBeNull();
  });
  it("keeps a startup warning visible after preferences save and clears it after retry", async () => {
    const warning = "Your settings were saved, but Windows startup could not be updated. Retry startup setup.";
    settingsSave.mockResolvedValueOnce({ warning }).mockResolvedValueOnce({ warning: null });
    const store = await loadStore();
    await expect(store.getState().save(true)).resolves.toBeUndefined();
    expect(store.getState().saveError).toBeNull();
    expect(store.getState().saveWarning).toBe(warning);
    await store.getState().save(true);
    expect(store.getState().saveWarning).toBeNull();
  });

  it("orders a full client reset with saves and refreshes only the reset section", async () => {
    let release!: () => void;
    const order: string[] = [];
    settingsSave.mockImplementationOnce(async () => {
      order.push("earlier save");
      await new Promise<void>(resolve => { release = resolve; });
    }).mockImplementation(async () => { order.push("later save"); });
    const report = { failures: [], flag_files_removed: 1 };
    boostResetRobloxClient.mockImplementation(async () => { order.push("reset"); return report; });
    settingsLoad.mockResolvedValue(structuredClone(DEFAULT_SETTINGS));
    const store = await loadStore();
    store.getState().update({ config: { ...DEFAULT_SETTINGS.config,
      roblox_settings: { ...DEFAULT_SETTINGS.config.roblox_settings, unlock_fps: true },
    } });
    const first = store.getState().save(true);
    await Promise.resolve();
    const resetting = store.getState().resetRobloxClient();
    store.getState().setTab("games");
    store.getState().update({ minimize_to_tray: false, config: { ...store.getState().settings.config,
      overlay: { ...DEFAULT_SETTINGS.config.overlay, enabled: true },
    } });
    const last = store.getState().save(true);
    release();
    const results = await Promise.all([first, resetting, last]);
    expect(results[1]).toBe(report);
    expect(order).toEqual(["earlier save", "reset", "later save"]);
    expect(store.getState().activeTab).toBe("games");
    const saved = settingsSave.mock.calls[1][0];
    expect(saved.current_tab).toBe("games");
    expect(saved.minimize_to_tray).toBe(false);
    expect(saved.config.overlay.enabled).toBe(true);
    expect(saved.config.roblox_settings.unlock_fps).toBe(false);
  });

  it("keeps a failed full reset retryable without blocking queued saves", async () => {
    boostResetRobloxClient.mockRejectedValueOnce(new Error("Client files unavailable"));
    const store = await loadStore();
    const before = structuredClone(store.getState().settings);
    const resetting = store.getState().resetRobloxClient();
    const saving = store.getState().save(true);
    await expect(resetting).rejects.toThrow("Client files unavailable");
    await saving;
    expect(store.getState().settings).toEqual(before);
    expect(settingsLoad).not.toHaveBeenCalled();
    expect(settingsSave).toHaveBeenCalledOnce();
  });

  it("coalesces effective-state reads and publishes them before later full saves", async () => {
    let release!: (value: object) => void;
    boostSyncEffectiveConfig.mockReturnValueOnce(new Promise(resolve => { release = resolve; }));
    const store = await loadStore();
    store.getState().update({ config: { ...DEFAULT_SETTINGS.config,
      roblox_settings: { ...DEFAULT_SETTINGS.config.roblox_settings, unlock_fps: true },
    } });
    const reads = Array.from({ length: 20 }, () => store.getState().syncBoostConfig());
    await Promise.resolve();
    store.getState().update({ config: { ...store.getState().settings.config,
      overlay: { ...DEFAULT_SETTINGS.config.overlay, enabled: true },
    } });
    const saving = store.getState().save(true);
    await Promise.resolve();
    const wasWaiting = settingsSave.mock.calls.length === 0;
    release({ applied_config: DEFAULT_SETTINGS.config, warnings: [] });
    await Promise.all([...reads, saving]);
    expect(wasWaiting).toBe(true);
    expect(boostSyncEffectiveConfig).toHaveBeenCalledOnce();
    expect(settingsSave.mock.calls[0][0].config.roblox_settings.unlock_fps).toBe(false);
    expect(settingsSave.mock.calls[0][0].config.overlay.enabled).toBe(true);
  });

  it("releases a failed effective-state read so saves and a later read can recover", async () => {
    boostSyncEffectiveConfig.mockRejectedValueOnce(new Error("Read unavailable"))
      .mockResolvedValue({ applied_config: DEFAULT_SETTINGS.config, warnings: [] });
    const store = await loadStore();
    const syncing = store.getState().syncBoostConfig();
    const saving = store.getState().save(true);
    await expect(syncing).rejects.toThrow("Read unavailable");
    await saving;
    await store.getState().syncBoostConfig();
    expect(boostSyncEffectiveConfig).toHaveBeenCalledTimes(2);
    expect(settingsSave).toHaveBeenCalledOnce();
  });

  it("finishes earlier full saves before applying Boost", async () => {
    let release!: () => void;
    settingsSave.mockReturnValueOnce(new Promise<void>(resolve => { release = resolve; }));
    boostUpdateConfig.mockResolvedValue({ applied_config: DEFAULT_SETTINGS.config, warnings: [] });
    const store = await loadStore();
    const saving = store.getState().save(true);
    await Promise.resolve();
    const applying = store.getState().applyBoostConfig(JSON.stringify(DEFAULT_SETTINGS.config));
    await Promise.resolve();
    const wasWaiting = boostUpdateConfig.mock.calls.length === 0;
    release();
    await Promise.all([saving, applying]);
    expect(wasWaiting).toBe(true);
  });

  it("holds later saves until Boost merges its confirmed fields and preserves in-flight edits", async () => {
    let release!: (value: object) => void;
    boostUpdateConfig.mockReturnValueOnce(new Promise(resolve => { release = resolve; }));
    const store = await loadStore();
    const requested = structuredClone(DEFAULT_SETTINGS.config);
    requested.roblox_settings.unlock_fps = true;
    const applying = store.getState().applyBoostConfig(JSON.stringify(requested));
    await Promise.resolve();
    store.getState().update({ config: { ...store.getState().settings.config,
      overlay: { ...DEFAULT_SETTINGS.config.overlay, enabled: true },
    } });
    const saving = store.getState().save(true);
    await Promise.resolve();
    const wasWaiting = settingsSave.mock.calls.length === 0;
    release({ applied_config: requested, warnings: [] });
    await Promise.all([applying, saving]);
    expect(wasWaiting).toBe(true);
    expect(store.getState().settings.config.overlay.enabled).toBe(true);
    expect(settingsSave.mock.calls[0][0].config.overlay.enabled).toBe(true);
    expect(settingsSave.mock.calls[0][0].config.roblox_settings.unlock_fps).toBe(true);
  });

  it("rebases a waiting Boost draft over earlier confirmed flag changes", async () => {
    let release!: (value: object) => void;
    gamesSaveFlags.mockReturnValueOnce(new Promise(resolve => { release = resolve; }));
    boostUpdateConfig.mockImplementation(async (json: string) => ({ applied_config: JSON.parse(json), warnings: [] }));
    const store = await loadStore();
    const flags = { ...DEFAULT_SETTINGS.config.roblox_settings,
      custom_fflags_enabled: true, custom_fflags_json: '{"FFlagDebugSkyGray":true}',
    };
    const editing = store.getState().applyFastFlags(true, flags.custom_fflags_json, DEFAULT_SETTINGS.config.roblox_settings);
    await Promise.resolve();
    const requested = structuredClone(DEFAULT_SETTINGS.config);
    requested.roblox_settings.unlock_fps = true;
    const applying = store.getState().applyBoostConfig(JSON.stringify(requested));
    release({ applied_config: { ...DEFAULT_SETTINGS.config, roblox_settings: flags }, warnings: [] });
    await Promise.all([editing, applying]);
    const sent = JSON.parse(boostUpdateConfig.mock.calls[0][0]);
    expect(sent.roblox_settings.custom_fflags_json).toBe(flags.custom_fflags_json);
    expect(sent.roblox_settings.unlock_fps).toBe(true);
  });

  it("releases queued settings after Boost fails without publishing its draft", async () => {
    boostUpdateConfig.mockRejectedValueOnce(new Error("Could not apply"));
    const store = await loadStore();
    const before = structuredClone(store.getState().settings.config);
    const requested = structuredClone(before);
    requested.roblox_settings.unlock_fps = true;
    const applying = store.getState().applyBoostConfig(JSON.stringify(requested));
    const saving = store.getState().save(true);
    await expect(applying).rejects.toThrow("Could not apply");
    await saving;
    expect(store.getState().settings.config).toEqual(before);
    expect(settingsSave).toHaveBeenCalledOnce();
  });

  it("finishes earlier settings saves before applying native FastFlags", async () => {
    let release!: () => void;
    settingsSave.mockReturnValueOnce(new Promise<void>(resolve => { release = resolve; }));
    gamesSaveFlags.mockResolvedValue({ applied_config: DEFAULT_SETTINGS.config, warnings: [] });
    const store = await loadStore();
    const saving = store.getState().save(true);
    await Promise.resolve();
    const applying = store.getState().applyFastFlags(true, "{}", DEFAULT_SETTINGS.config.roblox_settings);
    await Promise.resolve();
    const nativeWasWaiting = gamesSaveFlags.mock.calls.length === 0;
    release();
    await Promise.all([saving, applying]);
    expect(nativeWasWaiting).toBe(true);
  });

  it("queues later saves behind FastFlags and preserves edits made during its native call", async () => {
    let release!: (value: { applied_config: AppSettings["config"]; warnings: string[] }) => void;
    gamesSaveFlags.mockReturnValueOnce(new Promise(resolve => { release = resolve; }));
    const store = await loadStore();
    const applying = store.getState().applyFastFlags(true, '{"FFlagDebugSkyGray":true}', DEFAULT_SETTINGS.config.roblox_settings);
    await Promise.resolve();
    store.getState().update({ config: { ...store.getState().settings.config,
      overlay: { ...DEFAULT_SETTINGS.config.overlay, enabled: true },
    } });
    const saving = store.getState().save(true);
    await Promise.resolve();
    const nativeWasWaiting = settingsSave.mock.calls.length === 0;
    const flags = { ...DEFAULT_SETTINGS.config.roblox_settings,
      custom_fflags_enabled: true, custom_fflags_json: '{"FFlagDebugSkyGray":true}', ultraboost: false,
    };
    release({ applied_config: { ...DEFAULT_SETTINGS.config, roblox_settings: flags }, warnings: [] });
    await Promise.all([applying, saving]);
    expect(nativeWasWaiting).toBe(true);
    expect(store.getState().settings.config.overlay.enabled).toBe(true);
    expect(settingsSave.mock.calls[0][0].config.overlay.enabled).toBe(true);
    expect(settingsSave.mock.calls[0][0].config.roblox_settings.custom_fflags_json).toBe(flags.custom_fflags_json);
  });

  it("keeps current settings and releases queued saves after a native FastFlag failure", async () => {
    gamesSaveFlags.mockRejectedValueOnce(new Error("Flags changed in another view"));
    const store = await loadStore();
    store.getState().update({ theme: "light" });
    const before = structuredClone(store.getState().settings.config);
    const applying = store.getState().applyFastFlags(true, "{}", before.roblox_settings);
    const saving = store.getState().save(true);
    await expect(applying).rejects.toThrow("Flags changed in another view");
    await saving;
    expect(store.getState().settings.config).toEqual(before);
    expect(settingsSave.mock.calls[0][0].theme).toBe("light");
  });
  it("reports a shared save failure to every waiting caller and allows retry", async () => {
    settingsSave.mockRejectedValueOnce(new Error("Disk unavailable")).mockResolvedValue(undefined);
    const store = await loadStore();
    const results = await Promise.allSettled([store.getState().save(true), store.getState().save(true)]);
    expect(results.every(result => result.status === "rejected")).toBe(true);
    expect(settingsSave).toHaveBeenCalledTimes(1);
    expect(store.getState().saveError).toBe("Disk unavailable");
    await store.getState().save(true);
    expect(settingsSave).toHaveBeenCalledTimes(2);
    expect(store.getState().saveError).toBeNull();
  });

  it("coalesces a burst behind a slow save and writes the latest preference", async () => {
    let finish!: () => void;
    settingsSave.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }))
      .mockResolvedValue(undefined);
    const store = await loadStore();
    const first = store.getState().save(true);
    await Promise.resolve();
    const queued: Promise<void>[] = [];
    for (let i = 1; i <= 40; i++) {
      store.getState().update({ theme: i === 40 ? "light" : "dark" });
      queued.push(store.getState().save(true));
    }
    expect(settingsSave).toHaveBeenCalledTimes(1);
    finish();
    await Promise.all([first, ...queued]);
    expect(settingsSave).toHaveBeenCalledTimes(2);
    expect(settingsSave.mock.calls[1][0].theme).toBe("light");
  });

  it("does not coalesce a post-reset save with one queued before Repair", async () => {
    let finish!: () => void;
    const order: string[] = [];
    settingsSave.mockImplementationOnce(async () => {
      order.push("first");
      await new Promise<void>(resolve => { finish = resolve; });
    }).mockImplementation(async (settings: AppSettings) => {
      order.push(settings.config.roblox_settings.ultraboost ? "before reset" : "after reset");
    });
    boostResetRobloxSettings.mockImplementation(async () => {
      order.push("reset");
      return structuredClone(DEFAULT_SETTINGS.config.roblox_settings);
    });
    const store = await loadStore();
    store.getState().update({ config: { ...DEFAULT_SETTINGS.config,
      roblox_settings: { ...DEFAULT_SETTINGS.config.roblox_settings, ultraboost: true } } });
    const first = store.getState().save(true);
    await Promise.resolve();
    const before = store.getState().save(true);
    const reset = store.getState().resetRobloxSettings();
    const after = store.getState().save(true);
    finish();
    await Promise.all([first, before, reset, after]);
    expect(order).toEqual(["first", "before reset", "reset", "after reset"]);
  });

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
    const first = store.getState().save();
    await Promise.resolve(); // Start this write before queuing the second one.
    await Promise.all([first, store.getState().save()]);
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
    boostResetRobloxClient.mockReset();
    gamesSaveFlags.mockReset();
    boostUpdateConfig.mockReset();
    boostSyncEffectiveConfig.mockReset();
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
    await Promise.resolve(); // The first request is already in flight.
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
