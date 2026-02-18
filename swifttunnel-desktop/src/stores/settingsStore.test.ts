import { beforeEach, describe, expect, it, vi } from "vitest";

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
      json: JSON.stringify({
        theme: "light",
        config: {},
        optimizations_active: false,
        window_state: { x: null, y: null, width: 560, height: 750, maximized: false },
        selected_region: "singapore",
        selected_server: "singapore",
        current_tab: "boost",
        update_settings: { auto_check: true, last_check: null },
        update_channel: "Stable",
        minimize_to_tray: true,
        run_on_startup: true,
        auto_reconnect: true,
        resume_vpn_on_startup: false,
        last_connected_region: null,
        expanded_boost_info: [],
        selected_game_presets: ["roblox"],
        forced_servers: {},
        artificial_latency_ms: 0,
        experimental_mode: false,
        custom_relay_server: "",
        enable_discord_rpc: true,
        auto_routing_enabled: false,
        whitelisted_regions: [],
      }),
    });

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(settingsLoad).toHaveBeenCalled();
    expect(useSettingsStore.getState().isLoaded).toBe(true);
    expect(useSettingsStore.getState().settings.theme).toBe("light");
    expect(useSettingsStore.getState().activeTab).toBe("boost");
  });

  it("defaults minimize_to_tray to false when load fails", async () => {
    settingsLoad.mockRejectedValue(new Error("boom"));

    const useSettingsStore = await loadStore();
    await useSettingsStore.getState().load();

    expect(useSettingsStore.getState().isLoaded).toBe(true);
    expect(useSettingsStore.getState().settings.minimize_to_tray).toBe(false);
    expect(useSettingsStore.getState().settings.run_on_startup).toBe(true);
    expect(useSettingsStore.getState().settings.auto_reconnect).toBe(true);
    expect(useSettingsStore.getState().settings.resume_vpn_on_startup).toBe(false);
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
    const payload = settingsSave.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(payload) as { current_tab?: string; theme?: string };
    expect(parsed.current_tab).toBe("connect");
    expect(parsed.theme).toBe("dark");
  });
});
