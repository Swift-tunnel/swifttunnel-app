import { beforeEach, describe, expect, it, vi } from "vitest";

const { updaterCheckChannel, updaterInstallChannel } = vi.hoisted(() => ({
  updaterCheckChannel: vi.fn(),
  updaterInstallChannel: vi.fn(),
}));

const { notify } = vi.hoisted(() => ({
  notify: vi.fn(),
}));

const { mockSettingsStore } = vi.hoisted(() => {
  const store = {
    settings: {
      update_channel: "Stable" as "Stable" | "Live",
      update_settings: {
        auto_check: true,
        last_check: null,
      },
    },
    update: vi.fn(),
    save: vi.fn(async () => {}),
  };
  return { mockSettingsStore: store };
});

vi.mock("../lib/commands", () => ({
  updaterCheckChannel,
  updaterInstallChannel,
}));

vi.mock("../lib/notifications", () => ({
  notify,
}));

vi.mock("./settingsStore", () => ({
  useSettingsStore: {
    getState: () => mockSettingsStore,
  },
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./updaterStore")).useUpdaterStore;
}

describe("stores/updaterStore", () => {
  beforeEach(() => {
    mockSettingsStore.settings.update_channel = "Stable";
    mockSettingsStore.settings.update_settings = { auto_check: true, last_check: null };
    mockSettingsStore.update.mockClear();
    mockSettingsStore.save.mockClear();

    updaterCheckChannel.mockReset();
    updaterInstallChannel.mockReset();
    notify.mockReset();

    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
  });

  it("marks up_to_date when no update is available and persists last_check", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: null,
      release_tag: null,
      channel: "Stable",
    });

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(true);

    expect(updaterCheckChannel).toHaveBeenCalledWith("Stable");
    expect(mockSettingsStore.update).toHaveBeenCalledWith({
      update_settings: {
        auto_check: true,
        last_check: 1_700_000_000,
      },
    });
    expect(mockSettingsStore.save).toHaveBeenCalled();

    const state = useUpdaterStore.getState();
    expect(state.status).toBe("up_to_date");
    expect(state.availableVersion).toBeNull();
    expect(state.lastChecked).toBe(1_700_000_000);
    expect(notify).toHaveBeenCalledWith("SwiftTunnel", "You are on the latest version.");
  });

  it("surfaces an available update on manual check and installs it via selected channel", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      channel: "Stable",
    });
    updaterInstallChannel.mockResolvedValue({
      installed_version: "1.5.1",
      release_tag: "v1.5.1",
    });

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(true);

    expect(useUpdaterStore.getState().status).toBe("update_available");
    expect(useUpdaterStore.getState().availableVersion).toBe("1.5.1");

    await useUpdaterStore.getState().installUpdate();

    expect(updaterInstallChannel).toHaveBeenCalledWith("Stable", "1.5.1");
    expect(useUpdaterStore.getState().status).toBe("up_to_date");
    expect(useUpdaterStore.getState().availableVersion).toBeNull();
    expect(useUpdaterStore.getState().progressPercent).toBe(100);
    expect(notify).toHaveBeenCalledWith(
      "SwiftTunnel Update",
      "Update installed. Restarting application...",
    );
  });

  it("auto-installs available updates during background checks", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      channel: "Stable",
    });
    updaterInstallChannel.mockResolvedValue({
      installed_version: "1.5.1",
      release_tag: "v1.5.1",
    });

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(false);

    expect(updaterInstallChannel).toHaveBeenCalledWith("Stable", "1.5.1");
    expect(useUpdaterStore.getState().status).toBe("up_to_date");
    expect(useUpdaterStore.getState().availableVersion).toBeNull();
  });

  it("uses Live channel when selected in settings", async () => {
    mockSettingsStore.settings.update_channel = "Live";

    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: null,
      release_tag: null,
      channel: "Live",
    });

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(false);

    expect(updaterCheckChannel).toHaveBeenCalledWith("Live");
  });

  it("transitions to error state when check fails", async () => {
    updaterCheckChannel.mockRejectedValue(new Error("network down"));

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(false);

    const state = useUpdaterStore.getState();
    expect(state.status).toBe("error");
    expect(state.error).toContain("network down");
  });
});
