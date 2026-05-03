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

  it("surfaces available updates during background checks without auto-installing", async () => {
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

    expect(updaterInstallChannel).not.toHaveBeenCalled();
    expect(useUpdaterStore.getState().status).toBe("update_available");
    expect(useUpdaterStore.getState().availableVersion).toBe("1.5.1");
    expect(notify).toHaveBeenCalledWith(
      "Update Available",
      "Version 1.5.1 is ready to install.",
    );
  });

  it("auto-installs when autoInstall flag is true and update is available", async () => {
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
    await useUpdaterStore.getState().checkForUpdates(false, true);

    expect(updaterInstallChannel).toHaveBeenCalledWith("Stable", "1.5.1");
    expect(useUpdaterStore.getState().status).toBe("up_to_date");
    expect(useUpdaterStore.getState().progressPercent).toBe(100);
    expect(notify).toHaveBeenCalledWith(
      "SwiftTunnel Update",
      "Updating to v1.5.1, restarting...",
    );
  });

  it("does not auto-install when autoInstall is false even on background check", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      channel: "Stable",
    });

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(false, false);

    expect(updaterInstallChannel).not.toHaveBeenCalled();
    expect(useUpdaterStore.getState().status).toBe("update_available");
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

  it("installs using the channel that was checked, even if settings change later", async () => {
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

    mockSettingsStore.settings.update_channel = "Live";
    await useUpdaterStore.getState().installUpdate();

    expect(updaterInstallChannel).toHaveBeenCalledWith("Stable", "1.5.1");
  });

  it("updates install progress from updater progress events", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      channel: "Stable",
    });
    let resolveInstall: (value: {
      installed_version: string;
      release_tag: string;
    }) => void;
    updaterInstallChannel.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveInstall = resolve;
        }),
    );

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(false);
    const installPromise = useUpdaterStore.getState().installUpdate();

    useUpdaterStore
      .getState()
      .handleUpdaterProgress({ downloaded: 50, total: 100 });

    expect(useUpdaterStore.getState().status).toBe("installing");
    expect(useUpdaterStore.getState().progressPercent).toBe(50);

    useUpdaterStore.getState().handleUpdaterDone();
    expect(useUpdaterStore.getState().progressPercent).toBe(100);

    resolveInstall!({ installed_version: "1.5.1", release_tag: "v1.5.1" });
    await installPromise;
  });

  it("signals activity when updater progress has an unknown total", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      channel: "Stable",
    });
    updaterInstallChannel.mockImplementation(
      () =>
        new Promise(() => {
          // Keep install in progress for the progress event assertion.
        }),
    );

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(false);
    void useUpdaterStore.getState().installUpdate();

    useUpdaterStore
      .getState()
      .handleUpdaterProgress({ downloaded: 1024, total: null });

    expect(useUpdaterStore.getState().status).toBe("installing");
    expect(useUpdaterStore.getState().progressPercent).toBe(1);
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
