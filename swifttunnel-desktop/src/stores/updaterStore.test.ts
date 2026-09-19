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

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

const available = {
  current_version: "1.0.0", available_version: "1.5.1",
  release_tag: "v1.5.1", release_notes: "Test release", channel: "Stable",
};

describe("stores/updaterStore", () => {
  beforeEach(() => {
    mockSettingsStore.settings.update_channel = "Stable";
    mockSettingsStore.settings.update_settings = { auto_check: true, last_check: null };
    mockSettingsStore.update.mockClear();
    mockSettingsStore.save.mockClear();

    updaterCheckChannel.mockReset();
    updaterInstallChannel.mockReset();
    notify.mockReset();
    const storage = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => storage.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => {
        storage.set(key, value);
      }),
      removeItem: vi.fn((key: string) => {
        storage.delete(key);
      }),
      clear: vi.fn(() => {
        storage.clear();
      }),
      key: vi.fn((index: number) => Array.from(storage.keys())[index] ?? null),
      get length() {
        return storage.size;
      },
    });

    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
  });

  it("does not start duplicate native installs", async () => {
    updaterCheckChannel.mockResolvedValue(available);
    const install = deferred<{ reboot_required: boolean }>();
    updaterInstallChannel.mockReturnValue(install.promise);
    const store = await loadStore();
    await store.getState().checkForUpdates();
    const first = store.getState().installUpdate();
    const second = store.getState().installUpdate();
    install.resolve({ reboot_required: false });
    await Promise.all([first, second]);
    expect(updaterInstallChannel).toHaveBeenCalledOnce();
  });

  it("keeps installation progress when a background check is requested", async () => {
    updaterCheckChannel.mockResolvedValue(available);
    const install = deferred<{ reboot_required: boolean }>();
    updaterInstallChannel.mockReturnValue(install.promise);
    const store = await loadStore();
    await store.getState().checkForUpdates();
    const installing = store.getState().installUpdate();
    await store.getState().checkForUpdates();
    const status = store.getState().status;
    install.resolve({ reboot_required: false });
    await installing;
    expect(status).toBe("installing");
    expect(updaterCheckChannel).toHaveBeenCalledOnce();
  });

  it.each(["success", "failure"])("ignores an older check's %s after installation starts", async (outcome) => {
    updaterCheckChannel.mockResolvedValueOnce(available);
    const install = deferred<{ reboot_required: boolean }>();
    updaterInstallChannel.mockReturnValue(install.promise);
    const store = await loadStore();
    await store.getState().checkForUpdates();
    const check = deferred<typeof available>();
    updaterCheckChannel.mockReturnValueOnce(check.promise);
    const checking = store.getState().checkForUpdates();
    const installing = store.getState().installUpdate();
    if (outcome === "success") check.resolve(available);
    else check.reject(new Error("late check failure"));
    await checking;
    const status = store.getState().status;
    install.resolve({ reboot_required: false });
    await installing;
    expect(status).toBe("installing");
  });

  it("retains the newest check when checks finish out of order", async () => {
    const old = deferred<typeof available>();
    updaterCheckChannel.mockReturnValueOnce(old.promise).mockResolvedValueOnce({
      ...available, available_version: "1.5.2", release_tag: "v1.5.2",
    });
    const store = await loadStore();
    const first = store.getState().checkForUpdates();
    await store.getState().checkForUpdates();
    old.resolve(available);
    await first;
    expect(store.getState().availableVersion).toBe("1.5.2");
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
      release_notes: "- Faster startup",
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
    expect(useUpdaterStore.getState().releaseNotes).toBe("- Faster startup");
    expect(useUpdaterStore.getState().showWhatsNew).toBe(true);

    await useUpdaterStore.getState().installUpdate();

    expect(updaterInstallChannel).toHaveBeenCalledWith("Stable", "1.5.1");
    expect(useUpdaterStore.getState().status).toBe("up_to_date");
    expect(useUpdaterStore.getState().availableVersion).toBeNull();
    expect(useUpdaterStore.getState().showWhatsNew).toBe(false);
    expect(useUpdaterStore.getState().progressPercent).toBe(100);
    expect(notify).toHaveBeenCalledWith(
      "SwiftTunnel Update",
      "Update installed. Reopen SwiftTunnel if it does not restart.",
    );
  });

  it("surfaces available updates during background checks without auto-installing", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      release_notes: "- New popup",
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
    expect(useUpdaterStore.getState().showWhatsNew).toBe(true);
    expect(notify).not.toHaveBeenCalled();
  });

  it("does not show the whats-new popup again after dismissing the same release", async () => {
    updaterCheckChannel.mockResolvedValue({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      release_notes: "- New popup",
      channel: "Stable",
    });

    const useUpdaterStore = await loadStore();
    await useUpdaterStore.getState().checkForUpdates(false);

    expect(useUpdaterStore.getState().showWhatsNew).toBe(true);
    useUpdaterStore.getState().dismissWhatsNew();
    expect(useUpdaterStore.getState().showWhatsNew).toBe(false);

    await useUpdaterStore.getState().checkForUpdates(false);
    expect(useUpdaterStore.getState().showWhatsNew).toBe(false);
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
