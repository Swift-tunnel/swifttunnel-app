import { beforeEach, describe, expect, it, vi } from "vitest";
import type { UpdaterCheckResponse } from "../lib/types";

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
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
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

  it("keeps the newer update check result when an older check resolves last", async () => {
    const olderStableCheck = deferred<UpdaterCheckResponse>();
    const newerLiveCheck = deferred<UpdaterCheckResponse>();
    updaterCheckChannel
      .mockReturnValueOnce(olderStableCheck.promise)
      .mockReturnValueOnce(newerLiveCheck.promise);
    updaterInstallChannel.mockResolvedValue({
      installed_version: "2.0.0",
      release_tag: "v2.0.0",
    });

    const useUpdaterStore = await loadStore();
    const olderRun = useUpdaterStore.getState().checkForUpdates(false);
    mockSettingsStore.settings.update_channel = "Live";
    const newerRun = useUpdaterStore.getState().checkForUpdates(false);

    newerLiveCheck.resolve({
      current_version: "1.0.0",
      available_version: "2.0.0",
      release_tag: "v2.0.0",
      channel: "Live",
    });
    await newerRun;

    olderStableCheck.resolve({
      current_version: "1.0.0",
      available_version: null,
      release_tag: null,
      channel: "Stable",
    });
    await olderRun;

    expect(useUpdaterStore.getState().status).toBe("update_available");
    expect(useUpdaterStore.getState().availableVersion).toBe("2.0.0");

    await useUpdaterStore.getState().installUpdate();
    expect(updaterInstallChannel).toHaveBeenCalledWith("Live", "2.0.0");
  });

  it("does not let an older check failure overwrite a newer result", async () => {
    const olderCheck = deferred<UpdaterCheckResponse>();
    const newerCheck = deferred<UpdaterCheckResponse>();
    updaterCheckChannel
      .mockReturnValueOnce(olderCheck.promise)
      .mockReturnValueOnce(newerCheck.promise);

    const useUpdaterStore = await loadStore();
    const olderRun = useUpdaterStore.getState().checkForUpdates(false);
    const newerRun = useUpdaterStore.getState().checkForUpdates(false);

    newerCheck.resolve({
      current_version: "1.0.0",
      available_version: null,
      release_tag: null,
      channel: "Stable",
    });
    await newerRun;

    olderCheck.reject(new Error("old check failed"));
    await olderRun;

    expect(useUpdaterStore.getState().status).toBe("up_to_date");
    expect(useUpdaterStore.getState().availableVersion).toBeNull();
    expect(useUpdaterStore.getState().error).toBeNull();
  });

  it("does not let an older update-available check overwrite newer up-to-date state", async () => {
    const olderCheck = deferred<UpdaterCheckResponse>();
    const newerCheck = deferred<UpdaterCheckResponse>();
    updaterCheckChannel
      .mockReturnValueOnce(olderCheck.promise)
      .mockReturnValueOnce(newerCheck.promise);

    const useUpdaterStore = await loadStore();
    const olderRun = useUpdaterStore.getState().checkForUpdates(false);
    const newerRun = useUpdaterStore.getState().checkForUpdates(false);

    newerCheck.resolve({
      current_version: "2.0.0",
      available_version: null,
      release_tag: null,
      channel: "Stable",
    });
    await newerRun;

    olderCheck.resolve({
      current_version: "1.0.0",
      available_version: "1.5.1",
      release_tag: "v1.5.1",
      channel: "Stable",
    });
    await olderRun;

    expect(useUpdaterStore.getState().status).toBe("up_to_date");
    expect(useUpdaterStore.getState().availableVersion).toBeNull();

    await useUpdaterStore.getState().installUpdate();
    expect(updaterInstallChannel).not.toHaveBeenCalled();
  });

  it("does not let a stale auto-install tail install a newer check result", async () => {
    const notifyGate = deferred<void>();
    updaterCheckChannel
      .mockResolvedValueOnce({
        current_version: "1.0.0",
        available_version: "1.5.1",
        release_tag: "v1.5.1",
        channel: "Stable",
      })
      .mockResolvedValueOnce({
        current_version: "1.0.0",
        available_version: "2.0.0",
        release_tag: "v2.0.0",
        channel: "Stable",
      });
    notify.mockReturnValueOnce(notifyGate.promise).mockResolvedValue(undefined);
    updaterInstallChannel.mockResolvedValue({
      installed_version: "2.0.0",
      release_tag: "v2.0.0",
    });

    const useUpdaterStore = await loadStore();
    const olderRun = useUpdaterStore.getState().checkForUpdates(false, true);
    await Promise.resolve();
    await Promise.resolve();

    const newerRun = useUpdaterStore.getState().checkForUpdates(false, false);
    await newerRun;

    expect(useUpdaterStore.getState().status).toBe("update_available");
    expect(useUpdaterStore.getState().availableVersion).toBe("2.0.0");

    notifyGate.resolve();
    await olderRun;

    expect(updaterInstallChannel).not.toHaveBeenCalled();
    expect(useUpdaterStore.getState().status).toBe("update_available");
    expect(useUpdaterStore.getState().availableVersion).toBe("2.0.0");
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
