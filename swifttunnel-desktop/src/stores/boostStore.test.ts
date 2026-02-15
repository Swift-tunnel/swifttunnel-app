import { beforeEach, describe, expect, it, vi } from "vitest";

const { boostToggle } = vi.hoisted(() => ({
  boostToggle: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  boostGetMetrics: vi.fn(),
  boostToggle,
  boostGetSystemInfo: vi.fn(),
  boostUpdateConfig: vi.fn(),
  boostRestartRoblox: vi.fn(),
}));

const { notify } = vi.hoisted(() => ({
  notify: vi.fn(),
}));

vi.mock("../lib/notifications", () => ({
  notify,
}));

const { settingsUpdate, settingsSave } = vi.hoisted(() => ({
  settingsUpdate: vi.fn(),
  settingsSave: vi.fn(),
}));

vi.mock("./settingsStore", () => ({
  useSettingsStore: {
    getState: () => ({
      update: settingsUpdate,
      save: settingsSave,
    }),
  },
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./boostStore")).useBoostStore;
}

describe("stores/boostStore", () => {
  beforeEach(() => {
    boostToggle.mockReset();
    notify.mockReset();
    settingsUpdate.mockReset();
    settingsSave.mockReset();
  });

  it("syncs optimizations_active to settingsStore after a successful toggle", async () => {
    boostToggle.mockResolvedValue(undefined);

    const useBoostStore = await loadStore();
    await useBoostStore.getState().toggle(true);

    expect(boostToggle).toHaveBeenCalledTimes(1);
    expect(boostToggle).toHaveBeenCalledWith(true);
    expect(useBoostStore.getState().isActive).toBe(true);
    expect(useBoostStore.getState().isToggling).toBe(false);
    expect(settingsUpdate).toHaveBeenCalledTimes(1);
    expect(settingsUpdate).toHaveBeenCalledWith({ optimizations_active: true });
    expect(settingsSave).toHaveBeenCalledTimes(1);
    expect(notify).not.toHaveBeenCalled();
  });

  it("does not sync settings when toggle fails and emits a notification", async () => {
    boostToggle.mockRejectedValue(new Error("boom"));

    const useBoostStore = await loadStore();
    await useBoostStore.getState().toggle(true);

    expect(useBoostStore.getState().isActive).toBe(false);
    expect(useBoostStore.getState().isToggling).toBe(false);
    expect(useBoostStore.getState().error).toBe("Error: boom");
    expect(settingsUpdate).not.toHaveBeenCalled();
    expect(settingsSave).not.toHaveBeenCalled();
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith(
      "Boost failed",
      "Could not apply optimization changes.",
    );
  });
});

