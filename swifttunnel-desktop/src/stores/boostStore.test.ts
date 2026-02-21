import { beforeEach, describe, expect, it, vi } from "vitest";

const { boostUpdateConfig, boostRestartRoblox } = vi.hoisted(() => ({
  boostUpdateConfig: vi.fn(),
  boostRestartRoblox: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  boostGetMetrics: vi.fn(),
  boostGetSystemInfo: vi.fn(),
  boostUpdateConfig,
  boostRestartRoblox,
}));

const { notify } = vi.hoisted(() => ({
  notify: vi.fn(),
}));

vi.mock("../lib/notifications", () => ({
  notify,
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./boostStore")).useBoostStore;
}

describe("stores/boostStore", () => {
  beforeEach(() => {
    boostUpdateConfig.mockReset();
    boostRestartRoblox.mockReset();
    notify.mockReset();
  });

  it("updates config without notifications on success", async () => {
    boostUpdateConfig.mockResolvedValue(undefined);

    const useBoostStore = await loadStore();
    await useBoostStore.getState().updateConfig("{\"profile\":\"Balanced\"}");

    expect(boostUpdateConfig).toHaveBeenCalledTimes(1);
    expect(boostUpdateConfig).toHaveBeenCalledWith("{\"profile\":\"Balanced\"}");
    expect(useBoostStore.getState().error).toBeNull();
    expect(notify).not.toHaveBeenCalled();
  });

  it("stores error and notifies when config update fails", async () => {
    boostUpdateConfig.mockRejectedValue(new Error("boom"));

    const useBoostStore = await loadStore();
    await useBoostStore.getState().updateConfig("{\"profile\":\"Balanced\"}");

    expect(useBoostStore.getState().error).toBe("Error: boom");
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith(
      "Boost config failed",
      "Could not save optimization profile.",
    );
  });
});
