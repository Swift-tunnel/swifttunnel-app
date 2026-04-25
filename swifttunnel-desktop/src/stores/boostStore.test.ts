import { beforeEach, describe, expect, it, vi } from "vitest";

const { boostUpdateConfig, boostSyncEffectiveConfig, boostRestartRoblox, boostGetSystemMemory, boostCleanRam } = vi.hoisted(() => ({
  boostUpdateConfig: vi.fn(),
  boostSyncEffectiveConfig: vi.fn(),
  boostRestartRoblox: vi.fn(),
  boostGetSystemMemory: vi.fn(),
  boostCleanRam: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  boostGetMetrics: vi.fn(),
  boostGetSystemInfo: vi.fn(),
  boostGetSystemMemory,
  boostCleanRam,
  boostUpdateConfig,
  boostSyncEffectiveConfig,
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
    boostSyncEffectiveConfig.mockReset();
    boostRestartRoblox.mockReset();
    boostGetSystemMemory.mockReset();
    boostCleanRam.mockReset();
    notify.mockReset();
  });

  it("updates config without notifications on success", async () => {
    boostUpdateConfig.mockResolvedValue({ warnings: [] });

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
    await expect(
      useBoostStore.getState().updateConfig("{\"profile\":\"Balanced\"}"),
    ).rejects.toThrow("boom");

    expect(useBoostStore.getState().error).toBe("Error: boom");
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith(
      "Boost config failed",
      "Could not save optimization profile.",
    );
  });

  it("syncs effective config without notifying when persisted toggles were stale", async () => {
    const applied_config = { profile: "Balanced", network_settings: { disable_nagle: false } };
    boostSyncEffectiveConfig.mockResolvedValue({
      warnings: ["Network booster: Disable Nagle's algorithm was not active on Windows"],
      applied_config,
    });

    const useBoostStore = await loadStore();
    await expect(useBoostStore.getState().syncEffectiveConfig()).resolves.toBe(applied_config);

    expect(useBoostStore.getState().error).toContain("Disable Nagle");
    expect(notify).not.toHaveBeenCalled();
  });

  it("cleans RAM and updates state without notifications on success", async () => {
    boostGetSystemMemory.mockResolvedValue({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
      standby_mb: null,
      modified_mb: null,
    });

    const resp = {
      before: { total_mb: 16000, used_mb: 10000, available_mb: 6000, load_pct: 63, standby_mb: null, modified_mb: null },
      after: { total_mb: 16000, used_mb: 9000, available_mb: 7000, load_pct: 56, standby_mb: null, modified_mb: null },
      trimmed_count: 8,
      standby_purge: { attempted: true, success: true, skipped_reason: null },
      modified_flush: { attempted: true, success: true, skipped_reason: null },
      freed_mb: 1000,
      standby_freed_mb: null,
      modified_freed_mb: null,
      duration_ms: 900,
      warnings: [],
    };

    let resolveClean: (value: typeof resp) => void;
    boostCleanRam.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveClean = resolve;
        }),
    );

    const useBoostStore = await loadStore();
    const promise = useBoostStore.getState().cleanRam();

    expect(useBoostStore.getState().isCleaningRam).toBe(true);
    // Allow the click-time baseline snapshot to resolve before the cleaner starts.
    await new Promise((r) => setTimeout(r, 0));
    expect(boostCleanRam).toHaveBeenCalledTimes(1);
    resolveClean!(resp);
    await promise;

    expect(boostCleanRam).toHaveBeenCalledTimes(1);
    expect(boostGetSystemMemory).toHaveBeenCalledTimes(1);
    expect(useBoostStore.getState().isCleaningRam).toBe(false);
    expect(useBoostStore.getState().ramCleanResult).toEqual(resp);
    expect(useBoostStore.getState().systemMem).toEqual(resp.after);
    expect(useBoostStore.getState().ramCleanStartSnapshot).toEqual({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
      standby_mb: null,
      modified_mb: null,
    });
    expect(useBoostStore.getState().ramCleanDoneSnapshot).toEqual(resp.after);
    expect(notify).not.toHaveBeenCalled();
  });

  it("stores error and notifies when RAM clean fails", async () => {
    boostGetSystemMemory.mockResolvedValue({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
      standby_mb: null,
      modified_mb: null,
    });
    boostCleanRam.mockRejectedValue(new Error("boom"));

    const useBoostStore = await loadStore();
    await useBoostStore.getState().cleanRam();

    expect(useBoostStore.getState().error).toBe("Error: boom");
    expect(useBoostStore.getState().isCleaningRam).toBe(false);
    expect(useBoostStore.getState().ramCleanStartSnapshot).toBeNull();
    expect(useBoostStore.getState().ramCleanDoneSnapshot).toBeNull();
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith(
      "RAM cleaner failed",
      "Could not clean memory.",
    );
  });

  it("captures RAM cleaner start and done snapshots from progress events", async () => {
    const useBoostStore = await loadStore();

    useBoostStore.getState().handleRamCleanProgress({
      stage: "start",
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
      standby_mb: 2048,
      modified_mb: 512,
      trimmed_count: 0,
      current_process: null,
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanStartSnapshot).toEqual({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
      standby_mb: 2048,
      modified_mb: 512,
    });

    useBoostStore.getState().handleRamCleanProgress({
      stage: "trimming",
      total_mb: 16000,
      used_mb: 9500,
      available_mb: 6500,
      load_pct: 59,
      standby_mb: 2048,
      modified_mb: 512,
      trimmed_count: 1,
      current_process: "chrome.exe",
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanStartSnapshot).toEqual({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
      standby_mb: 2048,
      modified_mb: 512,
    });

    useBoostStore.getState().handleRamCleanProgress({
      stage: "done",
      total_mb: 16000,
      used_mb: 9000,
      available_mb: 7000,
      load_pct: 56,
      standby_mb: 256,
      modified_mb: 64,
      trimmed_count: 1,
      current_process: null,
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanDoneSnapshot).toEqual({
      total_mb: 16000,
      used_mb: 9000,
      available_mb: 7000,
      load_pct: 56,
      standby_mb: 256,
      modified_mb: 64,
    });
  });

  it("updates system memory snapshot from ram-clean-progress events", async () => {
    const useBoostStore = await loadStore();

    useBoostStore.getState().handleRamCleanProgress({
      stage: "trimming",
      total_mb: 16000,
      used_mb: 11000,
      available_mb: 5000,
      load_pct: 69,
      standby_mb: null,
      modified_mb: null,
      trimmed_count: 3,
      current_process: "chrome.exe",
      warning: null,
    });

    expect(useBoostStore.getState().systemMem).toEqual({
      total_mb: 16000,
      used_mb: 11000,
      available_mb: 5000,
      load_pct: 69,
      standby_mb: null,
      modified_mb: null,
    });
    expect(useBoostStore.getState().ramCleanStage).toBe("trimming");
    expect(useBoostStore.getState().ramCleanTrimmedCount).toBe(3);
    expect(useBoostStore.getState().ramCleanCurrentProcess).toBe("chrome.exe");
  });

  it("updateConfig resolves before restartRoblox can proceed (sequencing contract)", async () => {
    // Verifies the async contract used by BoostTab.restartAndApply:
    // updateConfig must fully resolve before restartRoblox is called.
    const callOrder: string[] = [];

    boostUpdateConfig.mockImplementation(
      () =>
        new Promise((resolve) =>
          setTimeout(() => {
            callOrder.push("updateConfig:resolved");
            resolve({ warnings: [] });
          }, 50),
        ),
    );
    boostRestartRoblox.mockImplementation(async () => {
      callOrder.push("restartRoblox:called");
    });

    const useBoostStore = await loadStore();
    const store = useBoostStore.getState();

    // Simulate the BoostTab.restartAndApply sequencing: await config, then restart
    await store.updateConfig('{"test":true}');
    await store.restartRoblox();

    expect(callOrder).toEqual([
      "updateConfig:resolved",
      "restartRoblox:called",
    ]);
  });

  it("progresses through flushing_modified stage", async () => {
    const useBoostStore = await loadStore();

    useBoostStore.getState().handleRamCleanProgress({
      stage: "start",
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
      standby_mb: 2048,
      modified_mb: 512,
      trimmed_count: 0,
      current_process: null,
      warning: null,
    });

    useBoostStore.getState().handleRamCleanProgress({
      stage: "flushing_modified",
      total_mb: 16000,
      used_mb: 9800,
      available_mb: 6200,
      load_pct: 61,
      standby_mb: 2048,
      modified_mb: 512,
      trimmed_count: 5,
      current_process: null,
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanStage).toBe("flushing_modified");
    expect(useBoostStore.getState().systemMem?.standby_mb).toBe(2048);
    expect(useBoostStore.getState().systemMem?.modified_mb).toBe(512);

    useBoostStore.getState().handleRamCleanProgress({
      stage: "standby_purge",
      total_mb: 16000,
      used_mb: 9800,
      available_mb: 6200,
      load_pct: 61,
      standby_mb: 2560,
      modified_mb: 64,
      trimmed_count: 5,
      current_process: null,
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanStage).toBe("standby_purge");
    // Modified pages should have been flushed to standby
    expect(useBoostStore.getState().systemMem?.modified_mb).toBe(64);
    expect(useBoostStore.getState().systemMem?.standby_mb).toBe(2560);
  });
});
