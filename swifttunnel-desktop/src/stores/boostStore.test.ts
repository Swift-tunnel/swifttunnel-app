import { beforeEach, describe, expect, it, vi } from "vitest";

const { boostUpdateConfig, boostRestartRoblox, boostGetSystemMemory, boostCleanRam } = vi.hoisted(() => ({
  boostUpdateConfig: vi.fn(),
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
    boostGetSystemMemory.mockReset();
    boostCleanRam.mockReset();
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

  it("cleans RAM and updates state without notifications on success", async () => {
    boostGetSystemMemory.mockResolvedValue({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
    });

    const resp = {
      before: { total_mb: 16000, used_mb: 10000, available_mb: 6000, load_pct: 63 },
      after: { total_mb: 16000, used_mb: 9000, available_mb: 7000, load_pct: 56 },
      trimmed_count: 8,
      standby_purge: { attempted: true, success: true, skipped_reason: null },
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
      trimmed_count: 0,
      current_process: null,
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanStartSnapshot).toEqual({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
    });

    useBoostStore.getState().handleRamCleanProgress({
      stage: "trimming",
      total_mb: 16000,
      used_mb: 9500,
      available_mb: 6500,
      load_pct: 59,
      trimmed_count: 1,
      current_process: "chrome.exe",
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanStartSnapshot).toEqual({
      total_mb: 16000,
      used_mb: 10000,
      available_mb: 6000,
      load_pct: 63,
    });

    useBoostStore.getState().handleRamCleanProgress({
      stage: "done",
      total_mb: 16000,
      used_mb: 9000,
      available_mb: 7000,
      load_pct: 56,
      trimmed_count: 1,
      current_process: null,
      warning: null,
    });

    expect(useBoostStore.getState().ramCleanDoneSnapshot).toEqual({
      total_mb: 16000,
      used_mb: 9000,
      available_mb: 7000,
      load_pct: 56,
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
      trimmed_count: 3,
      current_process: "chrome.exe",
      warning: null,
    });

    expect(useBoostStore.getState().systemMem).toEqual({
      total_mb: 16000,
      used_mb: 11000,
      available_mb: 5000,
      load_pct: 69,
    });
    expect(useBoostStore.getState().ramCleanStage).toBe("trimming");
    expect(useBoostStore.getState().ramCleanTrimmedCount).toBe(3);
    expect(useBoostStore.getState().ramCleanCurrentProcess).toBe("chrome.exe");
  });
});
