import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  BufferbloatResultResponse,
  SpeedResultResponse,
  StabilityResultResponse,
} from "../lib/types";

const {
  networkStartStabilityTest,
  networkStartSpeedTest,
  networkStartBufferbloatTest,
} = vi.hoisted(() => ({
  networkStartStabilityTest: vi.fn(),
  networkStartSpeedTest: vi.fn(),
  networkStartBufferbloatTest: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  networkStartStabilityTest,
  networkStartSpeedTest,
  networkStartBufferbloatTest,
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./networkStore")).useNetworkStore;
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

function speedResult(download: number): SpeedResultResponse {
  return {
    download_mbps: download,
    upload_mbps: download / 2,
    server: `server-${download}`,
  };
}

function stabilityResult(avg: number): StabilityResultResponse {
  return {
    avg_ping: avg,
    min_ping: avg - 2,
    max_ping: avg + 2,
    jitter: 1,
    packet_loss: 0,
    ping_spread: 4,
    quality: "good",
    sample_count: 2,
    ping_samples: [
      { elapsed_secs: 0, latency_ms: avg - 2 },
      { elapsed_secs: 1, latency_ms: avg + 2 },
    ],
  };
}

function bufferbloatResult(bufferbloat: number): BufferbloatResultResponse {
  return {
    idle_latency: 20,
    loaded_latency: 20 + bufferbloat,
    bufferbloat_ms: bufferbloat,
    grade: "A",
  };
}

describe("stores/networkStore", () => {
  beforeEach(() => {
    networkStartStabilityTest.mockReset();
    networkStartSpeedTest.mockReset();
    networkStartBufferbloatTest.mockReset();
  });

  it("keeps the newer speed result when an older run resolves last", async () => {
    const older = deferred<SpeedResultResponse>();
    const newer = deferred<SpeedResultResponse>();
    networkStartSpeedTest
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const useNetworkStore = await loadStore();
    const olderRun = useNetworkStore.getState().runSpeedTest();
    const newerRun = useNetworkStore.getState().runSpeedTest();

    newer.resolve(speedResult(200));
    await newerRun;

    expect(useNetworkStore.getState().speedStatus).toBe("complete");
    expect(useNetworkStore.getState().speedResult).toEqual(speedResult(200));

    older.resolve(speedResult(20));
    await olderRun;

    expect(networkStartSpeedTest).toHaveBeenCalledTimes(2);
    expect(useNetworkStore.getState().speedStatus).toBe("complete");
    expect(useNetworkStore.getState().speedResult).toEqual(speedResult(200));
    expect(useNetworkStore.getState().speedError).toBeNull();
  });

  it("does not let an older speed error overwrite a newer success", async () => {
    const older = deferred<SpeedResultResponse>();
    const newer = deferred<SpeedResultResponse>();
    networkStartSpeedTest
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const useNetworkStore = await loadStore();
    const olderRun = useNetworkStore.getState().runSpeedTest();
    const newerRun = useNetworkStore.getState().runSpeedTest();

    newer.resolve(speedResult(150));
    await newerRun;
    older.reject(new Error("old run timed out"));
    await olderRun;

    expect(useNetworkStore.getState().speedStatus).toBe("complete");
    expect(useNetworkStore.getState().speedResult).toEqual(speedResult(150));
    expect(useNetworkStore.getState().speedError).toBeNull();
  });

  it("does not let an older stability error overwrite a newer success", async () => {
    const older = deferred<StabilityResultResponse>();
    const newer = deferred<StabilityResultResponse>();
    networkStartStabilityTest
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const useNetworkStore = await loadStore();
    const olderRun = useNetworkStore.getState().runStabilityTest(5);
    const newerRun = useNetworkStore.getState().runStabilityTest(5);

    newer.resolve(stabilityResult(35));
    await newerRun;
    older.reject(new Error("old stability run timed out"));
    await olderRun;

    expect(useNetworkStore.getState().stabilityStatus).toBe("complete");
    expect(useNetworkStore.getState().stabilityResult).toEqual(
      stabilityResult(35),
    );
    expect(useNetworkStore.getState().stabilityError).toBeNull();
  });

  it("does not let an older bufferbloat error overwrite a newer success", async () => {
    const older = deferred<BufferbloatResultResponse>();
    const newer = deferred<BufferbloatResultResponse>();
    networkStartBufferbloatTest
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const useNetworkStore = await loadStore();
    const olderRun = useNetworkStore.getState().runBufferbloatTest();
    const newerRun = useNetworkStore.getState().runBufferbloatTest();

    newer.resolve(bufferbloatResult(8));
    await newerRun;
    older.reject(new Error("old bufferbloat run timed out"));
    await olderRun;

    expect(useNetworkStore.getState().bufferbloatStatus).toBe("complete");
    expect(useNetworkStore.getState().bufferbloatResult).toEqual(
      bufferbloatResult(8),
    );
    expect(useNetworkStore.getState().bufferbloatError).toBeNull();
  });

  it("reset invalidates in-flight diagnostic results", async () => {
    const stability = deferred<StabilityResultResponse>();
    const speed = deferred<SpeedResultResponse>();
    const bufferbloat = deferred<BufferbloatResultResponse>();
    networkStartStabilityTest.mockReturnValueOnce(stability.promise);
    networkStartSpeedTest.mockReturnValueOnce(speed.promise);
    networkStartBufferbloatTest.mockReturnValueOnce(bufferbloat.promise);

    const useNetworkStore = await loadStore();
    const stabilityRun = useNetworkStore.getState().runStabilityTest(5);
    const speedRun = useNetworkStore.getState().runSpeedTest();
    const bufferbloatRun = useNetworkStore.getState().runBufferbloatTest();

    expect(useNetworkStore.getState().stabilityStatus).toBe("running");
    expect(useNetworkStore.getState().speedStatus).toBe("running");
    expect(useNetworkStore.getState().bufferbloatStatus).toBe("running");

    useNetworkStore.getState().reset();
    stability.resolve(stabilityResult(42));
    speed.resolve(speedResult(100));
    bufferbloat.resolve(bufferbloatResult(5));
    await Promise.all([stabilityRun, speedRun, bufferbloatRun]);

    expect(networkStartStabilityTest).toHaveBeenCalledWith(5);
    expect(useNetworkStore.getState().stabilityStatus).toBe("idle");
    expect(useNetworkStore.getState().stabilityResult).toBeNull();
    expect(useNetworkStore.getState().speedStatus).toBe("idle");
    expect(useNetworkStore.getState().speedResult).toBeNull();
    expect(useNetworkStore.getState().bufferbloatStatus).toBe("idle");
    expect(useNetworkStore.getState().bufferbloatResult).toBeNull();
  });
});
