import { beforeEach, describe, expect, it, vi } from "vitest";

const commands = vi.hoisted(() => ({
  networkStartStabilityTest: vi.fn(),
  networkStartSpeedTest: vi.fn(),
  networkStartBufferbloatTest: vi.fn(),
}));
vi.mock("../lib/commands", () => commands);

describe("network diagnostic sequence", () => {
  beforeEach(() => {
    vi.resetModules();
    Object.values(commands).forEach((mock) => mock.mockReset());
  });

  it("blocks individual competing tests and reset while native diagnostic work is pending", async () => {
    let finish!: (value: object) => void;
    commands.networkStartStabilityTest.mockReturnValue(new Promise(resolve => { finish = resolve; }));
    const store = (await import("./networkStore")).useNetworkStore;
    const running = store.getState().runStabilityTest();
    store.getState().reset();
    const remainedRunning = store.getState().stabilityStatus;
    await store.getState().runSpeedTest();
    await store.getState().runBufferbloatTest();
    const duplicate = store.getState().runStabilityTest();
    const stabilityCalls = commands.networkStartStabilityTest.mock.calls.length;
    finish({ packet_loss: 0 });
    await Promise.all([running, duplicate]);
    expect(remainedRunning).toBe("running");
    expect(stabilityCalls).toBe(1);
    expect(commands.networkStartSpeedTest).not.toHaveBeenCalled();
    expect(commands.networkStartBufferbloatTest).not.toHaveBeenCalled();
  });

  it("clears all previous results at the start of a full run", async () => {
    let finish!: (value: object) => void;
    commands.networkStartStabilityTest.mockReturnValue(new Promise(resolve => { finish = resolve; }));
    commands.networkStartSpeedTest.mockResolvedValue({ download_mbps: 20 });
    commands.networkStartBufferbloatTest.mockResolvedValue({ grade: "C" });
    const store = (await import("./networkStore")).useNetworkStore;
    store.setState({ speedStatus: "complete", bufferbloatStatus: "complete", speedResult: { download_mbps: 999 } as never, bufferbloatResult: { grade: "A" } as never });
    const running = store.getState().runAllTests();
    const snapshot = store.getState();
    finish({ packet_loss: 0 });
    await running;
    expect(snapshot.speedStatus).toBe("idle");
    expect(snapshot.speedResult).toBeNull();
    expect(snapshot.bufferbloatResult).toBeNull();
  });

  it("finishes each test before starting traffic that would contaminate the next measurement", async () => {
    let finishStability!: () => void;
    let finishSpeed!: () => void;
    commands.networkStartStabilityTest.mockReturnValue(new Promise<void>((resolve) => { finishStability = resolve; }));
    commands.networkStartSpeedTest.mockReturnValue(new Promise<void>((resolve) => { finishSpeed = resolve; }));
    commands.networkStartBufferbloatTest.mockResolvedValue({ grade: "A" });
    const store = (await import("./networkStore")).useNetworkStore;
    const run = store.getState().runAllTests(15);
    expect(commands.networkStartStabilityTest).toHaveBeenCalledWith(15);
    expect(commands.networkStartSpeedTest).not.toHaveBeenCalled();
    expect(commands.networkStartBufferbloatTest).not.toHaveBeenCalled();
    await store.getState().runAllTests();
    expect(commands.networkStartStabilityTest).toHaveBeenCalledOnce();
    finishStability();
    await vi.waitFor(() => expect(commands.networkStartSpeedTest).toHaveBeenCalledOnce());
    expect(commands.networkStartBufferbloatTest).not.toHaveBeenCalled();
    finishSpeed();
    await run;
    expect(commands.networkStartBufferbloatTest).toHaveBeenCalledOnce();
    expect(store.getState().bufferbloatStatus).toBe("complete");
  });

  it("keeps each error and continues remaining diagnostics", async () => {
    commands.networkStartStabilityTest.mockRejectedValue(new Error("ICMP unavailable"));
    commands.networkStartSpeedTest.mockRejectedValue(new Error("HTTP unavailable"));
    commands.networkStartBufferbloatTest.mockResolvedValue({ grade: "B" });
    const store = (await import("./networkStore")).useNetworkStore;
    await store.getState().runAllTests();
    expect(store.getState().stabilityError).toContain("ICMP unavailable");
    expect(store.getState().speedError).toContain("HTTP unavailable");
    expect(store.getState().bufferbloatStatus).toBe("complete");
    expect(store.getState().isRunning).toBe(false);
    commands.networkStartStabilityTest.mockResolvedValue({ packet_loss: 0 });
    await store.getState().runStabilityTest();
    expect(store.getState().stabilityStatus).toBe("complete");
  });

  it("keeps the full-run permit between individual phases", async () => {
    commands.networkStartStabilityTest.mockResolvedValue({ packet_loss: 0 });
    commands.networkStartSpeedTest.mockResolvedValue({ download_mbps: 50 });
    commands.networkStartBufferbloatTest.mockResolvedValue({ grade: "A" });
    const store = (await import("./networkStore")).useNetworkStore;
    let attempted = false;
    const stop = store.subscribe(state => {
      if (state.stabilityStatus === "complete" && !attempted) {
        attempted = true;
        void state.runSpeedTest();
      }
    });
    await store.getState().runAllTests();
    stop();
    expect(attempted).toBe(true);
    expect(commands.networkStartSpeedTest).toHaveBeenCalledOnce();
    expect(store.getState().isRunning).toBe(false);
  });
});
