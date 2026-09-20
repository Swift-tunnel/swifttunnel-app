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
  });
});
