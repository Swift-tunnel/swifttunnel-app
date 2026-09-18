import { beforeEach, describe, expect, it, vi } from "vitest";

const { serverGetLatencies } = vi.hoisted(() => ({ serverGetLatencies: vi.fn() }));
vi.mock("../lib/commands", () => ({
  serverGetLatencies,
  serverGetList: vi.fn(),
  serverRefresh: vi.fn(),
  serverSmartSelect: vi.fn(),
}));

beforeEach(() => vi.resetModules());

describe("server latency polling", () => {
  it("shares a delayed scan across timer ticks and refresh clicks", async () => {
    const entries = [{ region: "singapore", latency_ms: 40 }];
    let finish!: (value: typeof entries) => void;
    serverGetLatencies.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const store = (await import("./serverStore")).useServerStore;
    const requests = Array.from({ length: 30 }, () => store.getState().fetchLatencies());
    const callsWhilePending = serverGetLatencies.mock.calls.length;
    finish(entries);
    await Promise.all(requests);
    expect(callsWhilePending).toBe(1);
    expect(store.getState().getLatency("singapore")).toBe(40);

    serverGetLatencies.mockResolvedValueOnce([{ region: "singapore", latency_ms: 55 }]);
    await store.getState().fetchLatencies();
    expect(serverGetLatencies).toHaveBeenCalledTimes(2);
    expect(store.getState().getLatency("singapore")).toBe(55);
  });

  it("permits a fresh scan after an error and preserves the last measurement", async () => {
    serverGetLatencies
      .mockResolvedValueOnce([{ region: "singapore", latency_ms: 40 }])
      .mockRejectedValueOnce(new Error("probe unavailable"))
      .mockResolvedValueOnce([{ region: "singapore", latency_ms: 50 }]);
    const store = (await import("./serverStore")).useServerStore;
    await store.getState().fetchLatencies();
    await store.getState().fetchLatencies();
    expect(store.getState().getLatency("singapore")).toBe(40);
    await store.getState().fetchLatencies();
    expect(store.getState().getLatency("singapore")).toBe(50);
    expect(serverGetLatencies).toHaveBeenCalledTimes(3);
  });
});
