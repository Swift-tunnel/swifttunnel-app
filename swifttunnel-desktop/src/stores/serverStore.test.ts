import { beforeEach, describe, expect, it, vi } from "vitest";

const { serverGetLatencies, serverGetList, serverRefresh } = vi.hoisted(() => ({ serverGetLatencies: vi.fn(), serverGetList: vi.fn(), serverRefresh: vi.fn() }));
vi.mock("../lib/commands", () => ({
  serverGetLatencies,
  serverGetList,
  serverRefresh,
  serverSmartSelect: vi.fn(),
}));

beforeEach(() => { vi.resetModules(); vi.resetAllMocks(); });

it("keeps city-best ping distinct from each relay's own ping", async () => {
  serverGetLatencies.mockResolvedValue([
    { region: "singapore", latency_ms: 10, server_id: null },
    { region: "singapore", latency_ms: 70, server_id: "singapore" },
    { region: "singapore-02", latency_ms: 10, server_id: "singapore-02" },
  ]);
  const store = (await import("./serverStore")).useServerStore;
  await store.getState().fetchLatencies();
  expect(store.getState().getLatency("singapore")).toBe(10);
  expect(store.getState().getLatency("relay:singapore")).toBe(70);
  expect(store.getState().getLatency("relay:singapore-02")).toBe(10);
});

it("does not let an old cached list undo a completed refresh", async () => {
  let finishOld!: (value: object) => void;
  serverGetList.mockReturnValueOnce(new Promise(resolve => { finishOld = resolve; }))
    .mockResolvedValueOnce({ regions: [{ id: "new" }], servers: [], source: "fresh" });
  serverRefresh.mockResolvedValue(undefined);
  const store = (await import("./serverStore")).useServerStore;
  const old = store.getState().fetchList();
  await store.getState().refresh();
  finishOld({ regions: [{ id: "old" }], servers: [], source: "stale" });
  await old;
  expect(store.getState().source).toBe("fresh");
});

it("shares refresh work and keeps list readers waiting for the fresh list", async () => {
  let finishRefresh!: () => void;
  serverRefresh.mockReturnValue(new Promise<void>(resolve => { finishRefresh = resolve; }));
  serverGetList.mockResolvedValue({ regions: [], servers: [], source: "fresh" });
  const store = (await import("./serverStore")).useServerStore;
  const jobs = [store.getState().refresh(), store.getState().refresh(), store.getState().fetchList()];
  const refreshCalls = serverRefresh.mock.calls.length;
  const earlyReads = serverGetList.mock.calls.length;
  finishRefresh();
  await Promise.all(jobs);
  expect(refreshCalls).toBe(1);
  expect(earlyReads).toBe(0);
  expect(serverGetList).toHaveBeenCalledOnce();
  expect(store.getState().isLoading).toBe(false);
});

it("allows retry after a failed refresh and keeps the last usable list", async () => {
  serverGetList.mockResolvedValue({ regions: [], servers: [], source: "last good" });
  serverRefresh.mockRejectedValueOnce({ message: "Network unavailable" }).mockResolvedValueOnce(undefined);
  const store = (await import("./serverStore")).useServerStore;
  await store.getState().fetchList();
  await store.getState().refresh();
  expect(store.getState().source).toBe("last good");
  expect(store.getState().error).toBe("Network unavailable");
  expect(store.getState().isLoading).toBe(false);
  serverGetList.mockResolvedValue({ regions: [], servers: [], source: "recovered" });
  await store.getState().refresh();
  expect(store.getState().source).toBe("recovered");
  expect(store.getState().error).toBeNull();
});

it("shares ordinary list reads without starting a network refresh", async () => {
  let finish!: (value: object) => void;
  serverGetList.mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const store = (await import("./serverStore")).useServerStore;
  const jobs = Array.from({ length: 10 }, () => store.getState().fetchList());
  const calls = serverGetList.mock.calls.length;
  finish({ regions: [], servers: [], source: "cached" });
  await Promise.all(jobs);
  expect(calls).toBe(1);
  expect(serverRefresh).not.toHaveBeenCalled();
});

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


it("drops displayed and in-flight pings when a relay id moves to a new box", async () => {
  const list = (ip: string) => ({
    regions: [{ id: "jakarta", name: "Jakarta", country_code: "ID", servers: ["jakarta-01"] }],
    servers: [{ region: "jakarta-01", ip, port: 51820, relay_port: 51821, relay_available: true }],
    source: "API",
  });
  serverGetList.mockResolvedValueOnce(list("192.0.2.1")).mockResolvedValueOnce(list("192.0.2.2"));
  serverGetLatencies.mockResolvedValueOnce([{ region: "jakarta", latency_ms: 5 }]);
  const store = (await import("./serverStore")).useServerStore;
  await store.getState().fetchList();
  await store.getState().fetchLatencies();
  expect(store.getState().getLatency("jakarta")).toBe(5);
  let finish!: (value: object) => void;
  serverGetLatencies.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
  const oldScan = store.getState().fetchLatencies();
  await store.getState().fetchList();
  expect(store.getState().getLatency("jakarta")).toBeNull();
  finish([{ region: "jakarta", latency_ms: 6 }]);
  await oldScan;
  expect(store.getState().getLatency("jakarta")).toBeNull();
});
