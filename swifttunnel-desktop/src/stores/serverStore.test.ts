import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LatencyEntry, ServerListResponse } from "../lib/types";

const {
  serverGetList,
  serverGetLatencies,
  serverRefresh,
  serverSmartSelect,
} = vi.hoisted(() => ({
  serverGetList: vi.fn(),
  serverGetLatencies: vi.fn(),
  serverRefresh: vi.fn(),
  serverSmartSelect: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  serverGetList,
  serverGetLatencies,
  serverRefresh,
  serverSmartSelect,
}));

const { reportError } = vi.hoisted(() => ({
  reportError: vi.fn(),
}));

vi.mock("../lib/errors", () => ({
  reportError,
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./serverStore")).useServerStore;
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

function serverList(id: string): ServerListResponse {
  return {
    regions: [
      {
        id,
        name: id.toUpperCase(),
        description: `${id} region`,
        country_code: "SG",
        servers: [`${id}-01`],
      },
    ],
    servers: [
      {
        region: id,
        name: `${id}-01`,
        country_code: "SG",
        ip: "203.0.113.10",
        port: 51820,
        relay_available: true,
        relay_port: 8080,
      },
    ],
    source: id,
  };
}

describe("stores/serverStore", () => {
  beforeEach(() => {
    serverGetList.mockReset();
    serverGetLatencies.mockReset();
    serverRefresh.mockReset();
    serverSmartSelect.mockReset();
    reportError.mockReset();
  });

  it("keeps the newer server list when an older fetch resolves last", async () => {
    const older = deferred<ServerListResponse>();
    const newer = deferred<ServerListResponse>();
    serverGetList
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const useServerStore = await loadStore();
    const olderRun = useServerStore.getState().fetchList();
    const newerRun = useServerStore.getState().fetchList();

    newer.resolve(serverList("newer"));
    await newerRun;

    older.resolve(serverList("older"));
    await olderRun;

    expect(useServerStore.getState().source).toBe("newer");
    expect(useServerStore.getState().regions[0]?.id).toBe("newer");
    expect(useServerStore.getState().error).toBeNull();
  });

  it("does not let an older list failure overwrite a newer success", async () => {
    const older = deferred<ServerListResponse>();
    const newer = deferred<ServerListResponse>();
    serverGetList
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const useServerStore = await loadStore();
    const olderRun = useServerStore.getState().fetchList();
    const newerRun = useServerStore.getState().fetchList();

    newer.resolve(serverList("fresh"));
    await newerRun;

    older.reject(new Error("old list failed"));
    await olderRun;

    expect(useServerStore.getState().source).toBe("fresh");
    expect(useServerStore.getState().isLoading).toBe(false);
    expect(useServerStore.getState().error).toBeNull();
  });

  it("keeps the newer latency map when an older latency fetch resolves last", async () => {
    const older = deferred<LatencyEntry[]>();
    const newer = deferred<LatencyEntry[]>();
    serverGetLatencies
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const useServerStore = await loadStore();
    const olderRun = useServerStore.getState().fetchLatencies();
    const newerRun = useServerStore.getState().fetchLatencies();

    newer.resolve([{ region: "singapore", latency_ms: 41 }]);
    await newerRun;

    older.resolve([{ region: "singapore", latency_ms: 180 }]);
    await olderRun;

    expect(useServerStore.getState().getLatency("singapore")).toBe(41);
  });

  it("refresh invalidates an already in-flight list fetch", async () => {
    const oldList = deferred<ServerListResponse>();
    const refreshGate = deferred<string>();
    const refreshedList = deferred<ServerListResponse>();
    serverGetList
      .mockReturnValueOnce(oldList.promise)
      .mockReturnValueOnce(refreshedList.promise);
    serverRefresh.mockReturnValueOnce(refreshGate.promise);

    const useServerStore = await loadStore();
    const oldRun = useServerStore.getState().fetchList();
    const refreshRun = useServerStore.getState().refresh();

    refreshGate.resolve("ok");
    await Promise.resolve();
    refreshedList.resolve(serverList("refreshed"));
    await refreshRun;

    oldList.resolve(serverList("old"));
    await oldRun;

    expect(serverRefresh).toHaveBeenCalledTimes(1);
    expect(useServerStore.getState().source).toBe("refreshed");
    expect(useServerStore.getState().regions[0]?.id).toBe("refreshed");
  });
});
