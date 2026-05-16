import type { UnlistenFn } from "@tauri-apps/api/event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  listen: vi.fn(),
  handleAuthStateEvent: vi.fn(),
  handleBoostMetricsEvent: vi.fn(),
  handleRamCleanProgress: vi.fn(),
  handleUpdaterDone: vi.fn(),
  handleUpdaterProgress: vi.fn(),
  handleVpnStateEvent: vi.fn(),
  handleVpnThroughputEvent: vi.fn(),
  fetchServerList: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: mocks.listen,
}));

vi.mock("../stores/authStore", () => ({
  useAuthStore: {
    getState: () => ({ handleStateEvent: mocks.handleAuthStateEvent }),
  },
}));

vi.mock("../stores/boostStore", () => ({
  useBoostStore: {
    getState: () => ({
      handleMetricsEvent: mocks.handleBoostMetricsEvent,
      handleRamCleanProgress: mocks.handleRamCleanProgress,
    }),
  },
}));

vi.mock("../stores/serverStore", () => ({
  useServerStore: {
    getState: () => ({ fetchList: mocks.fetchServerList }),
  },
}));

vi.mock("../stores/updaterStore", () => ({
  useUpdaterStore: {
    getState: () => ({
      handleUpdaterDone: mocks.handleUpdaterDone,
      handleUpdaterProgress: mocks.handleUpdaterProgress,
    }),
  },
}));

vi.mock("../stores/vpnStore", () => ({
  useVpnStore: {
    getState: () => ({
      handleStateEvent: mocks.handleVpnStateEvent,
      handleThroughputEvent: mocks.handleVpnThroughputEvent,
    }),
  },
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function loadEventsModule() {
  vi.resetModules();
  return await import("./events");
}

describe("lib/events", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("unregisters all listeners on cleanup", async () => {
    const unlisteners = Array.from({ length: 8 }, () => vi.fn());
    let nextUnlistener = 0;
    mocks.listen.mockImplementation(async () => unlisteners[nextUnlistener++]);
    const { cleanupEventListeners, initEventListeners } =
      await loadEventsModule();

    await initEventListeners();
    await cleanupEventListeners();

    expect(mocks.listen).toHaveBeenCalledTimes(8);
    for (const unlisten of unlisteners) {
      expect(unlisten).toHaveBeenCalledTimes(1);
    }
  });

  it("unregisters a listener that resolves after cleanup invalidates init", async () => {
    const lateRegistration = deferred<UnlistenFn>();
    const lateUnlisten = vi.fn();
    mocks.listen.mockReturnValueOnce(lateRegistration.promise);
    const { cleanupEventListeners, initEventListeners } =
      await loadEventsModule();

    const initPromise = initEventListeners();
    expect(mocks.listen).toHaveBeenCalledTimes(1);

    await cleanupEventListeners();
    lateRegistration.resolve(lateUnlisten);
    await initPromise;

    expect(lateUnlisten).toHaveBeenCalledTimes(1);
    expect(mocks.listen).toHaveBeenCalledTimes(1);
  });

  it("cleans partial listeners when a later registration fails", async () => {
    const firstUnlisten = vi.fn();
    mocks.listen
      .mockResolvedValueOnce(firstUnlisten)
      .mockRejectedValueOnce(new Error("listen failed"));
    const { cleanupEventListeners, initEventListeners } =
      await loadEventsModule();

    await expect(initEventListeners()).rejects.toThrow("listen failed");

    expect(firstUnlisten).toHaveBeenCalledTimes(1);

    await cleanupEventListeners();

    expect(firstUnlisten).toHaveBeenCalledTimes(1);
  });
});
