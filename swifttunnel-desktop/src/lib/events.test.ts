import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ listen: vi.fn(), handle: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: h.listen }));
vi.mock("../stores/vpnStore", () => ({ useVpnStore: { getState: () => ({ handleStateEvent: h.handle, handleThroughputEvent: h.handle }) } }));
vi.mock("../stores/authStore", () => ({ useAuthStore: { getState: () => ({ handleStateEvent: h.handle }) } }));
vi.mock("../stores/boostStore", () => ({ useBoostStore: { getState: () => ({ handleMetricsEvent: h.handle, handleRamCleanProgress: h.handle }) } }));
vi.mock("../stores/serverStore", () => ({ useServerStore: { getState: () => ({ fetchList: h.handle }) } }));
vi.mock("../stores/updaterStore", () => ({ useUpdaterStore: { getState: () => ({ handleUpdaterProgress: h.handle, handleUpdaterDone: h.handle }) } }));
vi.mock("../stores/toastStore", () => ({ useToastStore: { getState: () => ({ addToast: h.handle }) } }));

beforeEach(() => vi.resetModules());

describe("native listener lifecycle", () => {
  it("releases a registration that finishes after cleanup", async () => {
    let finish!: (stop: () => void) => void;
    const stop = vi.fn();
    h.listen.mockReturnValueOnce(new Promise((resolve) => { finish = resolve; }));
    h.listen.mockImplementation(() => Promise.resolve(vi.fn()));
    const events = await import("./events");
    const init = events.initEventListeners();
    await Promise.resolve();
    await events.cleanupEventListeners();
    finish(stop);
    await init;
    expect(stop).toHaveBeenCalledTimes(1);
    expect(h.listen).toHaveBeenCalledTimes(1);
  });

  it("keeps only the newer registration set when starts overlap", async () => {
    let finish!: (stop: () => void) => void;
    const oldStop = vi.fn();
    const currentStops: Array<ReturnType<typeof vi.fn>> = [];
    h.listen.mockReturnValueOnce(new Promise((resolve) => { finish = resolve; }));
    h.listen.mockImplementation(() => {
      const stop = vi.fn();
      currentStops.push(stop);
      return Promise.resolve(stop);
    });
    const events = await import("./events");
    const older = events.initEventListeners();
    await Promise.resolve();
    const newer = events.initEventListeners();
    await newer;
    finish(oldStop);
    await older;
    expect(oldStop).toHaveBeenCalledTimes(1);
    expect(currentStops).toHaveLength(9);
    expect(currentStops.every((stop) => stop.mock.calls.length === 0)).toBe(true);
    await events.cleanupEventListeners();
    expect(currentStops.every((stop) => stop.mock.calls.length === 1)).toBe(true);
  });

  it("ignores events delivered from an obsolete listener", async () => {
    h.listen.mockResolvedValue(vi.fn());
    const events = await import("./events");
    await events.initEventListeners();
    const callback = h.listen.mock.calls[0][1];
    await events.cleanupEventListeners();
    callback({ payload: { state: "connected" } });
    expect(h.handle).not.toHaveBeenCalled();
  });

  it("releases earlier registrations when a later registration fails", async () => {
    const stop = vi.fn();
    h.listen.mockResolvedValueOnce(stop).mockRejectedValueOnce(new Error("registration failed"));
    const events = await import("./events");
    await expect(events.initEventListeners()).rejects.toThrow("registration failed");
    expect(stop).toHaveBeenCalledTimes(1);
  });

  it("does not tear down the newer set when an older registration fails", async () => {
    let fail!: (error: Error) => void;
    h.listen.mockReturnValueOnce(new Promise((_resolve, reject) => { fail = reject; }));
    const stops: Array<ReturnType<typeof vi.fn>> = [];
    h.listen.mockImplementation(() => {
      const stop = vi.fn();
      stops.push(stop);
      return Promise.resolve(stop);
    });
    const events = await import("./events");
    const older = events.initEventListeners();
    const failure = expect(older).rejects.toThrow("old failure");
    await events.initEventListeners();
    fail(new Error("old failure"));
    await failure;
    expect(stops).toHaveLength(9);
    expect(stops.every((stop) => stop.mock.calls.length === 0)).toBe(true);
    h.listen.mock.calls[1][1]({ payload: { state: "connected" } });
    expect(h.handle).toHaveBeenCalledOnce();
    await events.cleanupEventListeners();
  });
});
