import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ listen: vi.fn(), handle: vi.fn(), report: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: h.listen }));
vi.mock("../stores/vpnStore", () => ({ useVpnStore: { getState: () => ({ handleStateEvent: h.handle }) } }));
vi.mock("../stores/authStore", () => ({ useAuthStore: { getState: () => ({ handleStateEvent: h.handle }) } }));
vi.mock("../stores/boostStore", () => ({ useBoostStore: { getState: () => ({ handleRamCleanProgress: h.handle }) } }));
vi.mock("../stores/serverStore", () => ({ useServerStore: { getState: () => ({ fetchList: h.handle }) } }));
vi.mock("../stores/updaterStore", () => ({ useUpdaterStore: { getState: () => ({ handleUpdaterProgress: h.handle, handleUpdaterDone: h.handle }) } }));
vi.mock("../stores/toastStore", () => ({ useToastStore: { getState: () => ({ addToast: h.handle }) } }));
vi.mock("./errors", () => ({ reportError: h.report }));

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
    expect(h.listen).toHaveBeenCalledTimes(7);
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
    expect(currentStops).toHaveLength(13);
    expect(currentStops.slice(0, 6).every((stop) => stop.mock.calls.length === 1)).toBe(true);
    expect(currentStops.slice(6).every((stop) => stop.mock.calls.length === 0)).toBe(true);
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

  it("keeps VPN and sign-in listeners when an optional registration fails or stalls", async () => {
    const stop = vi.fn();
    const lateStop = vi.fn();
    const failure = new Error("registration failed");
    let finish!: (stop: () => void) => void;
    h.listen.mockImplementation(async (name) => {
      if (name === "ram-clean-progress") throw failure;
      if (name === "updater://progress") return new Promise(resolve => { finish = resolve; });
      return stop;
    });
    const events = await import("./events");
    await events.initEventListeners();
    expect(stop).not.toHaveBeenCalled();
    expect(h.report).toHaveBeenCalledWith(expect.stringContaining("ram-clean-progress"), failure, expect.anything());
    h.listen.mock.calls[0][1]({ payload: { state: "connected" } });
    h.listen.mock.calls[1][1]({ payload: { state: "logged_in" } });
    expect(h.handle).toHaveBeenCalledTimes(2);
    await events.cleanupEventListeners();
    finish(lateStop);
    await vi.waitFor(() => expect(lateStop).toHaveBeenCalledOnce());
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
    await events.initEventListeners();
    fail(new Error("old failure"));
    await older;
    expect(stops).toHaveLength(13);
    expect(stops.slice(6).every((stop) => stop.mock.calls.length === 0)).toBe(true);
    expect(h.report).not.toHaveBeenCalled();
    h.listen.mock.calls[7][1]({ payload: { state: "connected" } });
    expect(h.handle).toHaveBeenCalledOnce();
    await events.cleanupEventListeners();
  });
});
