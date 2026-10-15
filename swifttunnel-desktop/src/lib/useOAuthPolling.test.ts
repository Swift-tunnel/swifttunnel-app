import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => (() => void) | undefined>,
  setElapsed: vi.fn(),
}));
vi.mock("react", () => ({
  useEffect: (effect: () => (() => void) | undefined) => h.effects.push(effect),
  useState: () => [0, h.setElapsed],
}));
vi.mock("./errors", () => ({ reportError: vi.fn() }));
import { reportError } from "./errors";
import { OAUTH_TIMEOUT_MS, useOAuthPolling } from "./useOAuthPolling";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

describe("browser sign-in polling", () => {
  let cleanups: Array<() => void>;
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "performance", "Date"] });
    vi.stubGlobal("window", { setInterval, clearInterval });
    h.effects.length = 0;
    cleanups = [];
  });
  afterEach(() => {
    cleanups.forEach((stop) => stop());
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });
  function start(poll = vi.fn().mockResolvedValue(false), waiting = true) {
    const cancel = vi.fn().mockResolvedValue(undefined);
    useOAuthPolling(waiting, poll, cancel);
    const stop = h.effects[h.effects.length - 1]() ?? (() => {});
    cleanups.push(stop);
    return { poll, cancel, stop };
  }

  it("times out even when the native poll never returns", async () => {
    const { poll, cancel } = start(vi.fn(() => new Promise<boolean>(() => {})));
    await vi.advanceTimersByTimeAsync(OAUTH_TIMEOUT_MS + 5000);
    expect(poll).toHaveBeenCalledOnce();
    expect(cancel).toHaveBeenCalledExactlyOnceWith("Login timed out. Please try again.");
    expect(h.setElapsed).toHaveBeenLastCalledWith(120);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("uses elapsed time when the system clock moves backward or forward", async () => {
    const { cancel } = start();
    await vi.advanceTimersByTimeAsync(30_000);
    vi.setSystemTime(Date.now() - 86_400_000);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(h.setElapsed).toHaveBeenLastCalledWith(60);
    vi.setSystemTime(Date.now() + 172_800_000);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(cancel).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("a previous attempt cannot stop the replacement timer", async () => {
    const oldReply = deferred<boolean>();
    const previous = start(vi.fn(() => oldReply.promise));
    await vi.advanceTimersByTimeAsync(1000);
    previous.stop();
    const current = start();
    oldReply.resolve(true);
    await vi.advanceTimersByTimeAsync(3000);
    expect(current.poll).toHaveBeenCalledTimes(3);
    expect(current.cancel).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(1);
  });

  it("retires the timer on success or unmount", async () => {
    const complete = start(vi.fn().mockResolvedValue(true));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(complete.poll).toHaveBeenCalledOnce();
    expect(complete.cancel).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    const reply = deferred<boolean>();
    const pending = start(vi.fn(() => reply.promise));
    await vi.advanceTimersByTimeAsync(1000);
    pending.stop();
    h.setElapsed.mockClear();
    reply.resolve(false);
    await vi.advanceTimersByTimeAsync(OAUTH_TIMEOUT_MS);
    expect(h.setElapsed).not.toHaveBeenCalled();
    expect(pending.cancel).not.toHaveBeenCalled();
  });

  it("can recover from a rejected poll without overlapping requests", async () => {
    const reply = deferred<boolean>();
    const { poll } = start(vi.fn().mockReturnValueOnce(reply.promise).mockResolvedValue(false));
    await vi.advanceTimersByTimeAsync(5000);
    expect(poll).toHaveBeenCalledOnce();
    reply.reject(new Error("owned failure"));
    await vi.advanceTimersByTimeAsync(1000);
    expect(reportError).toHaveBeenCalledOnce();
    expect(poll).toHaveBeenCalledTimes(2);
  });

  it("does not poll when no browser sign-in is pending", async () => {
    const { poll, cancel } = start(undefined, false);
    await vi.advanceTimersByTimeAsync(OAUTH_TIMEOUT_MS);
    expect(poll).not.toHaveBeenCalled();
    expect(cancel).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
