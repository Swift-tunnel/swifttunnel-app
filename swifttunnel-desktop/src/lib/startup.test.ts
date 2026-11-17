import { describe, expect, it, vi } from "vitest";
import { pollUpdateRequirement, shouldAutoReconnectOnLaunch, startupProgress, watchStartupRecoveryCompletion } from "./startup";

describe("startupProgress", () => {
  const steps = (done: boolean[]) =>
    done.map((d, i) => ({ label: `step ${i + 1}`, done: d }));

  it("keeps a sliver of bar before any step finishes", () => {
    expect(startupProgress(steps([false, false, false, false]))).toEqual({
      done: 0,
      fraction: 0.06,
      current: "step 1",
    });
  });

  it("fills one share per finished step and names the first one still running", () => {
    expect(startupProgress(steps([true, false, true, false]))).toEqual({
      done: 2,
      fraction: 0.5,
      current: "step 2",
    });
  });

  it("is full with nothing running once every step is done", () => {
    expect(startupProgress(steps([true, true, true, true]))).toEqual({
      done: 4,
      fraction: 1,
      current: null,
    });
  });

  it("treats no steps as finished", () => {
    expect(startupProgress([])).toEqual({ done: 0, fraction: 1, current: null });
  });
});

it("clears the update gate on a successful null read and keeps just one pending poll", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("window", globalThis);
  let finish!: (message: string | null) => void;
  const read = vi.fn<() => Promise<string | null>>()
    .mockResolvedValueOnce("Update required")
    .mockRejectedValueOnce(new Error("IPC unavailable"))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const publish = vi.fn();
  const stop = pollUpdateRequirement(read, publish);
  try {
    await vi.advanceTimersByTimeAsync(81_500);
    expect(read).toHaveBeenCalledTimes(3);
    expect(publish.mock.calls).toEqual([["Update required"]]);
    finish(null);
    await vi.advanceTimersByTimeAsync(0);
    expect(publish.mock.calls).toEqual([["Update required"], [null]]);
  } finally {
    stop();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  }
});

describe("shouldAutoReconnectOnLaunch", () => {
  it("returns true when auth is logged in, vpn is disconnected, and settings allow reconnect", () => {
    expect(
      shouldAutoReconnectOnLaunch("logged_in", "disconnected", {
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
    ).toBe(true);
  });

  it("returns false when user is not logged in", () => {
    expect(
      shouldAutoReconnectOnLaunch("logged_out", "disconnected", {
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
    ).toBe(false);
    expect(
      shouldAutoReconnectOnLaunch("banned", "disconnected", {
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
    ).toBe(false);
  });

  it("returns false when reconnect is disabled or no prior active tunnel marker exists", () => {
    expect(
      shouldAutoReconnectOnLaunch("logged_in", "disconnected", {
        auto_reconnect: false,
        resume_vpn_on_startup: true,
      }),
    ).toBe(false);
    expect(
      shouldAutoReconnectOnLaunch("logged_in", "disconnected", {
        auto_reconnect: true,
        resume_vpn_on_startup: false,
      }),
    ).toBe(false);
  });
});

describe("watchStartupRecoveryCompletion", () => {
  it("catches recovery that finishes before the completion listener is ready", async () => {
    let register!: (stop: () => void) => void;
    let emit!: () => void;
    const unlisten = vi.fn();
    const isDone = vi.fn(async () => done);
    const complete = vi.fn();
    let done = false;
    const stop = watchStartupRecoveryCompletion((handler) => {
      emit = handler;
      return new Promise(resolve => { register = resolve; });
    }, isDone, complete, vi.fn());

    expect(isDone).not.toHaveBeenCalled();
    done = true;
    register(unlisten);
    await vi.waitFor(() => expect(complete).toHaveBeenCalledOnce());
    emit();
    expect(complete).toHaveBeenCalledOnce();
    stop();
    expect(unlisten).toHaveBeenCalledOnce();
  });

  it("still checks recovery if listener registration fails", async () => {
    const error = new Error("listen failed");
    const complete = vi.fn();
    const onSubscribeError = vi.fn();
    const stop = watchStartupRecoveryCompletion(
      async () => { throw error; },
      async () => true,
      complete,
      onSubscribeError,
    );

    await vi.waitFor(() => expect(complete).toHaveBeenCalledOnce());
    expect(onSubscribeError).toHaveBeenCalledWith(error);
    stop();
  });
});
