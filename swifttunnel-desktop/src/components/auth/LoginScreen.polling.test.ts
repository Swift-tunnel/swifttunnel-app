import { describe, expect, it, vi } from "vitest";
import { runOAuthPollTick } from "./LoginScreen";

function createDeps(overrides?: Partial<Parameters<typeof runOAuthPollTick>[0]>) {
  let disposed = false;
  let polling = false;

  const deps = {
    isDisposed: vi.fn(() => disposed),
    isPolling: vi.fn(() => polling),
    setPolling: vi.fn((next: boolean) => {
      polling = next;
    }),
    getStartedAt: vi.fn(() => 0),
    now: vi.fn(() => 1_000),
    setElapsedSecs: vi.fn(),
    clearPoll: vi.fn(),
    cancelOAuth: vi.fn(async () => {}),
    pollOAuth: vi.fn(async () => false),
    setDisposed: (next: boolean) => {
      disposed = next;
    },
    get polling() {
      return polling;
    },
    ...overrides,
  };

  return deps;
}

describe("LoginScreen OAuth polling", () => {
  it("does not start a poll tick after cleanup", async () => {
    const deps = createDeps();
    deps.setDisposed(true);

    await runOAuthPollTick(deps);

    expect(deps.setPolling).not.toHaveBeenCalled();
    expect(deps.setElapsedSecs).not.toHaveBeenCalled();
    expect(deps.pollOAuth).not.toHaveBeenCalled();
  });

  it("clears the interval when OAuth completes", async () => {
    const deps = createDeps({
      pollOAuth: vi.fn(async () => true),
    });

    await runOAuthPollTick(deps);

    expect(deps.setElapsedSecs).toHaveBeenCalledWith(1);
    expect(deps.pollOAuth).toHaveBeenCalledTimes(1);
    expect(deps.clearPoll).toHaveBeenCalledTimes(1);
    expect(deps.polling).toBe(false);
  });

  it("does not clear the interval after cleanup happens during poll", async () => {
    let deps!: ReturnType<typeof createDeps>;
    const pollOAuth = vi.fn(async () => {
      deps.setDisposed(true);
      return true;
    });
    deps = createDeps({ pollOAuth });

    await runOAuthPollTick(deps);

    expect(deps.clearPoll).not.toHaveBeenCalled();
    expect(deps.polling).toBe(false);
  });

  it("clears and cancels the OAuth flow on timeout", async () => {
    const deps = createDeps({
      now: vi.fn(() => 120_000),
    });

    await runOAuthPollTick(deps);

    expect(deps.clearPoll).toHaveBeenCalledTimes(1);
    expect(deps.cancelOAuth).toHaveBeenCalledWith(
      "Login timed out. Please try again.",
    );
    expect(deps.pollOAuth).not.toHaveBeenCalled();
    expect(deps.polling).toBe(false);
  });

  it("releases the polling lock when polling throws", async () => {
    const deps = createDeps({
      pollOAuth: vi.fn(async () => {
        throw new Error("poll failed");
      }),
    });

    await expect(runOAuthPollTick(deps)).rejects.toThrow("poll failed");

    expect(deps.polling).toBe(false);
  });
});
