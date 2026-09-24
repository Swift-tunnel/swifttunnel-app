import { describe, expect, it } from "vitest";
import { shouldAutoReconnectOnLaunch, startupProgress } from "./startup";

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
