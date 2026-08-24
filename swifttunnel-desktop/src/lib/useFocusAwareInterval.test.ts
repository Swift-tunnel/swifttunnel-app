import { describe, expect, it } from "vitest";

import { pollPeriodMs } from "./useFocusAwareInterval";

const ACTIVE = 2_000;
const IDLE = 15_000;

describe("pollPeriodMs", () => {
  it("polls at the active rate while the window is focused", () => {
    expect(
      pollPeriodMs(ACTIVE, IDLE, { idleWhenUnfocused: true, hasFocus: true }),
    ).toBe(ACTIVE);
  });

  it("backs right off once the window loses focus", () => {
    // The bug this covers: the Connect tab polled throughput, state and ping
    // several times a second inside WebView2 while the player was in a game,
    // updating a window nobody was looking at. Users reported it as
    // SwiftTunnel making the game stutter and traced it to Edge WebView.
    expect(
      pollPeriodMs(ACTIVE, IDLE, { idleWhenUnfocused: true, hasFocus: false }),
    ).toBe(IDLE);
  });

  it("keeps the fast rate when the user turns the setting off", () => {
    // Someone watching the graph on a second monitor is never focused on it,
    // so the setting has to win over the focus check.
    expect(
      pollPeriodMs(ACTIVE, IDLE, { idleWhenUnfocused: false, hasFocus: false }),
    ).toBe(ACTIVE);
  });

  it("never stops polling altogether", () => {
    // Slowed, not stopped: coming back to numbers from ten minutes ago looks
    // broken, so the idle period still has to elapse and fire.
    const period = pollPeriodMs(ACTIVE, IDLE, {
      idleWhenUnfocused: true,
      hasFocus: false,
    });
    expect(Number.isFinite(period)).toBe(true);
    expect(period).toBeGreaterThan(0);
  });
});
