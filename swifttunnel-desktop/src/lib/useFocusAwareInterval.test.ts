import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => (() => void) | undefined>,
  idleWhenUnfocused: true,
}));
vi.mock("react", () => ({
  useEffect: (effect: () => (() => void) | undefined) => h.effects.push(effect),
  useRef: <T,>(current: T) => ({ current }),
}));
vi.mock("../stores/settingsStore", () => ({
  useSettingsStore: (select: (state: unknown) => unknown) => select({
    settings: { idle_when_unfocused: h.idleWhenUnfocused },
  }),
}));
import { pollPeriodMs, useFocusAwareInterval } from "./useFocusAwareInterval";

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

describe("focus-aware polling lifecycle", () => {
  let hasFocus: boolean;
  let events: EventTarget;
  let stop: (() => void) | undefined;

  beforeEach(() => {
    vi.useFakeTimers();
    h.effects.length = 0;
    h.idleWhenUnfocused = true;
    hasFocus = false;
    events = new EventTarget();
    vi.stubGlobal("document", { hasFocus: () => hasFocus });
    vi.stubGlobal("window", {
      setTimeout: (callback: () => void, delay: number) => setTimeout(callback, delay),
      clearTimeout: (id: number) => clearTimeout(id),
      addEventListener: events.addEventListener.bind(events),
      removeEventListener: events.removeEventListener.bind(events),
    });
  });

  afterEach(() => {
    stop?.();
    stop = undefined;
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  function start(activeMs = 1000, enabled = true) {
    const poll = vi.fn();
    useFocusAwareInterval(poll, activeMs, { enabled });
    stop = h.effects[0]();
    return poll;
  }

  it("limits a one-second display poll to four ticks per idle minute", () => {
    const poll = start();
    vi.advanceTimersByTime(60_000);
    expect(poll).toHaveBeenCalledTimes(4);
  });

  it("catches up on focus and replaces the pending idle timer", () => {
    const poll = start();
    vi.advanceTimersByTime(5000);
    expect(poll).not.toHaveBeenCalled();
    hasFocus = true;
    events.dispatchEvent(new Event("focus"));
    expect(poll).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(10_000);
    expect(poll).toHaveBeenCalledTimes(11);
    hasFocus = false;
    // The already scheduled active tick can run, then it must slow down.
    vi.advanceTimersByTime(1000);
    poll.mockClear();
    vi.advanceTimersByTime(60_000);
    expect(poll).toHaveBeenCalledTimes(4);
  });

  it("keeps the requested cadence when idle polling is disabled", () => {
    h.idleWhenUnfocused = false;
    const poll = start();
    vi.advanceTimersByTime(60_000);
    expect(poll).toHaveBeenCalledTimes(60);
  });

  it("retires both the timer and focus listener on unmount", () => {
    const poll = start();
    stop?.();
    vi.advanceTimersByTime(60_000);
    events.dispatchEvent(new Event("focus"));
    expect(poll).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not poll or react to focus while disabled", () => {
    const poll = start(1000, false);
    vi.advanceTimersByTime(60_000);
    events.dispatchEvent(new Event("focus"));
    expect(poll).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
