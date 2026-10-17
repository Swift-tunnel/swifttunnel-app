import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => void | (() => void)>,
  running: false,
  loaded: true,
  idleWhenUnfocused: true,
  scan: vi.fn(),
}));
vi.mock("react", () => ({
  useEffect: (effect: () => void | (() => void)) => h.effects.push(effect),
  useRef: <T,>(current: T) => ({ current }),
  useCallback: <T,>(callback: T) => callback,
}));
vi.mock("../stores/boostStore", () => {
  const state = () => ({ robloxRunning: h.running, hasLoadedMetrics: h.loaded });
  return {
    useBoostStore: Object.assign(
      (select: (s: ReturnType<typeof state>) => unknown) => select(state()),
      { getState: state },
    ),
  };
});
vi.mock("../stores/serverStore", () => ({
  useServerStore: (select: (s: { fetchLatencies: typeof h.scan }) => unknown) =>
    select({ fetchLatencies: h.scan }),
}));
vi.mock("../stores/settingsStore", () => ({
  useSettingsStore: (select: (s: unknown) => unknown) => select({
    settings: { idle_when_unfocused: h.idleWhenUnfocused },
  }),
}));

import { useRelayLatencyPolling } from "./useRelayLatencyPolling";

describe("automatic picker scans", () => {
  let events: EventTarget;
  let hasFocus: boolean;
  let cleanups: Array<() => void>;

  function stop() {
    cleanups.forEach(cleanup => cleanup());
    cleanups = [];
  }

  // Run mount effects with the real focus-aware timer. Remounting also models
  // the cleanup/restart when process state enables or disables that timer.
  function start() {
    stop();
    h.effects.length = 0;
    useRelayLatencyPolling();
    cleanups = h.effects.flatMap(effect => {
      const cleanup = effect();
      return cleanup ? [cleanup] : [];
    });
  }

  beforeEach(() => {
    vi.useFakeTimers();
    h.running = false;
    h.loaded = true;
    h.idleWhenUnfocused = true;
    h.scan.mockResolvedValue(undefined);
    cleanups = [];
    hasFocus = true;
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
    stop();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("refreshes on opening the picker and every 15 seconds while idle", () => {
    start();
    expect(h.scan).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(60_000);
    expect(h.scan).toHaveBeenCalledTimes(5);
  });

  it("waits for the first process sample instead of assuming Roblox is closed", () => {
    h.loaded = false;
    start();
    vi.advanceTimersByTime(60_000);
    events.dispatchEvent(new Event("focus"));
    expect(h.scan).not.toHaveBeenCalled();
    h.loaded = true;
    start();
    expect(h.scan).toHaveBeenCalledOnce();
  });

  it.each([true, false])("does not scan during Roblox even with idle setting %s", idle => {
    h.running = true;
    h.idleWhenUnfocused = idle;
    start();
    vi.advanceTimersByTime(5 * 60_000);
    events.dispatchEvent(new Event("focus"));
    expect(h.scan).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("guards queued timer and focus callbacks before React handles game startup", () => {
    start();
    h.scan.mockClear();
    h.running = true;
    vi.advanceTimersByTime(15_000);
    events.dispatchEvent(new Event("focus"));
    expect(h.scan).not.toHaveBeenCalled();
    start();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does one fresh round when Roblox closes, then resumes the idle cadence", () => {
    h.running = true;
    start();
    vi.advanceTimersByTime(30_000);
    h.running = false;
    start();
    expect(h.scan).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(14_999);
    expect(h.scan).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(1);
    expect(h.scan).toHaveBeenCalledTimes(2);
  });

  it("backs off out of focus and refreshes immediately when the window returns", () => {
    hasFocus = false;
    start();
    vi.advanceTimersByTime(59_999);
    expect(h.scan).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(1);
    expect(h.scan).toHaveBeenCalledTimes(2);
    hasFocus = true;
    events.dispatchEvent(new Event("focus"));
    expect(h.scan).toHaveBeenCalledTimes(3);
  });

  it("leaves no automatic work behind when the picker closes", () => {
    start();
    stop();
    h.scan.mockClear();
    vi.advanceTimersByTime(60_000);
    events.dispatchEvent(new Event("focus"));
    expect(h.scan).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
