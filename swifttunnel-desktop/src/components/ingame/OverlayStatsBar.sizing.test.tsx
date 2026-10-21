import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as (() => void | (() => void))[],
  resize: null as (() => void) | null,
  setSize: vi.fn(),
  bounds: { width: 200, height: 50 },
}));
vi.mock("react", () => ({
  useCallback: (callback: unknown) => callback,
  useRef: (current: unknown) => ({ current }),
  useState: (initial: unknown) => [initial, vi.fn()],
  useEffect: (effect: () => void | (() => void)) => h.effects.push(effect),
}));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    setSize: h.setSize,
    setPosition: async () => {},
    setIgnoreCursorEvents: async () => {},
    hide: async () => {}, show: async () => {},
    outerPosition: async () => ({ x: 0, y: 0 }),
  }),
  currentMonitor: async () => null,
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: async () => () => {} }));
import { OverlayStatsBar } from "./OverlayStatsBar";

let cleanup: (() => void)[] = [];
function mount() {
  const tree = OverlayStatsBar();
  tree.props.ref.current = { getBoundingClientRect: () => h.bounds };
  cleanup = h.effects.map(effect => effect()).filter((fn): fn is () => void => typeof fn === "function");
  expect(h.resize).not.toBeNull();
}
beforeEach(() => {
  vi.useFakeTimers();
  h.effects = []; h.resize = null; cleanup = [];
  h.bounds = { width: 200, height: 50 };
  h.setSize.mockResolvedValue(undefined);
  vi.stubGlobal("window", { devicePixelRatio: 1, setTimeout, clearTimeout, addEventListener: vi.fn(), removeEventListener: vi.fn() });
  vi.stubGlobal("ResizeObserver", class {
    constructor(callback: () => void) { h.resize = callback; }
    observe() {} disconnect() {}
  });
});
afterEach(async () => {
  cleanup.forEach(stop => stop());
  await vi.advanceTimersByTimeAsync(0);
  vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllGlobals();
});

describe("overlay window size writes", () => {
  it("keeps one native resize pending through a burst of layout notifications", async () => {
    let release!: () => void;
    const pending = new Promise<void>(resolve => { release = resolve; });
    h.setSize.mockReturnValue(pending);
    mount();
    try {
      for (let number = 0; number < 1000; number++) h.resize!();
      await vi.advanceTimersByTimeAsync(0);
      expect(h.setSize).toHaveBeenCalledOnce();
    } finally {
      release();
      await vi.advanceTimersByTimeAsync(0);
    }
    h.resize!();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.setSize).toHaveBeenCalledOnce();
  });

  it("can retry after a failed native size update", async () => {
    h.setSize.mockRejectedValueOnce(new Error("window busy"));
    mount();
    h.resize!();
    await vi.advanceTimersByTimeAsync(0);
    h.resize!();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.setSize).toHaveBeenCalledTimes(2);
  });

  it("remeasures a changed layout after the pending write completes", async () => {
    let release!: () => void;
    h.setSize.mockReturnValueOnce(new Promise<void>(resolve => { release = resolve; }));
    mount();
    h.resize!();
    await vi.advanceTimersByTimeAsync(0);
    h.bounds = { width: 300, height: 50 };
    h.resize!();
    release();
    await vi.advanceTimersByTimeAsync(0);
    // The normal sizing poll retries with current geometry, not the old one.
    h.resize!();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.setSize.mock.calls.map(([size]) => [size.width, size.height])).toEqual([[200, 50], [300, 50]]);
  });

  it("contains a synchronous SDK failure and releases the next size attempt", async () => {
    h.setSize.mockImplementationOnce(() => { throw new Error("window metadata unavailable"); });
    mount();
    expect(() => h.resize!()).not.toThrow();
    await vi.advanceTimersByTimeAsync(0);
    h.resize!();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.setSize).toHaveBeenCalledTimes(2);
  });
});
