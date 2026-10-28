import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OverlayRenderPayload } from "./overlayBus";

const h = vi.hoisted(() => ({
  effects: [] as (() => void | (() => void))[],
  render: null as ((event: { payload: OverlayRenderPayload }) => Promise<void>) | null,
  cursor: vi.fn(),
  ignore: vi.fn(),
  move: vi.fn(),
  save: vi.fn(),
  report: vi.fn(),
  listenError: null as Error | null,
  payload: null as OverlayRenderPayload | null,
}));
vi.mock("react", () => ({
  useCallback: (callback: unknown) => callback,
  useRef: (current: unknown) => ({ current }),
  useState: (initial: unknown) => [initial === null ? h.payload : initial, vi.fn()],
  useEffect: (effect: () => void | (() => void)) => h.effects.push(effect),
}));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    setSize: async () => {}, setPosition: h.move,
    setIgnoreCursorEvents: h.ignore,
    hide: async () => {}, show: async () => {},
    outerPosition: async () => ({ x: 100, y: 100 }),
  }),
  currentMonitor: async () => null,
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: async (_name: string, callback: typeof h.render) => {
    if (h.listenError) throw h.listenError;
    h.render = callback;
    return () => {};
  },
  emitTo: h.save,
}));
vi.mock("../../lib/commands", () => ({ boostCursorPos: h.cursor }));
vi.mock("../../lib/errors", () => ({ reportError: h.report }));
import { OverlayStatsBar } from "./OverlayStatsBar";

let cleanup: (() => void)[] = [];
function attachBounds(node: any) {
  if (!node || typeof node !== "object") return;
  if (node.props?.ref) node.props.ref.current = {
    getBoundingClientRect: () => ({ width: 200, height: 50, left: 0, top: 0, right: 200, bottom: 50 }),
  };
  const children = node.props?.children;
  (Array.isArray(children) ? children : [children]).forEach(attachBounds);
}
async function mountAndDrag() {
  const tree = OverlayStatsBar();
  attachBounds(tree);
  cleanup = h.effects.map(effect => effect()).filter((stop): stop is () => void => typeof stop === "function");
  await vi.advanceTimersByTimeAsync(0);
  await h.render!({ payload: h.payload! });
  h.cursor.mockResolvedValue({ x: 125, y: 120, left_down: false });
  await vi.advanceTimersByTimeAsync(1000);
  h.cursor.mockResolvedValue({ x: 125, y: 120, left_down: true });
  await vi.advanceTimersByTimeAsync(350);
  expect(h.ignore).toHaveBeenLastCalledWith(false);
  h.move.mockClear();
}
beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
  h.effects = []; h.render = null; cleanup = []; h.listenError = null;
  h.ignore.mockResolvedValue(undefined);
  h.move.mockResolvedValue(undefined);
  h.save.mockResolvedValue(undefined);
  h.payload = {
    enabled: true, forceHide: false, metrics: ["fps"], values: {},
    size: "small", color: "white", style: "straight", position: "top-left",
    customX: 100, customY: 100, locked: false,
    monitor: { x: 0, y: 0, w: 1000, h: 800, scale: 1 },
  };
  vi.stubGlobal("window", { devicePixelRatio: 1, setTimeout, clearTimeout, addEventListener: vi.fn(), removeEventListener: vi.fn() });
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
});
afterEach(async () => {
  cleanup.forEach(stop => stop());
  await vi.advanceTimersByTimeAsync(0);
  vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllGlobals();
});

describe("overlay cursor availability", () => {
  it("cancels a drag and releases clicks on a failed cursor read, without saving a false position", async () => {
    await mountAndDrag();
    h.cursor.mockRejectedValueOnce(new Error("cursor is on another desktop"));
    await vi.advanceTimersByTimeAsync(16);
    expect(h.ignore).toHaveBeenLastCalledWith(true);
    expect(h.move).not.toHaveBeenCalled();
    expect(h.save).not.toHaveBeenCalled();

    // A button held through the failure must not restart the interrupted drag.
    h.cursor.mockResolvedValue({ x: 900, y: 700, left_down: true });
    await vi.advanceTimersByTimeAsync(350);
    expect(h.move).not.toHaveBeenCalled();
    expect(h.ignore).toHaveBeenLastCalledWith(true);
    h.cursor.mockResolvedValue({ x: 125, y: 120, left_down: false });
    await vi.advanceTimersByTimeAsync(350);
    h.cursor.mockResolvedValue({ x: 125, y: 120, left_down: true });
    await vi.advanceTimersByTimeAsync(350);
    h.cursor.mockResolvedValue({ x: 150, y: 140, left_down: false });
    await vi.advanceTimersByTimeAsync(16);
    expect(h.move).toHaveBeenLastCalledWith(expect.objectContaining({ x: 125, y: 120 }));
    expect(h.save).toHaveBeenCalledOnce();
  });

  it("accepts a genuine screen origin rather than treating zero coordinates as unavailable", async () => {
    await mountAndDrag();
    h.cursor.mockResolvedValue({ x: 0, y: 0, left_down: false });
    await vi.advanceTimersByTimeAsync(16);
    expect(h.move).toHaveBeenLastCalledWith(expect.objectContaining({ x: 0, y: 0 }));
    expect(h.save).toHaveBeenLastCalledWith("main", "overlay-position", { x: 0, y: 0 });
  });

  it("contains a failed position delivery and allows another drag to save", async () => {
    await mountAndDrag();
    const failure = new Error("main window is busy");
    h.save.mockRejectedValueOnce(failure);
    h.cursor.mockResolvedValue({ x: 150, y: 140, left_down: false });
    await vi.advanceTimersByTimeAsync(16);
    expect(h.report).toHaveBeenCalledWith(
      expect.stringContaining("Drag the bar again to retry"), failure,
      { dedupeKey: "overlay-position" },
    );
    await vi.advanceTimersByTimeAsync(350);
    h.cursor.mockResolvedValue({ x: 150, y: 140, left_down: true });
    await vi.advanceTimersByTimeAsync(350);
    h.cursor.mockResolvedValue({ x: 180, y: 160, left_down: false });
    await vi.advanceTimersByTimeAsync(16);
    expect(h.save).toHaveBeenCalledTimes(2);
  });

  it("contains failed event registration and reports a next step", async () => {
    const failure = new Error("event bridge unavailable");
    h.listenError = failure;
    const tree = OverlayStatsBar();
    attachBounds(tree);
    cleanup = h.effects.map(effect => effect()).filter((stop): stop is () => void => typeof stop === "function");
    await vi.advanceTimersByTimeAsync(0);
    expect(h.report).toHaveBeenCalledWith(
      expect.stringContaining("Restart SwiftTunnel to retry"), failure,
      { dedupeKey: "overlay-render-listener" },
    );
  });
});
