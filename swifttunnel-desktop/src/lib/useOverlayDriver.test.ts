import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => void | (() => void)>,
  invoke: vi.fn(),
  listen: vi.fn(),
  push: vi.fn(),
  metrics: vi.fn(),
  throughput: vi.fn(),
  ping: vi.fn(),
  overlay: { enabled: true, metrics: ["ping", "upload"], size: "medium", color: "white", style: "solid", position: "top-left", custom_x: 0, custom_y: 0 },
}));

vi.mock("react", () => ({
  useEffect: (effect: () => void | (() => void)) => { h.effects.push(effect); },
  useRef: (current: unknown) => ({ current }),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: h.listen }));
vi.mock("../components/ingame/overlayBus", () => ({
  OVERLAY_POSITION_EVENT: "position",
  pushOverlayRender: h.push,
}));
vi.mock("../stores/settingsStore", () => ({
  useSettingsStore: (select: (s: unknown) => unknown) => select({
    settings: { config: { overlay: h.overlay } }, update: vi.fn(), save: vi.fn(),
  }),
}));
vi.mock("../stores/boostStore", () => ({
  useBoostStore: Object.assign(
    (select: (s: unknown) => unknown) => select({ fetchMetrics: h.metrics }),
    { getState: () => ({ robloxRunning: true, robloxForeground: true, fps: 60, ramTotal: 100, ramUsage: 50, cpuUsage: 10 }) },
  ),
}));
vi.mock("../stores/vpnStore", () => ({
  useVpnStore: Object.assign(
    (select: (s: unknown) => unknown) => select({ fetchThroughput: h.throughput, fetchPing: h.ping }),
    { getState: () => ({ state: "connected", bytesUp: 100, bytesDown: 200, ping: 30 }) },
  ),
}));

import { useOverlayDriver } from "./useOverlayDriver";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

function start() {
  useOverlayDriver();
  // Run the render effect; the position listener is unrelated to polling.
  return h.effects[0]() as () => void;
}

describe("overlay polling under slow native calls", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal("window", globalThis);
    h.effects.length = 0;
    h.overlay.enabled = true;
    h.invoke.mockResolvedValue(undefined);
    h.metrics.mockResolvedValue(undefined);
    h.throughput.mockResolvedValue(undefined);
    h.ping.mockResolvedValue(undefined);
    h.push.mockResolvedValue(undefined);
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("does not accumulate ticks while window creation is stalled", async () => {
    const pending = deferred();
    h.invoke.mockReturnValue(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(60_000);
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    const calls = h.push.mock.calls.length;
    stop();
    expect(calls).toBe(1);
  });

  it("keeps one tick pending during a slow metrics sample and resumes", async () => {
    const pending = deferred();
    h.metrics.mockReturnValueOnce(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(60_000);
    const calls = h.metrics.mock.calls.length;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    expect(calls).toBe(1);
    expect(h.push).toHaveBeenCalledTimes(2);
  });

  it.each(["metrics", "throughput", "ping"] as const)(
    "does not show the overlay after disabling it during %s",
    async (stage) => {
      const pending = deferred();
      h[stage].mockReturnValue(pending.promise);
      const stop = start();
      await vi.advanceTimersByTimeAsync(0);
      stop();
      pending.resolve();
      await vi.advanceTimersByTimeAsync(2_000);
      expect(h.push).not.toHaveBeenCalled();
      if (stage === "metrics") expect(h.throughput).not.toHaveBeenCalled();
      if (stage !== "ping") expect(h.ping).not.toHaveBeenCalled();
    },
  );

  it("also waits for render delivery before collecting another sample", async () => {
    const pending = deferred();
    h.push.mockReturnValueOnce(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(60_000);
    const calls = h.metrics.mock.calls.length;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    expect(calls).toBe(1);
    expect(h.push).toHaveBeenCalledTimes(2);
  });

  it("resumes after a failed metrics sample", async () => {
    h.metrics.mockRejectedValueOnce(new Error("sampler unavailable"));
    const stop = start();
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    expect(h.metrics).toHaveBeenCalledTimes(2);
    expect(h.push).toHaveBeenCalledTimes(2);
  });
});
