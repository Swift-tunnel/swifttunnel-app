import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => void | (() => void)>,
  history: vi.fn(),
  fetch: vi.fn(),
  native: vi.fn(),
  live: true,
  bytesUp: 0,
  bytesDown: 0,
}));
vi.mock("react", () => ({
  useEffect: (effect: () => void | (() => void)) => h.effects.push(effect),
  useRef: (current: unknown) => ({ current }),
  useState: () => [[], h.history],
}));
vi.mock("./useLiveUpdates", () => ({ useLiveUpdates: () => h.live }));
vi.mock("./commands", () => ({ vpnGetThroughput: h.native }));
vi.mock("../stores/vpnStore", () => ({ useVpnStore: {
  getState: () => ({ fetchThroughput: h.fetch, bytesUp: h.bytesUp, bytesDown: h.bytesDown }),
} }));
import { useTrafficSamples } from "./useTrafficSamples";

let stop: (() => void) | undefined;
function start(showGraph = true) {
  useTrafficSamples(showGraph);
  stop = h.effects[0]() as () => void;
}
describe("connection traffic sampling", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date", "performance"] });
    vi.stubGlobal("window", globalThis);
    h.effects.length = 0;
    h.live = true;
    h.bytesUp = h.bytesDown = 0;
    h.fetch.mockResolvedValue(true);
    h.native.mockResolvedValue({ bytes_up: 0, bytes_down: 0 });
  });
  afterEach(() => { stop?.(); stop = undefined; vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("keeps transfer totals updating after the graph is hidden, without building graph history", async () => {
    start(false);
    await vi.advanceTimersByTimeAsync(5000);
    expect(h.fetch).toHaveBeenCalledTimes(6);
    expect(h.history).toHaveBeenCalledTimes(1);
    expect(h.history).toHaveBeenLastCalledWith([]);
  });
  it("does no background sampling for a hidden graph", async () => {
    h.live = false;
    start(false);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.fetch).not.toHaveBeenCalled();
    expect(h.native).not.toHaveBeenCalled();
  });
  it("retains at most thirty seconds of match history without updating background UI state", async () => {
    h.live = false;
    start();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.native).toHaveBeenCalledTimes(121);
    expect(h.history).toHaveBeenCalledTimes(1);
    expect(h.fetch).not.toHaveBeenCalled();
  });
  it("uses elapsed time for rates even if the Windows clock changes", async () => {
    start();
    await vi.advanceTimersByTimeAsync(0);
    h.bytesUp = 1000;
    vi.setSystemTime(Date.now() + 3_600_000);
    await vi.advanceTimersByTimeAsync(500);
    expect(h.history.mock.lastCall?.[0]).toEqual([{ t: Date.now(), up: 2000, down: 0 }]);
  });
  it("does not turn an unsuccessful read into a false sample", async () => {
    start();
    await vi.advanceTimersByTimeAsync(0);
    h.fetch.mockResolvedValue(false);
    h.bytesDown = 5000;
    await vi.advanceTimersByTimeAsync(500);
    expect(h.history).toHaveBeenCalledTimes(1);
  });
  it("bounds history and discards counter resets", async () => {
    start();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.history.mock.lastCall?.[0]).toHaveLength(60);
    h.bytesUp = 100;
    await vi.advanceTimersByTimeAsync(500);
    const count = h.history.mock.calls.length;
    h.bytesUp = 0;
    await vi.advanceTimersByTimeAsync(500);
    expect(h.history).toHaveBeenCalledTimes(count);
  });
  it("does not queue slow reads or publish a late sample after unmount", async () => {
    let resolve!: (value: boolean) => void;
    h.fetch.mockReturnValue(new Promise<boolean>(r => { resolve = r; }));
    start();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(h.fetch).toHaveBeenCalledOnce();
    stop?.(); stop = undefined;
    resolve(true);
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.history).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });
});
