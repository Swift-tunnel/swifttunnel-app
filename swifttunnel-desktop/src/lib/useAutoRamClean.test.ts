import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => (() => void)>,
  ref: { current: true },
  listen: vi.fn(), metrics: vi.fn(), clean: vi.fn(), show: vi.fn(),
  foreground: true,
}));
vi.mock("react", () => ({
  useEffect: (effect: () => (() => void)) => { h.effects.push(effect); },
  useRef: (initial: boolean) => { h.ref.current = initial; return h.ref; },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: h.listen }));
vi.mock("./commands", () => ({ boostCleanRam: h.clean }));
vi.mock("../components/overlay/RamOverlay", () => ({ showRamOverlay: h.show }));
vi.mock("../stores/settingsStore", () => ({
  useSettingsStore: (select: (state: unknown) => unknown) => select({ settings: { config: { system_optimization: { auto_ram_clean: true } } } }),
}));
vi.mock("../stores/boostStore", () => ({
  useBoostStore: Object.assign(
    (select: (state: unknown) => unknown) => select({ fetchMetrics: h.metrics }),
    { getState: () => ({ robloxForeground: h.foreground }) },
  ),
}));
import { useAutoRamClean } from "./useAutoRamClean";

async function start() {
  useAutoRamClean();
  const stop = h.effects[0]();
  await vi.advanceTimersByTimeAsync(30_000);
  return { stop, join: h.listen.mock.calls[0][1] as () => Promise<void> };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-09-18T00:00:00Z"));
  h.effects.length = 0;
  h.foreground = true;
  h.listen.mockResolvedValue(vi.fn());
  h.metrics.mockResolvedValue(true);
  h.clean.mockResolvedValue({ freed_mb: 100 });
  h.show.mockResolvedValue(undefined);
});
afterEach(() => vi.useRealTimers());

describe("automatic RAM clean guardrails", () => {
  it("rechecks the setting after delayed metrics", async () => {
    let finish!: (ok: boolean) => void;
    h.metrics.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const { stop, join } = await start();
    const pending = join();
    h.ref.current = false;
    finish(true);
    await pending;
    stop();
    expect(h.clean).not.toHaveBeenCalled();
  });

  it("does not clean using stale foreground state after a failed sample", async () => {
    h.metrics.mockResolvedValue(false);
    const { stop, join } = await start();
    await join();
    stop();
    expect(h.clean).not.toHaveBeenCalled();
  });

  it("allows a later valid join after a failed sample", async () => {
    h.metrics.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const { stop, join } = await start();
    await join();
    await join();
    stop();
    expect(h.metrics).toHaveBeenCalledTimes(2);
    expect(h.clean).toHaveBeenCalledOnce();
    expect(h.show).toHaveBeenCalledWith(100);
  });

  it("does not clean when the hook was disposed during sampling", async () => {
    let finish!: (ok: boolean) => void;
    h.metrics.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const { stop, join } = await start();
    const pending = join();
    stop();
    finish(true);
    await pending;
    expect(h.clean).not.toHaveBeenCalled();
  });
});
