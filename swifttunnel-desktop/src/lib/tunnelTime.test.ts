import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ settings: { total_tunneled_ms: 0 }, save: vi.fn(), update: vi.fn() }));
vi.mock("../stores/settingsStore", () => ({ useSettingsStore: { getState: () => ({ settings: h.settings,
  save: h.save, update: (partial: Partial<typeof h.settings>) => { Object.assign(h.settings, partial); h.update(partial); } }) } }));
import { addTunneledMs, createTunnelTimeTracker } from "./tunnelTime";

beforeEach(() => {
  h.settings.total_tunneled_ms = 0;
  h.save.mockReset().mockResolvedValue(undefined);
  h.update.mockReset();
});

afterEach(() => vi.unstubAllGlobals());

describe("tunnel time", () => {
  it("counts only connected portions, including a disconnect before the next tick", () => {
    let now = 0;
    const add = vi.fn();
    const tracker = createTunnelTimeTracker(false, add, () => now);
    now = 50_000; tracker.setConnected(true);
    now = 60_000; tracker.flush();
    now = 65_000; tracker.setConnected(false);
    now = 120_000; tracker.flush();
    expect(add.mock.calls.map(call => call[0])).toEqual([10_000, 5_000]);
  });

  it("ignores repeated connection snapshots and counts consecutive intervals once", () => {
    let now = 0;
    const add = vi.fn();
    const tracker = createTunnelTimeTracker(true, add, () => now);
    now = 20; tracker.setConnected(true);
    now = 60; tracker.flush();
    now = 75; tracker.flush();
    expect(add.mock.calls.map(call => call[0])).toEqual([60, 15]);
  });

  function storage(initial: string) {
    let value: string | null = initial;
    const removeItem = vi.fn(() => { value = null; });
    vi.stubGlobal("localStorage", { getItem: () => value, removeItem });
    return { removeItem, value: () => value };
  }

  it("preserves the legacy counter when disk persistence fails", async () => {
    const old = storage("1000");
    h.save.mockRejectedValue(new Error("Disk full"));
    addTunneledMs(50);
    await Promise.resolve(); await Promise.resolve();
    expect(old.value()).toBe("1000");
    expect(old.removeItem).not.toHaveBeenCalled();
  });

  it("removes migrated storage only after save succeeds", async () => {
    const old = storage("1000");
    let finish!: () => void;
    h.save.mockReturnValue(new Promise<void>(resolve => { finish = resolve; }));
    addTunneledMs(50.8);
    expect(h.settings.total_tunneled_ms).toBe(1050);
    expect(old.removeItem).not.toHaveBeenCalled();
    finish(); await Promise.resolve();
    expect(old.removeItem).toHaveBeenCalledOnce();
  });

  it("refuses invalid time values instead of saving non-JSON numbers", () => {
    addTunneledMs(Infinity); addTunneledMs(NaN); addTunneledMs(-1);
    expect(h.save).not.toHaveBeenCalled();
  });
});
