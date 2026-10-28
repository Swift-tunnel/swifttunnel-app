import { describe, expect, it, vi } from "vitest";
import { createWindowStateSaver } from "./windowStateSaver";
import type { WindowState } from "./types";

const old: WindowState = { x: 10, y: 20, width: 1000, height: 700, maximized: false };
const latest: WindowState = { ...old, x: 300, width: 1200 };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
describe("window state persistence", () => {
  it("bounds pending geometry reads and never saves an obsolete snapshot after a newer movement", async () => {
    const first = deferred<WindowState>();
    const read = vi.fn().mockReturnValueOnce(first.promise).mockResolvedValue(latest);
    const persist = vi.fn().mockResolvedValue(undefined);
    const saver = createWindowStateSaver({ read, persist, onError: vi.fn() });
    const initial = saver.save();
    await Promise.resolve();
    for (let event = 0; event < 100; event++) {
      saver.invalidate();
      void saver.save();
    }
    expect(read).toHaveBeenCalledOnce();
    first.resolve(old);
    await initial;
    expect(read).toHaveBeenCalledTimes(2);
    expect(persist.mock.calls.map(([value]) => value)).toEqual([latest]);
  });

  it("invalidates a pending read immediately without bypassing the caller's debounce", async () => {
    const pending = deferred<WindowState>();
    const persist = vi.fn();
    const read = vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(latest);
    const saver = createWindowStateSaver({ read, persist, onError: vi.fn() });
    const saving = saver.save();
    await Promise.resolve();
    saver.invalidate();
    pending.resolve(old);
    await saving;
    expect(persist).not.toHaveBeenCalled();
    expect(read).toHaveBeenCalledOnce();
    await saver.save();
    expect(persist).toHaveBeenCalledWith(latest);
  });

  it("serializes writes, retries after failure and ignores reads finishing after disposal", async () => {
    const firstWrite = deferred<void>();
    const read = vi.fn().mockResolvedValue(old);
    const persist = vi.fn().mockReturnValueOnce(firstWrite.promise).mockRejectedValueOnce(new Error("disk busy")).mockResolvedValue(undefined);
    const report = vi.fn();
    const saver = createWindowStateSaver({ read, persist, onError: report });
    const saving = saver.save();
    await Promise.resolve(); await Promise.resolve();
    saver.invalidate();
    void saver.save();
    expect(read).toHaveBeenCalledOnce();
    firstWrite.resolve();
    await saving;
    expect(report).toHaveBeenCalledOnce();
    await saver.save();
    expect(persist).toHaveBeenCalledTimes(3);
    const last = deferred<WindowState>();
    read.mockReturnValueOnce(last.promise);
    const closing = saver.save();
    await Promise.resolve();
    saver.dispose();
    last.resolve(latest);
    await closing;
    await saver.save();
    expect(persist).toHaveBeenCalledTimes(3);
  });
});
