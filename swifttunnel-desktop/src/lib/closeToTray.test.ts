import { describe, expect, it, vi } from "vitest";
import { createCloseToTrayHandler } from "./closeToTray";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("createCloseToTrayHandler", () => {
  it("prevents close synchronously and hides to tray when minimize_to_tray is enabled", async () => {
    const preventDefault = vi.fn();
    const persistGate = deferred<void>();
    const hide = vi.fn(async () => {});
    const close = vi.fn(async () => {});

    const handler = createCloseToTrayHandler({
      persistWindowState: () => persistGate.promise,
      hide,
      close,
      shouldMinimizeToTray: () => true,
    });

    const p = handler({ preventDefault });

    // Before any awaits resolve, preventDefault must already have been called.
    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(hide).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();

    persistGate.resolve();
    await p;

    expect(hide).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();
  });

  it("closes the app when minimize_to_tray is disabled", async () => {
    const preventDefault = vi.fn();
    const persistWindowState = vi.fn(async () => {});
    const hide = vi.fn(async () => {});
    const close = vi.fn(async () => {});

    const handler = createCloseToTrayHandler({
      persistWindowState,
      hide,
      close,
      shouldMinimizeToTray: () => false,
    });

    await handler({ preventDefault });

    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(persistWindowState).toHaveBeenCalledTimes(1);
    expect(hide).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("falls back to a real close if hide fails (without recursion)", async () => {
    const preventDefault = vi.fn();
    const persistWindowState = vi.fn(async () => {});

    const hide = vi.fn(async () => {
      throw new Error("hide failed");
    });

    let handler: ReturnType<typeof createCloseToTrayHandler> | null = null;
    const close = vi.fn(async () => {
      // Simulate Tauri triggering onCloseRequested again from programmatic close.
      await handler?.({ preventDefault });
    });

    handler = createCloseToTrayHandler({
      persistWindowState,
      hide,
      close,
      shouldMinimizeToTray: () => true,
    });

    await handler({ preventDefault });

    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(persistWindowState).toHaveBeenCalledTimes(1);
    expect(hide).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
  });
});
