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
    // Saving settings can wait behind a connection operation. The window
    // should already be hidden while that save is pending.
    expect(hide).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();

    persistGate.resolve();
    await p;

    expect(hide).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();
  });

  it("defaults to hide-to-tray when no minimize preference callback is provided", async () => {
    const preventDefault = vi.fn();
    const persistWindowState = vi.fn(async () => {});
    const hide = vi.fn(async () => {});
    const close = vi.fn(async () => {});

    const handler = createCloseToTrayHandler({
      persistWindowState,
      hide,
      close,
    });

    await handler({ preventDefault });

    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(persistWindowState).toHaveBeenCalledTimes(1);
    expect(hide).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();
  });

  it("coalesces repeated close requests while the tray save is pending", async () => {
    const persistGate = deferred<void>();
    const persistWindowState = vi.fn(() => persistGate.promise);
    const hide = vi.fn(async () => {});
    const close = vi.fn(async () => {});
    const preventDefault = vi.fn();
    const handler = createCloseToTrayHandler({ persistWindowState, hide, close });
    const first = handler({ preventDefault });
    await handler({ preventDefault });
    expect(preventDefault).toHaveBeenCalledTimes(2);
    expect(hide).toHaveBeenCalledTimes(1);
    expect(persistWindowState).toHaveBeenCalledTimes(1);
    await first;
    // Reopening the tray window must not disable X while the old save is
    // still pending. Hide again without queuing another settings operation.
    await handler({ preventDefault });
    expect(hide).toHaveBeenCalledTimes(2);
    expect(persistWindowState).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();
    persistGate.resolve();
  });

  it("still hides when persisting geometry fails", async () => {
    const hide = vi.fn(async () => {});
    const close = vi.fn(async () => {});
    const handler = createCloseToTrayHandler({
      persistWindowState: async () => { throw new Error("save failed"); },
      hide,
      close,
    });
    await handler({ preventDefault: vi.fn() });
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

  it("waits for persistence before a real exit", async () => {
    const persistGate = deferred<void>();
    const close = vi.fn(async () => {});
    const handler = createCloseToTrayHandler({
      persistWindowState: () => persistGate.promise,
      hide: vi.fn(async () => {}),
      close,
      shouldMinimizeToTray: () => false,
    });
    const pending = handler({ preventDefault: vi.fn() });
    expect(close).not.toHaveBeenCalled();
    persistGate.resolve();
    await pending;
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("allows retry after a failed real close", async () => {
    const close = vi.fn().mockRejectedValueOnce(new Error("close failed")).mockResolvedValue(undefined);
    const handler = createCloseToTrayHandler({
      persistWindowState: async () => {},
      hide: async () => {},
      close,
      shouldMinimizeToTray: () => false,
    });
    const preventDefault = vi.fn();
    await handler({ preventDefault });
    await handler({ preventDefault });
    expect(preventDefault).toHaveBeenCalledTimes(2);
    expect(close).toHaveBeenCalledTimes(2);
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
