import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

async function loadStore() {
  vi.resetModules();
  return (await import("./toastStore")).useToastStore;
}

describe("toast lifecycle", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

  it("bounds both visible notifications and timers during a burst", async () => {
    const store = await loadStore();
    for (let i = 0; i < 1000; i++) {
      store.getState().addToast({ type: "info", message: `Notice ${i}` });
    }
    expect(store.getState().toasts.map(toast => toast.message)).toEqual([
      "Notice 996", "Notice 997", "Notice 998", "Notice 999",
    ]);
    expect(vi.getTimerCount()).toBe(4);
    vi.advanceTimersByTime(4000);
    expect(store.getState().toasts).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("extends a repeated notice without duplicate cards or repeated renders", async () => {
    const store = await loadStore();
    const render = vi.fn();
    const unsubscribe = store.subscribe(render);
    const toast = { type: "warning" as const, message: "Connection unavailable" };
    store.getState().addToast(toast);
    vi.advanceTimersByTime(3000);
    for (let i = 0; i < 1000; i++) store.getState().addToast(toast);
    expect(store.getState().toasts).toHaveLength(1);
    expect(render).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(1);
    vi.advanceTimersByTime(1000);
    expect(store.getState().toasts).toHaveLength(1);
    vi.advanceTimersByTime(3000);
    expect(store.getState().toasts).toEqual([]);
    unsubscribe();
  });

  it("cancels expiry on dismissal and ignores a second dismissal", async () => {
    const store = await loadStore();
    store.getState().addToast({ type: "success", message: "Saved" });
    const id = store.getState().toasts[0].id;
    store.getState().removeToast(id);
    expect(vi.getTimerCount()).toBe(0);
    const render = vi.fn();
    const unsubscribe = store.subscribe(render);
    store.getState().removeToast(id);
    vi.advanceTimersByTime(4000);
    expect(render).not.toHaveBeenCalled();
    unsubscribe();
  });

  it("keeps different actions and severities separate", async () => {
    const store = await loadStore();
    const first = vi.fn();
    const second = vi.fn();
    store.getState().addToast({ type: "info", message: "Review", action: { label: "Open", onClick: first } });
    store.getState().addToast({ type: "info", message: "Review", action: { label: "Open", onClick: second } });
    store.getState().addToast({ type: "error", message: "Review" });
    expect(store.getState().toasts).toHaveLength(3);
    store.getState().toasts[1].action?.onClick();
    expect(second).toHaveBeenCalledOnce();
    expect(first).not.toHaveBeenCalled();
  });
});
