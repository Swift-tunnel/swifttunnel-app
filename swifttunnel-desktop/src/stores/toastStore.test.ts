import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

async function loadStore() {
  vi.resetModules();
  return (await import("./toastStore")).useToastStore;
}

describe("stores/toastStore", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("auto-dismisses toasts after the timeout", async () => {
    const useToastStore = await loadStore();

    useToastStore
      .getState()
      .addToast({ type: "success", message: "Saved" });

    expect(useToastStore.getState().toasts).toHaveLength(1);

    vi.advanceTimersByTime(4000);

    expect(useToastStore.getState().toasts).toHaveLength(0);
  });

  it("clears the auto-dismiss timer when a toast is manually removed", async () => {
    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout");
    const useToastStore = await loadStore();

    useToastStore
      .getState()
      .addToast({ type: "warning", message: "Dismiss me" });
    const [toast] = useToastStore.getState().toasts;

    useToastStore.getState().removeToast(toast.id);

    expect(clearTimeoutSpy).toHaveBeenCalledTimes(1);
    expect(useToastStore.getState().toasts).toHaveLength(0);

    vi.advanceTimersByTime(4000);

    expect(useToastStore.getState().toasts).toHaveLength(0);
  });
});
