import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ setTab: vi.fn(), activeTab: "connect" }));
vi.mock("./settingsStore", () => ({ useSettingsStore: { getState: () => ({ setTab: h.setTab, activeTab: h.activeTab }) } }));

describe("search navigation lifetime", () => {
  let navigate: typeof import("./deepLinkStore").useDeepLinkStore;
  let query: ReturnType<typeof vi.fn>;
  const element = () => ({ isConnected: true, scrollIntoView: vi.fn(), classList: { add: vi.fn(), remove: vi.fn() } });
  beforeEach(async () => {
    vi.resetModules();
    h.activeTab = "connect";
    h.setTab.mockImplementation(tab => { h.activeTab = tab; });
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance", "Date"] });
    vi.stubGlobal("window", globalThis);
    vi.stubGlobal("CSS", { escape: (value: string) => value });
    query = vi.fn().mockReturnValue(null);
    vi.stubGlobal("document", { querySelector: query });
    navigate = (await import("./deepLinkStore")).useDeepLinkStore;
  });
  afterEach(() => {
    navigate.getState().navigateTo({ tab: "connect" });
    vi.useRealTimers(); vi.unstubAllGlobals();
  });

  it("cancels a pending scroll when a newer navigation wins", () => {
    const old = element();
    query.mockReturnValue(old);
    navigate.getState().navigateTo({ tab: "games", anchor: "old" });
    navigate.getState().navigateTo({ tab: "connect" });
    vi.advanceTimersByTime(10_000);
    expect(old.scrollIntoView).not.toHaveBeenCalled();
    expect(navigate.getState().anchor).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("retires old discovery polls instead of finding an old target later", () => {
    navigate.getState().navigateTo({ tab: "games", anchor: "missing" });
    navigate.getState().navigateTo({ tab: "connect" });
    const old = element();
    query.mockReturnValue(old);
    vi.advanceTimersByTime(10_000);
    expect(old.scrollIntoView).not.toHaveBeenCalled();
  });
  it("also cancels scrolling after a direct sidebar tab change", () => {
    const target = element();
    query.mockReturnValue(target);
    navigate.getState().navigateTo({ tab: "games", anchor: "flags" });
    h.activeTab = "overlay";
    vi.advanceTimersByTime(280);
    expect(target.scrollIntoView).not.toHaveBeenCalled();
    expect(navigate.getState().anchor).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("does not let the first flash clear a second search for the same anchor", () => {
    const target = element();
    query.mockReturnValue(target);
    navigate.getState().navigateTo({ tab: "games", anchor: "settings" });
    vi.advanceTimersByTime(1800);
    navigate.getState().navigateTo({ tab: "games", anchor: "settings" });
    vi.advanceTimersByTime(600);
    expect(navigate.getState().anchor).toBe("settings");
    expect(target.scrollIntoView).toHaveBeenCalledTimes(2);
    vi.advanceTimersByTime(1680);
    expect(navigate.getState().anchor).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("waits for a replacement when the discovered element unmounts before scrolling", () => {
    const old = element();
    query.mockReturnValue(old);
    navigate.getState().navigateTo({ tab: "games", anchor: "flags" });
    old.isConnected = false;
    query.mockReturnValue(null);
    vi.advanceTimersByTime(280);
    const current = element();
    query.mockReturnValue(current);
    vi.advanceTimersByTime(370);
    expect(old.scrollIntoView).not.toHaveBeenCalled();
    expect(current.scrollIntoView).toHaveBeenCalledOnce();
  });
  it("finishes missing-target discovery despite the Windows clock moving backwards", () => {
    navigate.getState().navigateTo({ tab: "games", anchor: "missing" });
    vi.setSystemTime(Date.now() - 3_600_000);
    vi.advanceTimersByTime(5200);
    expect(navigate.getState().anchor).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("does not clear a late-mounted target before its highlight ends", () => {
    navigate.getState().navigateTo({ tab: "games", anchor: "slow" });
    vi.advanceTimersByTime(4000);
    const target = element();
    query.mockReturnValue(target);
    vi.advanceTimersByTime(400);
    expect(target.scrollIntoView).toHaveBeenCalledOnce();
    expect(navigate.getState().anchor).toBe("slow");
    vi.advanceTimersByTime(2000);
    expect(navigate.getState().anchor).toBeNull();
  });
});
