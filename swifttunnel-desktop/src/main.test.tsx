import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  label: "main", failMain: false, failOverlay: false,
  mainLoads: 0, overlayLoads: 0,
  prepare: vi.fn(), render: vi.fn(), hide: vi.fn(), createRoot: vi.fn(),
  main: () => null, overlay: () => null,
}));
vi.mock("react-dom/client", () => ({ default: { createRoot: h.createRoot } }));
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => ({ label: h.label, hide: h.hide }) }));
vi.mock("./lib/webviewLockdown", () => ({ shouldLockDown: () => false, installWebviewLockdown: vi.fn() }));
vi.mock("./styles/globals.css", () => ({}));

beforeEach(() => {
  vi.resetModules();
  h.label = "main"; h.failMain = false; h.failOverlay = false;
  h.mainLoads = 0; h.overlayLoads = 0;
  h.createRoot.mockReturnValue({ render: h.render });
  h.hide.mockResolvedValue(undefined);
  vi.stubGlobal("window", { location: { search: "" } });
  vi.stubGlobal("document", {
    documentElement: { style: {} }, body: { style: {} },
    getElementById: () => ({ style: {} }),
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.doMock("./MainWindow", () => {
    h.mainLoads++;
    if (h.failMain) throw new Error("main chunk unavailable");
    return { MainWindow: h.main, prepareMainWindow: h.prepare };
  });
  vi.doMock("./components/ingame/OverlayStatsBar", () => {
    h.overlayLoads++;
    if (h.failOverlay) throw new Error("overlay chunk unavailable");
    return { OverlayStatsBar: h.overlay };
  });
});
afterEach(() => { vi.unstubAllGlobals(); });

describe("window entry loading", () => {
  it("loads and prepares the main UI without importing the overlay", async () => {
    await import("./main");
    await vi.waitFor(() => expect(h.render).toHaveBeenCalled());
    expect(h.mainLoads).toBe(1);
    expect(h.prepare).toHaveBeenCalledOnce();
    expect(h.overlayLoads).toBe(0);
    expect(h.render.mock.calls[0][0].props.children.type).toBe(h.main);
  });

  it("loads only the overlay without starting main-window services", async () => {
    h.label = "overlay-stats";
    await import("./main");
    await vi.waitFor(() => expect(h.render).toHaveBeenCalled());
    expect(h.overlayLoads).toBe(1);
    expect(h.mainLoads).toBe(0);
    expect(h.prepare).not.toHaveBeenCalled();
    expect(h.render.mock.calls[0][0].props.children.type).toBe(h.overlay);
    expect(document.documentElement.style.background).toBe("transparent");
  });

  it("shows a readable recovery message when the main chunk cannot load", async () => {
    h.failMain = true;
    await import("./main");
    await vi.waitFor(() => expect(h.render).toHaveBeenCalled());
    expect(h.prepare).not.toHaveBeenCalled();
    expect(h.render.mock.calls[0][0].props.role).toBe("alert");
    expect(h.render.mock.calls[0][0].props.children).toContain("Close the app and try again");
  });

  it("hides a failed overlay instead of leaving a broken window above the game", async () => {
    h.label = "overlay-stats"; h.failOverlay = true;
    await import("./main");
    await vi.waitFor(() => expect(h.hide).toHaveBeenCalledOnce());
    expect(h.render).not.toHaveBeenCalled();
    expect(h.mainLoads).toBe(0);
  });
});
