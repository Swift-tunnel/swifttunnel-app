import { beforeEach, describe, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ open: vi.fn(), toast: vi.fn() }));
vi.mock("./commands", () => ({ systemOpenUrl: h.open }));
vi.mock("../stores/toastStore", () => ({ useToastStore: { getState: () => ({ addToast: h.toast }) } }));
import { openSystemLink } from "./openSystemLink";
beforeEach(() => { h.open.mockReset(); h.toast.mockReset(); });
describe("system links", () => {
  it("shows the native failure without rejecting an unattended click", async () => {
    h.open.mockRejectedValue({ message: "Check your default browser." });
    await expect(openSystemLink("https://example.test")).resolves.toBeUndefined();
    expect(h.toast).toHaveBeenCalledWith({ type: "error", message: "Check your default browser." });
  });
  it("opens a local folder without reporting a failure", async () => {
    h.open.mockResolvedValue(undefined);
    await openSystemLink("C:/Downloads");
    expect(h.open).toHaveBeenCalledWith("C:/Downloads");
    expect(h.toast).not.toHaveBeenCalled();
  });
});
