import { describe, expect, it } from "vitest";
import { overlayMayInteract, overlayShouldShow, type OverlayRenderPayload } from "./overlayBus";

const payload: OverlayRenderPayload = {
  enabled: true, forceHide: false, metrics: ["fps"], size: "small",
  color: "white", style: "straight", position: "top-left",
  customX: null, customY: null, values: {},
  locked: false,
};

describe("overlay visibility", () => {
  it("explicit disable hides a hovered or dragged bar and disallows further interaction", () => {
    const disabled = { ...payload, enabled: false, forceHide: true };
    expect(overlayShouldShow(disabled, true)).toBe(false);
    expect(overlayMayInteract(disabled)).toBe(false);
  });

  it("keeps a drag through foreground loss but hides when interaction ends", () => {
    const background = { ...payload, enabled: false };
    expect(overlayShouldShow(background, true)).toBe(true);
    expect(overlayShouldShow(background, false)).toBe(false);
  });

  it("does not keep an empty or uninitialized overlay interactive", () => {
    expect(overlayShouldShow(null, true)).toBe(false);
    expect(overlayShouldShow({ ...payload, metrics: [] }, true)).toBe(false);
    expect(overlayMayInteract({ ...payload, metrics: [] })).toBe(false);
  });
  it("a locked overlay stays visible without intercepting clicks or holding visibility after alt-tab", () => {
    const locked = {...payload,locked:true};
    expect(overlayShouldShow(locked,false)).toBe(true);
    expect(overlayMayInteract(locked)).toBe(false);
    expect(overlayShouldShow({...locked,enabled:false},true)).toBe(false);
    expect(overlayMayInteract({...payload,locked:undefined})).toBe(false);
  });
});
