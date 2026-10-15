import { describe, expect, it } from "vitest";
import {
  clampOverlayPosition,
  overlayAnchor,
  overlayHeartbeatExpired,
  validOverlayMonitor,
} from "./overlayGeometry";
const monitor = { x: -2560, y: 0, w: 2560, h: 1440, scale: 1.5 };
describe("overlay screen placement", () => {
  it("anchors correctly on a screen with a negative origin and applies its scale", () => {
    expect(
      overlayAnchor(monitor, { w: 400, h: 50 }, "top-right", null, null),
    ).toEqual({ x: -433, y: 33 });
    expect(
      overlayAnchor(monitor, { w: 400, h: 50 }, "bottom-left", null, null),
    ).toEqual({ x: -2527, y: 1357 });
  });
  it("keeps dragged and old custom positions on the current screen", () => {
    expect(
      clampOverlayPosition(monitor, { w: 400, h: 50 }, 1000, -100),
    ).toEqual({ x: -400, y: 0 });
    expect(
      overlayAnchor(monitor, { w: 400, h: 50 }, "center", 10000, 10000),
    ).toEqual({ x: -400, y: 1390 });
    expect(clampOverlayPosition(monitor, { w: 4000, h: 2000 }, 0, 0)).toEqual({
      x: -2560,
      y: 0,
    });
  });
  it("rejects unusable screens and hides after updates stop", () => {
    expect(validOverlayMonitor(monitor)).toBe(true);
    expect(validOverlayMonitor({ ...monitor, scale: 0 })).toBe(false);
    expect(validOverlayMonitor({ ...monitor, x: NaN })).toBe(false);
    expect(overlayHeartbeatExpired(1000, 5500)).toBe(false);
    expect(overlayHeartbeatExpired(1000, 5501)).toBe(true);
    expect(overlayHeartbeatExpired(null, 10000)).toBe(false);
    expect(overlayHeartbeatExpired(0, 4501)).toBe(true);
  });
});
