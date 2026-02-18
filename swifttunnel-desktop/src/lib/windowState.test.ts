import { describe, expect, it } from "vitest";
import {
  MIN_WINDOW_HEIGHT,
  MIN_WINDOW_WIDTH,
  isPersistableWindowSize,
  normalizeWindowState,
} from "./windowState";

describe("windowState", () => {
  it("normalizes tiny and invalid persisted dimensions", () => {
    const normalized = normalizeWindowState({
      x: Number.NaN,
      y: Number.POSITIVE_INFINITY,
      width: 140,
      height: 80,
      maximized: false,
    });

    expect(normalized.x).toBeNull();
    expect(normalized.y).toBeNull();
    expect(normalized.width).toBe(MIN_WINDOW_WIDTH);
    expect(normalized.height).toBe(MIN_WINDOW_HEIGHT);
  });

  it("preserves valid persisted window state", () => {
    const normalized = normalizeWindowState({
      x: 200,
      y: 100,
      width: 1280,
      height: 840,
      maximized: true,
    });

    expect(normalized).toEqual({
      x: 200,
      y: 100,
      width: 1280,
      height: 840,
      maximized: true,
    });
  });

  it("treats minimized-like dimensions as non-persistable", () => {
    expect(isPersistableWindowSize(160, 42)).toBe(false);
    expect(isPersistableWindowSize(Number.NaN, 900)).toBe(false);
    expect(isPersistableWindowSize(1200, 800)).toBe(true);
  });
});
