import { describe, expect, it } from "vitest";
import {
  MIN_WINDOW_HEIGHT,
  MIN_WINDOW_WIDTH,
  ensureWindowStateVisible,
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

  it("re-centers the window when the titlebar is off-screen", () => {
    const adjusted = ensureWindowStateVisible(
      {
        x: 3500,
        y: 2200,
        width: 1280,
        height: 840,
        maximized: false,
      },
      [{ x: 0, y: 0, width: 1920, height: 1080 }],
    );

    expect(adjusted.x).toBe(320);
    expect(adjusted.y).toBe(120);
  });

  it("keeps the position when any part of the titlebar is visible", () => {
    const adjusted = ensureWindowStateVisible(
      {
        x: -500,
        y: 100,
        width: 1280,
        height: 840,
        maximized: false,
      },
      [{ x: 0, y: 0, width: 1920, height: 1080 }],
    );

    expect(adjusted.x).toBe(-500);
    expect(adjusted.y).toBe(100);
  });

  it("prefers the primary monitor when relocating", () => {
    const adjusted = ensureWindowStateVisible(
      {
        x: 9000,
        y: 9000,
        width: 1280,
        height: 840,
        maximized: false,
      },
      [
        { x: 0, y: 0, width: 1920, height: 1080 },
        { x: 1920, y: 0, width: 1920, height: 1080 },
      ],
      { primaryMonitor: { x: 1920, y: 0, width: 1920, height: 1080 } },
    );

    expect(adjusted.x).toBe(2240);
    expect(adjusted.y).toBe(120);
  });
});
