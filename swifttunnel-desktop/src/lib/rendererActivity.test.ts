import { describe, expect, it } from "vitest";
import {
  computeRendererActive,
  type RendererActivitySnapshot,
} from "./rendererActivity";

const base: RendererActivitySnapshot = {
  documentVisible: true,
  windowVisible: true,
  windowMinimized: false,
  windowFocused: true,
};

describe("computeRendererActive", () => {
  it("keeps renderer work active for a visible but unfocused window", () => {
    expect(computeRendererActive({ ...base, windowFocused: false })).toBe(true);
  });

  it("pauses renderer work when the document is hidden", () => {
    expect(computeRendererActive({ ...base, documentVisible: false })).toBe(
      false,
    );
  });

  it("pauses renderer work when the Tauri window is hidden to tray", () => {
    expect(computeRendererActive({ ...base, windowVisible: false })).toBe(
      false,
    );
  });

  it("pauses renderer work for minimized windows", () => {
    expect(computeRendererActive({ ...base, windowMinimized: true })).toBe(
      false,
    );
  });
});
