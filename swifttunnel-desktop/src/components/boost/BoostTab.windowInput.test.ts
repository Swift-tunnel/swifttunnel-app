import { describe, expect, it } from "vitest";
import { parseWindowDimensionInput } from "./BoostTab";

describe("BoostTab window input parsing", () => {
  it("falls back to minimum width when input is empty", () => {
    expect(parseWindowDimensionInput("", 800)).toBe(800);
  });

  it("falls back to minimum height when input is non-numeric", () => {
    expect(parseWindowDimensionInput("abc", 600)).toBe(600);
  });

  it("keeps parsed numeric values", () => {
    expect(parseWindowDimensionInput("1280", 800)).toBe(1280);
  });
});
