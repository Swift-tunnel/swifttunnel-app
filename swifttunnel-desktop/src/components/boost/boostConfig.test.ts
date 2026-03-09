import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS } from "../../lib/settings";
import {
  getPresetConfig,
  parseWindowDimensionInput,
  validateWindowDimension,
} from "./boostConfig";

describe("boost config helpers", () => {
  it("applies the low-end preset without dropping unrelated fields", () => {
    const result = getPresetConfig("LowEnd", DEFAULT_SETTINGS.config);

    expect(result.profile).toBe("LowEnd");
    expect(result.system_optimization.power_plan).toBe("Ultimate");
    expect(result.roblox_settings.graphics_quality).toBe("Level1");
    expect(result.network_settings.gaming_qos).toBe(true);
    expect(result.auto_start_with_roblox).toBe(false);
  });

  it("validates even-numbered window dimensions within bounds", () => {
    expect(validateWindowDimension("Width", 1280, 800, 3840)).toBeNull();
    expect(validateWindowDimension("Height", 719, 600, 2160)).toContain(
      "even number",
    );
  });

  it("parses numeric dimensions and falls back for invalid input", () => {
    expect(parseWindowDimensionInput("1280", 800)).toBe(1280);
    expect(parseWindowDimensionInput("abc", 800)).toBe(800);
  });
});
