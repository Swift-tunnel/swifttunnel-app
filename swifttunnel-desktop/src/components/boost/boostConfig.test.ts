import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS } from "../../lib/settings";
import {
  getPresetConfig,
  rememberedPowerPlanForSwiftTunnel,
  nextPowerPlanForSwiftTunnelToggle,
  parseWindowDimensionInput,
  previousNonSwiftTunnelPowerPlan,
  validateWindowDimension,
} from "./boostConfig";

describe("boost config helpers", () => {
  it("applies the low-end preset without dropping unrelated fields", () => {
    const result = getPresetConfig("LowEnd", DEFAULT_SETTINGS.config);

    expect(result.profile).toBe("LowEnd");
    expect(result.system_optimization.power_plan).toBe("SwiftTunnel");
    expect(result.system_optimization.previous_power_plan).toBe("Balanced");
    expect(result.roblox_settings.graphics_quality).toBe("Level1");
    expect(result.network_settings.enable_network_boost).toBe(true);
    expect(result.network_settings.disable_nagle).toBe(true);
    expect(result.network_settings.disable_network_throttling).toBe(true);
    expect(result.auto_start_with_roblox).toBe(false);
  });

  it("never lowers the frame cap when a preset is chosen", () => {
    // Presets used to write fixed caps: 144 for Balanced and 60 for Quality.
    // That was survivable while the writer refused to lower an existing cap
    // and became a real loss the moment it wrote the configured value in both
    // directions, which is also when profile selection started applying
    // immediately. Someone at 650 picking Quality would have lost 590 frames.
    const fast = {
      ...DEFAULT_SETTINGS.config,
      roblox_settings: {
        ...DEFAULT_SETTINGS.config.roblox_settings,
        target_fps: 650,
      },
    };

    for (const profile of ["LowEnd", "Balanced", "HighEnd"] as const) {
      expect(getPresetConfig(profile, fast).roblox_settings.target_fps).toBe(
        650,
      );
    }
  });

  it("raises a low frame cap to at least the default", () => {
    const slow = {
      ...DEFAULT_SETTINGS.config,
      roblox_settings: {
        ...DEFAULT_SETTINGS.config.roblox_settings,
        target_fps: 60,
      },
    };

    expect(getPresetConfig("Balanced", slow).roblox_settings.target_fps).toBe(
      300,
    );
    expect(getPresetConfig("HighEnd", slow).roblox_settings.target_fps).toBe(
      300,
    );
    expect(getPresetConfig("LowEnd", slow).roblox_settings.target_fps).toBe(
      360,
    );
  });

  it("does not produce a config that cannot be applied", () => {
    // Ultraboost and a custom FFlag import are mutually exclusive. With a
    // custom import already on, the performance preset used to hand back a
    // config with both set, which the validator rejects. Nothing noticed while
    // selecting a profile only filled a draft.
    const withCustomFflags = {
      ...DEFAULT_SETTINGS.config,
      roblox_settings: {
        ...DEFAULT_SETTINGS.config.roblox_settings,
        custom_fflags_enabled: true,
        custom_fflags_json: '{"FFlagDebugSkyGray":"True"}',
      },
    };

    const result = getPresetConfig("LowEnd", withCustomFflags);
    expect(result.roblox_settings.ultraboost).toBe(true);
    expect(result.roblox_settings.custom_fflags_enabled).toBe(false);
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

  it("restores the previous non-SwiftTunnel plan when toggled off", () => {
    expect(nextPowerPlanForSwiftTunnelToggle(false, "HighPerformance")).toBe(
      "HighPerformance",
    );
    expect(nextPowerPlanForSwiftTunnelToggle(false, "Balanced")).toBe(
      "Balanced",
    );
    expect(previousNonSwiftTunnelPowerPlan("SwiftTunnel")).toBe(
      "HighPerformance",
    );
  });

  it("uses the persisted previous power plan when SwiftTunnel is saved", () => {
    expect(rememberedPowerPlanForSwiftTunnel("SwiftTunnel", "Balanced")).toBe(
      "Balanced",
    );
    expect(rememberedPowerPlanForSwiftTunnel("SwiftTunnel", null)).toBe(
      "HighPerformance",
    );
  });
});
