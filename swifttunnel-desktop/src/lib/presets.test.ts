import { describe, it, expect } from "vitest";
import {
  buildPreset,
  encodePreset,
  decodePreset,
  mergePresetIntoConfig,
  presetFileName,
} from "./presets";
import { DEFAULT_SETTINGS } from "./settings";
import type { AppSettings } from "./types";

function sampleSettings(): AppSettings {
  return structuredClone(DEFAULT_SETTINGS);
}

describe("presets", () => {
  it("round-trips build → encode → decode without loss", () => {
    const settings = sampleSettings();
    settings.config.roblox_settings.unlock_fps = true;
    settings.config.roblox_settings.target_fps = 240;
    settings.config.overlay.enabled = true;
    settings.selected_game_presets = ["roblox"];

    const preset = buildPreset("My Setup", settings, ["game_mode_enable", "b"]);
    const decoded = decodePreset(encodePreset(preset));

    expect(decoded).toEqual(preset);
    expect(decoded.name).toBe("My Setup");
    expect(decoded.config.roblox_settings.target_fps).toBe(240);
    expect(decoded.optimizations).toEqual(["b", "game_mode_enable"]); // sorted, deduped
    expect(decoded.game_presets).toEqual(["roblox"]);
  });

  it("exports readable JSON, not an opaque token", () => {
    const code = encodePreset(buildPreset("x", sampleSettings(), []));
    expect(code.trimStart().startsWith("{")).toBe(true);
    expect(() => JSON.parse(code)).not.toThrow();
    // A human can read the field names, it clearly isn't a cookie/token.
    expect(code).toContain("roblox_settings");
  });

  it("extracts the config even when wrapped in surrounding text", () => {
    const code = encodePreset(buildPreset("Wrapped", sampleSettings(), ["a"]));
    const wrapped = `SwiftTunnel config, "Wrapped"\nCreated now\n\n${code}\n`;
    expect(decodePreset(wrapped).name).toBe("Wrapped");
  });

  it("still accepts the legacy SWT1.<base64> token", () => {
    const preset = buildPreset("Legacy", sampleSettings(), ["a"]);
    const b64 = btoa(
      String.fromCharCode(...new TextEncoder().encode(JSON.stringify(preset))),
    );
    expect(decodePreset(`SWT1.${b64}`).name).toBe("Legacy");
  });

  it("rejects garbage and empty input with a friendly error", () => {
    expect(() => decodePreset("")).toThrow(/paste a config/i);
    expect(() => decodePreset("not-a-preset")).toThrow();
    expect(() => decodePreset("SWT1.@@@not-base64@@@")).toThrow();
  });

  it("rebuilds hostile / out-of-range input into safe settings, dropping unknown fields", () => {
    const hostile = {
      v: 1,
      name: "x".repeat(500),
      config: {
        roblox_settings: {
          unlock_fps: "yes",
          target_fps: 999999999,
          graphics_quality: "Hack",
          custom_fflags_enabled: true,
          custom_fflags_json: "not-json",
          window_width: -5,
        },
        overlay: {
          enabled: true,
          metrics: ["fps", "evil", 123],
          size: "huge",
          color: "javascript:alert(1)",
          position: "nowhere",
        },
        network_settings: { disable_nagle: true },
        system_optimization: { power_plan: "Nuke", secret_backdoor: true },
        profile: "Ransomware",
        steal_keys: "gimme",
      },
      optimizations: ["game_mode_enable", 42, "extra_id"],
      game_presets: ["roblox"],
      secret_token: "abc",
    };
    const clean = decodePreset(JSON.stringify(hostile));

    expect(clean.name.length).toBeLessThanOrEqual(60);
    expect(clean.config.roblox_settings.target_fps).toBeLessThanOrEqual(99999);
    expect(typeof clean.config.roblox_settings.unlock_fps).toBe("boolean"); // "yes" coerced
    expect(clean.config.roblox_settings.graphics_quality).not.toBe("Hack");
    expect(clean.config.roblox_settings.custom_fflags_enabled).toBe(false); // bad json → off
    expect(clean.config.overlay.metrics).toEqual(["fps"]); // unknown metrics dropped
    expect(clean.config.overlay.color).not.toContain("javascript");
    expect(clean.config.system_optimization.power_plan).not.toBe("Nuke");
    expect(clean.optimizations).toEqual(["game_mode_enable", "extra_id"]); // non-strings dropped

    // Nothing outside the known schema survives.
    const flat = JSON.stringify(clean);
    expect(flat).not.toContain("secret_backdoor");
    expect(flat).not.toContain("steal_keys");
    expect(flat).not.toContain("secret_token");
  });

  it("rejects a config claiming a newer version", () => {
    expect(() => decodePreset(JSON.stringify({ v: 99, config: {} }))).toThrow(
      /newer version/i,
    );
  });

  it("dedupes and sorts optimization ids", () => {
    const preset = buildPreset("x", sampleSettings(), ["z", "a", "z", "m"]);
    expect(preset.optimizations).toEqual(["a", "m", "z"]);
  });

  it("preserves machine-specific system fields on merge", () => {
    const current = structuredClone(DEFAULT_SETTINGS.config);
    current.system_optimization.cpu_cores = [0, 1, 2, 3];
    current.system_optimization.set_cpu_affinity = true;
    current.system_optimization.previous_power_plan = "Balanced";

    const sender = sampleSettings();
    sender.config.system_optimization.game_mode_enabled = true;
    sender.config.roblox_settings.target_fps = 165;
    const preset = buildPreset("x", sender, []);

    const merged = mergePresetIntoConfig(current, preset);

    // Portable toggles come from the preset…
    expect(merged.system_optimization.game_mode_enabled).toBe(true);
    expect(merged.roblox_settings.target_fps).toBe(165);
    // …machine-specific state stays the importer's.
    expect(merged.system_optimization.cpu_cores).toEqual([0, 1, 2, 3]);
    expect(merged.system_optimization.set_cpu_affinity).toBe(true);
    expect(merged.system_optimization.previous_power_plan).toBe("Balanced");
  });

  it("never carries tunneling data in a preset", () => {
    const preset = buildPreset("x", sampleSettings(), []);
    const flat = JSON.stringify(preset);
    expect(flat).not.toMatch(/selected_region|custom_relay_server|whitelisted_regions|adapter_guid/);
  });

  it("builds a filesystem-safe .txt name", () => {
    expect(presetFileName("My Cool Setup!!")).toBe("SwiftTunnel-Preset-My-Cool-Setup.txt");
    expect(presetFileName("   ")).toBe("SwiftTunnel-Preset-preset.txt");
  });
});
