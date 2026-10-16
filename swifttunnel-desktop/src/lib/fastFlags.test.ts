import { describe, expect, it } from "vitest";
import { FLAG_KEYS, flagBool, flagBoolean, flagPreset, parseFlags, patchFlags, rendererPatch, validateCustomFflags } from "./fastFlags";
describe("FastFlags editor validation", () => {
  it("uses the backend's signed decimal syntax for integer text", () => {
    for (const value of ["1e2", "1.0", "0x10", "0b10", "1_000", "+", "Infinity"]) {
      expect(validateCustomFflags(true, JSON.stringify({ FIntGrassMovementReducedMotionFactor: value }))).toMatch(/integer/);
    }
    for (const value of [" -10 ", "+10", "0001", 100, 1e2]) {
      expect(validateCustomFflags(true, JSON.stringify({ FIntGrassMovementReducedMotionFactor: value }))).toBeNull();
    }
  });
  it("displays accepted boolean text exactly as the backend applies it", () => {
    for (const value of [true, " True ", "\tTRUE\n"]) {
      const flags = { FFlagDebugSkyGray: value };
      expect(validateCustomFflags(true, JSON.stringify(flags))).toBeNull();
      expect(flagBool(flags, "FFlagDebugSkyGray")).toBe(true);
      expect(flagBoolean(value)).toBe(true);
    }
    for (const value of [false, " False ", "FALSE"]) expect(flagBoolean(value)).toBe(false);
    for (const value of [null, {}, 1, "true-ish"]) expect(flagBoolean(value)).toBeNull();
  });
  it("does not expand oversized drafts into editable rows", () => {
    for (const raw of [
      JSON.stringify({ FFlagDebugSkyGray: "x".repeat(2 * 1024 * 1024) }),
      JSON.stringify({ FFlagDebugSkyGray: "中".repeat(3000) }),
    ]) {
      expect(parseFlags(raw)).toEqual({});
      expect(validateCustomFflags(false, raw)).toMatch(/8 KB/);
    }
    expect(parseFlags('{"FFlagDebugSkyGray":true}')).toEqual({ FFlagDebugSkyGray: true });
  });
  it("rejects unknown flags, nested values and invalid boolean or integer values", () => {
    for (const value of [ {FFlagUnknown:true}, {FFlagDebugSkyGray:1}, {DFIntTextureQualityOverride:{}}, {DFIntTextureQualityOverride:1.5}, {DFIntTextureQualityOverride:true}, {DFIntTextureQualityOverride:1000001} ]) expect(validateCustomFflags(true,JSON.stringify(value))).toBeTruthy();
  });
  it("validates UTF-8 byte length and rejects non-object JSON", () => {
    expect(validateCustomFflags(true,JSON.stringify({DFIntTextureQualityOverride:"中".repeat(3000)}))).toMatch(/8 KB/);
    for(const raw of ["null","[]","{}","no json"]) expect(validateCustomFflags(true,raw)).toBeTruthy();
  });
  it("keeps disabling management available even when a saved draft contains retired flags", () => {
    expect(validateCustomFflags(false,'{"FFlagRetired":true}')).toBeNull();
  });
  it("only stages supported presets and never creates multiple preferred renderers", () => {
    for(const preset of ["balanced","performance"] as const){const flags=flagPreset(preset);expect(Object.keys(flags).every(k=>(FLAG_KEYS as readonly string[]).includes(k))).toBe(true);expect(validateCustomFflags(true,JSON.stringify(flags))).toBeNull();}
    const vulkan=patchFlags(flagPreset("balanced"),rendererPatch("FFlagDebugGraphicsPreferVulkan"));
    expect(vulkan.FFlagDebugGraphicsPreferD3D11).toBe(false);expect(vulkan.FFlagDebugGraphicsPreferVulkan).toBe(true);
    expect(patchFlags(vulkan,rendererPatch("default"))).toEqual({});
  });
  it("preserves unrelated draft overrides when editing or removing a control",()=>{
    expect(patchFlags({FFlagDebugSkyGray:true,DFFlagDisableDPIScale:true},{FFlagDebugSkyGray:null})).toEqual({DFFlagDisableDPIScale:true});
  });
});
