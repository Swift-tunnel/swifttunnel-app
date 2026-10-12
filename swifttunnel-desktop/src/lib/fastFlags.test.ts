import { describe, expect, it } from "vitest";
import { FLAG_KEYS, flagPreset, patchFlags, rendererPatch, validateCustomFflags } from "./fastFlags";
describe("FastFlags editor validation", () => {
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
