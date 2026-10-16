export type FlagValue = boolean | number | string;
export type FlagMap = Record<string, FlagValue>;
export const FLAG_KEYS = [
  "FFlagHandleAltEnterFullscreenManually", "FFlagDebugGraphicsPreferD3D11",
  "FFlagDebugGraphicsPreferVulkan", "FFlagDebugGraphicsPreferOpenGL",
  "FIntDebugForceMSAASamples", "DFFlagTextureQualityOverrideEnabled",
  "DFIntTextureQualityOverride", "DFFlagDisableDPIScale",
  "DFIntDebugFRMQualityLevelOverride", "FFlagDebugSkyGray",
  "FIntFRMMinGrassDistance", "FIntFRMMaxGrassDistance",
  "FIntGrassMovementReducedMotionFactor", "DFFlagDebugPauseVoxelizer",
  "DFIntCSGLevelOfDetailSwitchingDistance", "DFIntCSGLevelOfDetailSwitchingDistanceL12",
  "DFIntCSGLevelOfDetailSwitchingDistanceL23", "DFIntCSGLevelOfDetailSwitchingDistanceL34",
] as const;
const allowed = new Set<string>(FLAG_KEYS);
export const MESH_FLAGS = FLAG_KEYS.filter(k => k.startsWith("DFIntCSG"));
export const RENDERER_FLAGS = ["FFlagDebugGraphicsPreferD3D11", "FFlagDebugGraphicsPreferVulkan", "FFlagDebugGraphicsPreferOpenGL"];
export function booleanFlag(key: string) { return key.startsWith("FFlag") || key.startsWith("DFFlag"); }
export function flagBoolean(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return null;
}
function oversizedFlags(raw: string): boolean {
  // Reject a large paste before allocating another full UTF-8 copy or parsing
  // it for the editor, including while flag management is switched off.
  return raw.length > 8192 || new TextEncoder().encode(raw).length > 8192;
}
export function validateCustomFflags(enabled: boolean, raw: string): string | null {
  if (oversizedFlags(raw)) return "FastFlags must be under 8 KB.";
  if (!enabled) return null;
  let value: unknown;
  try { value = JSON.parse(raw); } catch { return "FastFlags must be valid JSON."; }
  if (!value || Array.isArray(value) || typeof value !== "object") return "FastFlags must be a JSON object.";
  if (!Object.keys(value).length) return "Add an override, or turn off Manage FastFlags to use defaults.";
  for (const [key, entry] of Object.entries(value)) {
    if (!allowed.has(key)) return `${key} is not in SwiftTunnel's supported local flags.`;
    if (booleanFlag(key)) {
      if (flagBoolean(entry) !== null) continue;
      return `${key} must be true or false.`;
    }
    const number = typeof entry === "number" ? entry : typeof entry === "string" && /^[+-]?\d+$/.test(entry.trim()) ? Number(entry.trim()) : NaN;
    if (!Number.isInteger(number) || Math.abs(number) > 1_000_000) return `${key} must be an integer from -1000000 to 1000000.`;
  }
  return null;
}
export function parseFlags(raw: string): FlagMap {
  if (oversizedFlags(raw)) return {};
  try { const value = JSON.parse(raw); return value && !Array.isArray(value) && typeof value === "object" ? value : {}; }
  catch { return {}; }
}
export function flagNumber(flags: FlagMap, key: string, fallback: number) {
  const number = Number(flags[key]); return flags[key] !== undefined && Number.isFinite(number) ? number : fallback;
}
export function flagBool(flags: FlagMap, key: string) { return flagBoolean(flags[key]) === true; }
export function patchFlags(flags: FlagMap, patch: Record<string, FlagValue | null>): FlagMap {
  const next = { ...flags };
  for (const [key, value] of Object.entries(patch)) { if (value === null) delete next[key]; else next[key] = value; }
  return next;
}
export function rendererPatch(value: string) {
  return Object.fromEntries(RENDERER_FLAGS.map(key => [key, value === "default" ? null : key === value]));
}
export function flagPreset(preset: "default" | "balanced" | "performance"): FlagMap {
  if (preset === "default") return {};
  if (preset === "balanced") return { FFlagDebugGraphicsPreferD3D11: true, FFlagDebugGraphicsPreferVulkan: false, FFlagDebugGraphicsPreferOpenGL: false };
  return {
    ...flagPreset("balanced"), FIntDebugForceMSAASamples: 1,
    DFFlagTextureQualityOverrideEnabled: true, DFIntTextureQualityOverride: 0,
    DFIntDebugFRMQualityLevelOverride: 1, FFlagDebugSkyGray: true,
    FIntFRMMinGrassDistance: 0, FIntFRMMaxGrassDistance: 0,
    FIntGrassMovementReducedMotionFactor: 0, DFFlagDebugPauseVoxelizer: true,
    ...Object.fromEntries(MESH_FLAGS.map(key => [key, 0])),
  };
}
