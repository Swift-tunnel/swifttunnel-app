import { expect, it } from "vitest";
import { bulkEnableTargets } from "./bulkSelection";
import { OPTIMIZATIONS, SPEEDUP_OPTIMIZATIONS, TIER_ORDER } from "./optimizationCatalog";

it("never includes caution changes in a tier or whole-page enable batch", () => {
  for (const tier of TIER_ORDER) {
    const targets = bulkEnableTargets(OPTIMIZATIONS.filter((item) => item.tier === tier));
    expect(targets.every((item) => item.safety !== "caution")).toBe(true);
  }
  expect(bulkEnableTargets(OPTIMIZATIONS)).toEqual(OPTIMIZATIONS.filter((item) => item.safety !== "caution"));
  expect(bulkEnableTargets([{ id: "danger", name: "Danger", safety: "caution" }])).toEqual([]);
});

it("preserves the order of eligible speed-up changes", () => {
  expect(bulkEnableTargets(SPEEDUP_OPTIMIZATIONS)).toEqual(SPEEDUP_OPTIMIZATIONS);
});
