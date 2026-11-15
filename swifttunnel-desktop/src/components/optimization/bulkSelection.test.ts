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
  // Software drawing in browsers moves work onto the CPU Roblox needs, and
  // sets a machine-wide policy. Never part of a one-click batch.
  expect(bulkEnableTargets(OPTIMIZATIONS).map((item) => item.id)).not.toContain(
    "browser_hardware_accel_disable",
  );
  // Automatic low-space cleanup needs an explicit opt-out too.
  expect(bulkEnableTargets(OPTIMIZATIONS).map((item) => item.id)).not.toContain(
    "storage_sense_disable",
  );
});

it("preserves the order of eligible speed-up changes", () => {
  expect(bulkEnableTargets(SPEEDUP_OPTIMIZATIONS)).toEqual(
    SPEEDUP_OPTIMIZATIONS.filter((item) => item.safety !== "caution"),
  );
  // On SSDs the scheduled task sends TRIM; switching it off is a choice.
  expect(bulkEnableTargets(SPEEDUP_OPTIMIZATIONS).map((item) => item.id)).not.toContain(
    "su_disable_auto_defrag",
  );
});
