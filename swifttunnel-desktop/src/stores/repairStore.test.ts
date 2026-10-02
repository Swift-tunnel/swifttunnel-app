import { beforeEach, expect, it } from "vitest";
import { beginRepair, repairIsBusy, useRepairStore, saveRepairRun } from "./repairStore";

beforeEach(() => useRepairStore.setState({ running: false, restarting: false, reinstalling: false, error: null, lastRun: null }));

it("retains the operation across unsubscribing and blocks overlapping repair and reinstall", () => {
  const unsubscribe = useRepairStore.subscribe(() => {});
  expect(beginRepair("repair")).toBe(true);
  useRepairStore.setState({ progress: 3, currentStep: "Driver" });
  unsubscribe();
  expect(repairIsBusy()).toBe(true);
  expect(useRepairStore.getState().progress).toBe(3);
  expect(beginRepair("reinstall")).toBe(false);
  expect(beginRepair("repair")).toBe(false);
  useRepairStore.setState({ running: false });
  expect(beginRepair("reinstall")).toBe(true);
});

it("keeps results in memory even if persistent storage is unavailable", () => {
  const run = { overall: "partial" as const, ranAt: 123, items: [] };
  saveRepairRun(run);
  expect(useRepairStore.getState().lastRun).toEqual(run);
});
