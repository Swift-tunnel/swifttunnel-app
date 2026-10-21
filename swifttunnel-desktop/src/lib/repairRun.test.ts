import { describe, expect, it, vi } from "vitest";
import { formatRunForSupport, parseRepairRun, summarizeRepairRun } from "./repairRun";
import { parseSavedRepairResult } from "./repairResults";

const legacy = {
  ranAt: 1234, overall: "healthy",
  items: [{ id: "driver", label: "Driver", status: "checked", summary: "Inspected", changed: false }],
};

describe("repair-all results", () => {
  it.each([parseRepairRun, parseSavedRepairResult])("rejects oversized saved text before parsing it during startup: %s", (read) => {
    const oversized = " ".repeat(1024 * 1024) + JSON.stringify(legacy);
    const parse = vi.spyOn(JSON, "parse");
    try {
      expect(read(oversized)).toBeNull();
      expect(parse).not.toHaveBeenCalled();
    } finally { parse.mockRestore(); }
  });

  it("rejects an impossible check count before serializing each saved item", () => {
    const raw = JSON.stringify({ ...legacy, items: Array(1000).fill(legacy.items[0]) });
    const stringify = vi.spyOn(JSON, "stringify");
    try {
      expect(parseRepairRun(raw)).toBeNull();
      expect(stringify).not.toHaveBeenCalled();
    } finally { stringify.mockRestore(); }
  });

  it("retains failure evidence and next steps after saving and reopening", () => {
    const run = parseRepairRun(JSON.stringify({ ...legacy, items: [{
      ...legacy.items[0], status: "failed", nextStep: "Restart Windows and retry.",
      entries: [{ label: "Driver binding", value: "Access denied", tone: "bad" }],
    }] }))!;
    expect(run.overall).toBe("failed");
    const copied = formatRunForSupport(run);
    expect(copied).toContain("Next step: Restart Windows and retry.");
    expect(copied).toContain("Driver binding: Access denied");
  });

  it("opens old results without inventing missing details or calling checked healthy", () => {
    const run = parseRepairRun(JSON.stringify(legacy))!;
    expect(run.items[0].entries).toEqual([]);
    expect(run.items[0].nextStep).toBe("");
    expect(summarizeRepairRun(run)).toContain("1 checked");
    expect(summarizeRepairRun(run)).not.toContain("healthy");
    expect(() => formatRunForSupport(run)).not.toThrow();
  });

  it.each([null, "invalid", JSON.stringify({ ...legacy, items: [null] }),
    JSON.stringify({ ...legacy, items: [{ ...legacy.items[0], entries: [{ value: 42 }] }] }),
  ])("ignores damaged saved results: %s", (raw) => {
    expect(parseRepairRun(raw)).toBeNull();
  });
});

it("does not turn interrupted work into a healthy completed report after reopening", () => {
  const run = parseRepairRun(JSON.stringify({ ...legacy, interrupted: "Disconnect failed" }))!;
  expect(run.overall).toBe("partial");
  expect(summarizeRepairRun(run)).toContain("Stopped before completing");
  expect(formatRunForSupport(run)).toContain("Disconnect failed");
});
