import { describe, expect, it } from "vitest";
import { REPAIR_ISSUES } from "./repairCenter";
import { formatRunForSupport, parseRepairRun, plainRunSummary, type RepairRun } from "./repairRun";
import { ADVANCED_REPAIRS, REPAIR_SYMPTOMS, RESET_ISSUE_IDS } from "./repairSymptoms";
import type { RepairStatus } from "./repairResults";

const known = new Set(REPAIR_ISSUES.map((issue) => issue.id));

function run(statuses: RepairStatus[], extra: Partial<RepairRun> = {}): RepairRun {
  return {
    overall: "checked",
    ranAt: 1_800_000_000_000,
    items: statuses.map((status, i) => ({
      id: REPAIR_ISSUES[i].id,
      label: REPAIR_ISSUES[i].label,
      status,
      summary: "summary",
      nextStep: "",
      entries: [],
      changed: status === "fixed",
      reversible: false,
      ranAt: 1_800_000_000_000,
    })),
    ...extra,
  };
}

describe("repair symptoms", () => {
  it("never puts a reset in a symptom's first action", () => {
    for (const symptom of REPAIR_SYMPTOMS) {
      expect(symptom.issues.length).toBeGreaterThan(0);
      for (const id of symptom.issues) {
        expect(known.has(id)).toBe(true);
        expect(RESET_ISSUE_IDS).not.toContain(id);
      }
      expect(symptom.steps.length).toBeGreaterThan(0);
    }
  });

  it("keeps every reset reachable under Advanced, and the full repair complete", () => {
    const advanced = new Set(ADVANCED_REPAIRS.flatMap((item) => item.issues));
    for (const id of RESET_ISSUE_IDS) expect(advanced.has(id)).toBe(true);
    const full = ADVANCED_REPAIRS.find((item) => item.id === "full");
    expect(full?.issues).toEqual(REPAIR_ISSUES.map((issue) => issue.id));
  });

  it("uses no em dashes in player-facing text", () => {
    expect(JSON.stringify([REPAIR_SYMPTOMS, ADVANCED_REPAIRS])).not.toContain("—");
  });
});

describe("plain repair summary", () => {
  it("says what happened in one plain line", () => {
    expect(plainRunSummary(run(["healthy", "checked"]))).toBe("No problems found in the 2 things checked.");
    expect(plainRunSummary(run(["fixed", "healthy"]))).toBe("Fixed 1 thing.");
    expect(plainRunSummary(run(["fixed", "failed", "partial", "needs_reboot", "not_checked"]))).toBe(
      "Fixed 1 thing. 2 things need attention. Restart Windows to finish. 1 thing could not be checked.",
    );
    expect(plainRunSummary(run([], { interrupted: "Repair stopped: x" }))).toBe("Repair stopped before it finished.");
    expect(plainRunSummary(run([]))).toBe("Nothing was checked.");
  });

  it("keeps the problem a run was started for, and tolerates older saved runs", () => {
    const saved = parseRepairRun(JSON.stringify(run(["healthy"], { scope: "Can't connect" })));
    expect(saved?.scope).toBe("Can't connect");
    expect(formatRunForSupport(saved!).split("\n")[0]).toBe("SwiftTunnel Repair (Can't connect)");
    const older = parseRepairRun(JSON.stringify(run(["healthy"])));
    expect(older?.scope).toBeUndefined();
    expect(formatRunForSupport(older!).split("\n")[0]).toBe("SwiftTunnel Repair (all)");
    expect(parseRepairRun(JSON.stringify(run(["healthy"], { scope: "x".repeat(500) })))?.scope).toHaveLength(80);
  });
});
