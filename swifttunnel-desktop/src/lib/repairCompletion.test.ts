import { describe, expect, it } from "vitest";
import { repairCompletion } from "./repairCompletion";
import type { RepairStatus } from "./repairCenter";

describe("full repair completion", () => {
  it.each<RepairStatus>(["failed", "partial", "unsupported", "not_checked"])(
    "does not call unchanged %s results healthy",
    (status) => {
      const result = repairCompletion([{ status, changed: false }]);
      expect(result.type).not.toBe("success");
      expect(result.status).not.toBe("healthy");
      expect(result.restart).toBe(false);
    },
  );

  it("keeps failed checks visible even when another repair changed the system", () => {
    expect(repairCompletion([
      { status: "fixed", changed: true },
      { status: "failed", changed: false },
    ])).toMatchObject({ status: "failed", type: "error", restart: false });
  });

  it("requires a Windows restart instead of just relaunching the app", () => {
    const result = repairCompletion([{ status: "needs_reboot", changed: true }]);
    expect(result).toMatchObject({ status: "needs_reboot", restart: false });
    expect(result.message).toContain("Restart Windows");
  });

  it("preserves the reboot instruction alongside a failed repair", () => {
    const result = repairCompletion([
      { status: "needs_reboot", changed: true },
      { status: "failed", changed: false },
    ]);
    expect(result.status).toBe("failed");
    expect(result.message).toContain("Restart Windows");
    expect(result.restart).toBe(false);
  });

  it("only restarts after completed repairs actually changed something", () => {
    expect(repairCompletion([{ status: "healthy", changed: false }]).restart).toBe(false);
    expect(repairCompletion([
      { status: "checked", changed: false },
      { status: "fixed", changed: true },
    ])).toMatchObject({ status: "fixed", type: "success", restart: true });
  });

  it("does not treat an empty run as a healthy machine", () => {
    expect(repairCompletion([])).toMatchObject({ status: "partial", restart: false });
  });
});
