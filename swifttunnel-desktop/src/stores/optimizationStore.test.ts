import { beforeEach, expect, it, vi } from "vitest";
const commands = vi.hoisted(() => ({
  optimizationApply: vi.fn(), optimizationRevert: vi.fn(), optimizationGetActive: vi.fn(),
}));
vi.mock("../lib/commands", () => commands);
vi.mock("../lib/notifications", () => ({ notify: vi.fn() }));
vi.mock("../lib/errors", () => ({ reportError: vi.fn() }));
vi.mock("./toastStore", () => ({ useToastStore: { getState: () => ({ addToast: vi.fn() }) } }));
import { useOptimizationStore } from "./optimizationStore";

beforeEach(() => {
  vi.clearAllMocks();
  useOptimizationStore.setState({ status: {}, loaded: false });
  commands.optimizationApply.mockRejectedValue(new Error("Rollback record kept; revert to recover"));
});

it("keeps Revert available when a failed apply left a rollback record", async () => {
  commands.optimizationGetActive.mockResolvedValue(["test"]);
  expect(await useOptimizationStore.getState().activate({ id: "test", name: "Test" })).toEqual({ ok: false, requiresReboot: false });
  expect(useOptimizationStore.getState().status.test).toBe("active");
});

it("leaves a tweak inactive when no changes or rollback record remain", async () => {
  commands.optimizationGetActive.mockResolvedValue([]);
  await useOptimizationStore.getState().activate({ id: "test", name: "Test" });
  expect(useOptimizationStore.getState().status.test).toBe("inactive");
});
