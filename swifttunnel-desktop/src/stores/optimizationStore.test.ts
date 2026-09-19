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
  vi.resetAllMocks();
  useOptimizationStore.setState({ status: {}, loaded: false });
  commands.optimizationApply.mockRejectedValue(new Error("Rollback record kept; revert to recover"));
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const target = { id: "test", name: "Test" };

it("preserves a completed apply when an older status read returns", async () => {
  const read = deferred<string[]>();
  commands.optimizationGetActive.mockReturnValue(read.promise);
  commands.optimizationApply.mockResolvedValue({ requires_reboot: true });
  const loading = useOptimizationStore.getState().loadActive();
  await useOptimizationStore.getState().activate(target);
  read.resolve(["other"]);
  await loading;
  expect(useOptimizationStore.getState().status).toEqual({ test: "active", other: "active" });
});

it("preserves a completed revert when a read started during it returns", async () => {
  useOptimizationStore.setState({ status: { test: "active" } });
  const revert = deferred<{ requires_reboot: boolean }>();
  const read = deferred<string[]>();
  commands.optimizationRevert.mockReturnValue(revert.promise);
  commands.optimizationGetActive.mockReturnValue(read.promise);
  const reverting = useOptimizationStore.getState().deactivate(target);
  const loading = useOptimizationStore.getState().loadActive();
  revert.resolve({ requires_reboot: false });
  await reverting;
  read.resolve(["test"]);
  await loading;
  expect(useOptimizationStore.getState().status.test).toBe("inactive");
});

it("does not clear busy state when loading a snapshot", async () => {
  const apply = deferred<{ requires_reboot: boolean }>();
  commands.optimizationApply.mockReturnValue(apply.promise);
  commands.optimizationGetActive.mockResolvedValue([]);
  const applying = useOptimizationStore.getState().activate(target);
  await useOptimizationStore.getState().loadActive();
  const status = useOptimizationStore.getState().status.test;
  apply.resolve({ requires_reboot: false });
  await applying;
  expect(status).toBe("activating");
});

it("rejects duplicate apply and opposite requests while a tweak is busy", async () => {
  const apply = deferred<{ requires_reboot: boolean }>();
  commands.optimizationApply.mockReturnValue(apply.promise);
  const applying = useOptimizationStore.getState().activate(target);
  const duplicate = useOptimizationStore.getState().activate(target);
  const opposite = useOptimizationStore.getState().deactivate(target);
  apply.resolve({ requires_reboot: false });
  await applying;
  expect((await duplicate).ok).toBe(false);
  expect((await opposite).ok).toBe(false);
  expect(commands.optimizationApply).toHaveBeenCalledOnce();
  expect(commands.optimizationRevert).not.toHaveBeenCalled();
});

it("does not report a duplicate revert as a completed success", async () => {
  useOptimizationStore.setState({ status: { test: "active" } });
  const revert = deferred<{ requires_reboot: boolean }>();
  commands.optimizationRevert.mockReturnValue(revert.promise);
  const reverting = useOptimizationStore.getState().deactivate(target);
  const duplicate = await useOptimizationStore.getState().deactivate(target);
  revert.resolve({ requires_reboot: false });
  await reverting;
  expect(duplicate.ok).toBe(false);
  expect(commands.optimizationRevert).toHaveBeenCalledOnce();
});

it("ignores a superseded status response", async () => {
  const first = deferred<string[]>();
  commands.optimizationGetActive.mockReturnValueOnce(first.promise).mockResolvedValueOnce(["current"]);
  const loading = useOptimizationStore.getState().loadActive();
  await useOptimizationStore.getState().loadActive();
  first.resolve(["old"]);
  await loading;
  expect(useOptimizationStore.getState().status).toEqual({ current: "active" });
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
