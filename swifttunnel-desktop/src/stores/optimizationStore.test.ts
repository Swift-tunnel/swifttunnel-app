import { beforeEach, expect, it, vi } from "vitest";
const commands = vi.hoisted(() => ({
  optimizationApply: vi.fn(), optimizationRevert: vi.fn(), optimizationGetActive: vi.fn(),
}));
vi.mock("../lib/commands", () => commands);
vi.mock("../lib/notifications", () => ({ notify: vi.fn() }));
vi.mock("../lib/errors", async (original) => ({ ...await original<typeof import("../lib/errors")>(), reportError: vi.fn() }));
vi.mock("./toastStore", () => ({ useToastStore: { getState: () => ({ addToast: vi.fn() }) } }));
import { useOptimizationStore } from "./optimizationStore";

beforeEach(() => {
  vi.resetAllMocks();
  useOptimizationStore.setState({ status: {}, loaded: false, loading: false, loadError: null, errors: {}, restartRequired: false, batch: null });
  commands.optimizationApply.mockRejectedValue(new Error("Rollback record kept; revert to recover"));
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const target = { id: "test", name: "Test" };

it("keeps a batch exclusive across unsubscription and blocks opposite and individual changes", async () => {
  useOptimizationStore.setState({ loaded: true });
  const first = deferred<{ requires_reboot: boolean }>();
  commands.optimizationApply.mockReturnValueOnce(first.promise).mockResolvedValue({ requires_reboot: false });
  const unsubscribe = useOptimizationStore.subscribe(() => {});
  const batch = useOptimizationStore.getState().runBatch([target, { id: "second", name: "Second" }], "apply");
  unsubscribe();
  expect(useOptimizationStore.getState().batch).toEqual({ action: "apply", completed: 0, total: 2 });
  expect(await useOptimizationStore.getState().runBatch([target], "revert")).toBeNull();
  expect((await useOptimizationStore.getState().deactivate(target)).ok).toBe(false);
  expect((await useOptimizationStore.getState().activate({ id: "third", name: "Third" })).ok).toBe(false);
  first.resolve({ requires_reboot: true });
  expect(await batch).toEqual({ changed: 2, failed: 0, reboot: 1 });
  expect(commands.optimizationApply.mock.calls.map(([id]) => id)).toEqual(["test", "second"]);
  expect(commands.optimizationRevert).not.toHaveBeenCalled();
  expect(useOptimizationStore.getState().batch).toBeNull();
});

it("does not start a batch with unreadable status or a single change still running", async () => {
  expect(await useOptimizationStore.getState().runBatch([target], "apply")).toBeNull();
  useOptimizationStore.setState({ loaded: true });
  const applying = deferred<{ requires_reboot: boolean }>();
  commands.optimizationApply.mockReturnValue(applying.promise);
  const single = useOptimizationStore.getState().activate(target);
  expect(await useOptimizationStore.getState().runBatch([{ id: "second", name: "Second" }], "apply")).toBeNull();
  applying.resolve({ requires_reboot: false });
  await single;
  expect(commands.optimizationApply).toHaveBeenCalledOnce();
});

it("releases a failed batch, deduplicates targets and allows recovery by reverting", async () => {
  useOptimizationStore.setState({ loaded: true });
  commands.optimizationGetActive.mockResolvedValue([target.id]);
  expect(await useOptimizationStore.getState().runBatch([target, target], "apply")).toEqual({ changed: 0, failed: 1, reboot: 0 });
  expect(useOptimizationStore.getState().batch).toBeNull();
  expect(commands.optimizationApply).toHaveBeenCalledOnce();
  commands.optimizationRevert.mockResolvedValue({ requires_reboot: false });
  expect(await useOptimizationStore.getState().runBatch([target], "revert")).toEqual({ changed: 1, failed: 0, reboot: 0 });
  expect(useOptimizationStore.getState().status.test).toBe("inactive");
});

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

it("keeps failed status unavailable and allows retry", async () => {
  commands.optimizationGetActive.mockRejectedValue({ message: "Snapshot is unreadable" });
  await useOptimizationStore.getState().loadActive();
  expect(useOptimizationStore.getState().loaded).toBe(false);
  expect(useOptimizationStore.getState().loading).toBe(false);
  expect(useOptimizationStore.getState().loadError).toBe("Snapshot is unreadable");
  commands.optimizationGetActive.mockResolvedValue(["test"]);
  await useOptimizationStore.getState().loadActive();
  expect(useOptimizationStore.getState().loaded).toBe(true);
  expect(useOptimizationStore.getState().loadError).toBeNull();
  expect(useOptimizationStore.getState().status.test).toBe("active");
});

it("rejects malformed status instead of treating characters as tweak IDs", async () => {
  commands.optimizationGetActive.mockResolvedValue("test");
  await useOptimizationStore.getState().loadActive();
  expect(useOptimizationStore.getState().loaded).toBe(false);
  expect(useOptimizationStore.getState().status).toEqual({});
});

it("keeps bulk failures visible and normalizes object errors", async () => {
  commands.optimizationApply.mockRejectedValue({ message: "Access denied" });
  commands.optimizationGetActive.mockResolvedValue([]);
  await useOptimizationStore.getState().activate(target, { silent: true });
  expect(useOptimizationStore.getState().errors.test).toBe("Access denied");
  commands.optimizationApply.mockResolvedValue({ requires_reboot: true });
  await useOptimizationStore.getState().activate(target, { silent: true });
  expect(useOptimizationStore.getState().errors.test).toBe("");
  expect(useOptimizationStore.getState().restartRequired).toBe(true);
});
