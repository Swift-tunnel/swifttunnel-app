import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "../lib/settings";
import { buildPreset } from "../lib/presets";

const h = vi.hoisted(() => ({
  settings: {} as typeof DEFAULT_SETTINGS,
  save: vi.fn(), update: vi.fn(), updateConfig: vi.fn(), activate: vi.fn(), runBatch: vi.fn(), toast: vi.fn(),
  warning: null as string | null,
}));
vi.mock("./settingsStore", () => ({ useSettingsStore: { getState: () => ({ settings: h.settings, save: h.save, update: h.update }) } }));
vi.mock("./boostStore", () => ({ useBoostStore: { getState: () => ({ updateConfig: h.updateConfig, robloxRunning: false, warning: h.warning }) } }));
vi.mock("./optimizationStore", () => ({ useOptimizationStore: { getState: () => ({ status: {}, loaded: true, runBatch: h.runBatch }) } }));
vi.mock("./toastStore", () => ({ useToastStore: { getState: () => ({ addToast: h.toast }) } }));
import { usePresetStore } from "./presetStore";

beforeEach(() => {
  vi.resetAllMocks();
  h.settings = structuredClone(DEFAULT_SETTINGS);
  h.warning = null;
  h.updateConfig.mockImplementation(async (json: string) => JSON.parse(json));
  h.save.mockResolvedValue(undefined);
  h.activate.mockResolvedValue({ ok: true, requiresReboot: false });
  h.runBatch.mockImplementation(async (targets: { id: string }[], _action: string, prepare: () => Promise<void>) => {
    await prepare();
    const result = { changed: 0, failed: 0, reboot: 0 };
    for (const target of targets) {
      const outcome = await h.activate(target);
      if (outcome.ok) result.changed += 1;
      else result.failed += 1;
      if (outcome.requiresReboot) result.reboot += 1;
    }
    return result;
  });
  usePresetStore.setState({ presets: [], applyingId: null, activeId: "previous" });
});
afterEach(() => vi.unstubAllGlobals());

function addPreset(ids: string[] = []) {
  const preset = { ...buildPreset("Test preset", h.settings, ids), id: "test" };
  usePresetStore.setState({ presets: [preset] });
  return preset;
}

it("does not claim success or continue catalog changes when settings persistence fails", async () => {
  const { OPTIMIZATIONS } = await import("../components/optimization/optimizationCatalog");
  addPreset([OPTIMIZATIONS[0].id]);
  h.save.mockImplementation(async (propagate?: boolean) => { if (propagate) throw { message: "Disk is full" }; });
  await usePresetStore.getState().apply("test");
  expect(h.save).toHaveBeenCalledWith(true);
  expect(h.activate).not.toHaveBeenCalled();
  expect(usePresetStore.getState().activeId).toBeNull();
  expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ type: "error", message: expect.stringContaining("Disk is full") }));
  expect(h.toast.mock.calls.some(([toast]) => toast.type === "success")).toBe(false);
});

it("does not label a partial catalog apply as an active preset", async () => {
  // A real catalog ID is read from the catalog, not assumed by this test.
  const { OPTIMIZATIONS } = await import("../components/optimization/optimizationCatalog");
  addPreset([OPTIMIZATIONS[0].id]);
  h.activate.mockResolvedValue({ ok: false, requiresReboot: false });
  await usePresetStore.getState().apply("test");
  expect(usePresetStore.getState().activeId).toBeNull();
  expect(h.toast.mock.calls.some(([toast]) => toast.type === "success")).toBe(false);
  expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ type: "warning" }));
});

it("clears the previous active preset after a backend apply fails", async () => {
  addPreset();
  h.updateConfig.mockRejectedValue({ message: "Windows rejected the change" });
  await usePresetStore.getState().apply("test");
  expect(usePresetStore.getState().activeId).toBeNull();
  expect(usePresetStore.getState().applyingId).toBeNull();
  expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ type: "error", message: expect.stringContaining("Windows rejected") }));
});

it("marks a fully applied and saved preset active", async () => {
  addPreset();
  await usePresetStore.getState().apply("test");
  expect(usePresetStore.getState().activeId).toBe("test");
  expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ type: "success" }));
});

it("does not mutate settings or the active preset when another batch prevents admission", async () => {
  addPreset();
  h.runBatch.mockResolvedValue(null);
  await usePresetStore.getState().apply("test");
  expect(h.updateConfig).not.toHaveBeenCalled();
  expect(h.update).not.toHaveBeenCalled();
  expect(h.save).not.toHaveBeenCalled();
  expect(usePresetStore.getState().activeId).toBe("previous");
  expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ type: "warning", message: expect.stringContaining("not applied") }));
});

it("does not claim a full switch for unavailable catalog items or native warnings", async () => {
  addPreset(["retired-tweak"]);
  await usePresetStore.getState().apply("test");
  expect(usePresetStore.getState().activeId).toBeNull();
  expect(h.toast).toHaveBeenLastCalledWith(expect.objectContaining({ type: "warning", message: expect.stringContaining("unavailable") }));
  addPreset();
  h.warning = "Roblox settings could not be written";
  await usePresetStore.getState().apply("test");
  expect(usePresetStore.getState().activeId).toBeNull();
  expect(h.toast).toHaveBeenLastCalledWith(expect.objectContaining({ type: "warning", message: expect.stringContaining(h.warning) }));
});

it("loads valid saved presets without admitting broken records that crash the panel", async () => {
  const valid = { ...buildPreset("Saved", h.settings, []), id: "valid" };
  vi.stubGlobal("localStorage", { getItem: (key: string) => key === "st.presetLibrary"
    ? JSON.stringify([null, { id: "broken", name: "Missing config" }, valid, { ...valid, name: "Duplicate" }])
    : "broken" });
  vi.resetModules();
  const loaded = (await import("./presetStore")).usePresetStore.getState();
  expect(loaded.presets).toHaveLength(1);
  expect(loaded.presets[0].config.roblox_settings).toBeDefined();
  expect(loaded.presets[0].id).toBe("valid");
  expect(loaded.activeId).toBeNull();
});

it("revalidates persisted preset values using the same rules as new imports", async () => {
  const saved = { ...buildPreset("Saved", h.settings, []), id: "valid" };
  saved.config.roblox_settings.target_fps = -99;
  Object.assign(saved.config.system_optimization, { previous_power_plan: "Someone else's plan", cpu_cores: [999] });
  vi.stubGlobal("localStorage", { getItem: (key: string) => key === "st.presetLibrary" ? JSON.stringify([saved]) : "valid" });
  vi.resetModules();
  const loaded = (await import("./presetStore")).usePresetStore.getState();
  expect(loaded.presets[0].config.roblox_settings.target_fps).toBeGreaterThan(0);
  expect(loaded.presets[0].config.system_optimization).not.toHaveProperty("previous_power_plan");
  expect(loaded.presets[0].config.system_optimization).not.toHaveProperty("cpu_cores");
  expect(loaded.activeId).toBe("valid");
});
