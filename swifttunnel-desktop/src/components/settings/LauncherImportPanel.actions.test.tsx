import { beforeEach, expect, it, vi } from "vitest";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import { DEFAULT_SETTINGS } from "../../lib/settings";

const h = vi.hoisted(() => ({
  hooks: [] as unknown[], cursor: 0, scan: vi.fn(), save: vi.fn(), update: vi.fn(),
  settings: {} as typeof DEFAULT_SETTINGS,
}));
vi.mock("react", async () => ({
  ...await vi.importActual("react"),
  useState: (initial: unknown) => {
    const index = h.cursor++;
    if (!(index in h.hooks)) h.hooks[index] = initial;
    return [h.hooks[index], (next: unknown) => {
      h.hooks[index] = typeof next === "function" ? next(h.hooks[index]) : next;
    }];
  },
  useRef: (current: unknown) => {
    const index = h.cursor++;
    if (!(index in h.hooks)) h.hooks[index] = { current };
    return h.hooks[index];
  },
}));
vi.mock("../../lib/commands", () => ({ gamesScanImports: h.scan }));
vi.mock("../../stores/settingsStore", () => ({ useSettingsStore: {
  getState: () => ({ settings: h.settings, save: h.save, update: h.update }),
} }));
import { LauncherImportPanel } from "./LauncherImportPanel";

type Node = ReactElement<{ children?: ReactNode; [key: string]: unknown }>;
function nodes(node: ReactNode): Node[] {
  if (Array.isArray(node)) return node.flatMap(nodes);
  if (!isValidElement(node)) return [];
  const value = node as Node;
  return [value, ...nodes(value.props.children)];
}
function render() { h.cursor = 0; return LauncherImportPanel(); }
function control(label: string) {
  const node = nodes(render()).find(node => node.props.ariaLabel === label || node.props.children === label)!;
  return node.props as { onChange: (value: boolean) => void; onClick: () => void; loading: boolean };
}
function deferred() {
  let resolve!: () => void, reject!: (error: Error) => void;
  const promise = new Promise<void>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
async function settle() { for (let i = 0; i < 20; i++) await Promise.resolve(); }
beforeEach(() => {
  h.hooks = []; h.cursor = 0;
  h.settings = structuredClone(DEFAULT_SETTINGS);
  h.scan.mockReset().mockResolvedValue({ sources: [], fps_cap: 240, graphics_quality: null });
  h.save.mockReset().mockResolvedValue(undefined);
  h.update.mockReset().mockImplementation((patch: Partial<typeof DEFAULT_SETTINGS>) => {
    h.settings = { ...h.settings, ...patch };
  });
});

it("admits one import and restores the original settings if its save fails", async () => {
  control("Import launcher settings").onChange(true);
  await settle();
  const before = h.settings.config;
  const pending = deferred();
  h.save.mockReturnValue(pending.promise);
  const button = control("Import settings");
  button.onClick(); button.onClick();
  const writes = h.save.mock.calls.length;
  pending.reject(new Error("Private disk failure"));
  await settle();
  expect(h.settings.config).toBe(before);
  expect(writes).toBe(1);
  expect(control("Import settings").loading).toBe(false);
  h.save.mockResolvedValue(undefined);
  control("Import settings").onClick();
  await settle();
  expect(h.save).toHaveBeenCalledTimes(2);
  expect(h.settings.config.roblox_settings.target_fps).toBe(240);
});

it("does not start two scans before the busy state renders", async () => {
  const pending = deferred();
  h.scan.mockImplementation(() => pending.promise.then(() => ({ sources: [], fps_cap: 240, graphics_quality: null })));
  const toggle = control("Import launcher settings");
  toggle.onChange(true); toggle.onChange(true);
  const scans = h.scan.mock.calls.length;
  pending.resolve(); await settle();
  expect(scans).toBe(1);
});
