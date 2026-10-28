import { afterEach, beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
  effects: [] as (() => void | (() => void))[], updates: [] as unknown[],
  report: vi.fn(), copy: vi.fn(), open: vi.fn(), toast: vi.fn(),
}));
vi.mock("react", () => ({
  useRef: (current: unknown) => ({ current }),
  useState: (initial: unknown) => [initial, (value: unknown) => h.updates.push(value)],
  useEffect: (effect: () => void | (() => void)) => h.effects.push(effect),
}));
vi.mock("../../lib/commands", () => ({
  settingsGenerateNetworkDiagnosticsBundle: h.report, systemCopyLogToClipboard: h.copy, systemOpenUrl: h.open,
}));
vi.mock("../../stores/toastStore", () => ({ useToastStore: (select: (state: unknown) => unknown) => select({ addToast: h.toast }) }));
vi.mock("../ui", () => ({ Button: "button", Row: "row", InfoIcon: "info", Tooltip: "tooltip" }));
vi.mock("./SupportSection", () => ({ SupportSection: "section" }));
import { SupportToolsSection } from "./SupportToolsSection";
let cleanups: (() => void)[] = [];
function mount() {
  const tree = SupportToolsSection();
  cleanups = h.effects.map(effect => effect()).filter((stop): stop is () => void => typeof stop === "function");
  return tree;
}
function button(node: any, label: string): any {
  if (!node || typeof node !== "object") return null;
  if (node.type === "button" && node.props.children === label) return node;
  const children = node.props?.children;
  for (const child of Array.isArray(children) ? children : [children]) {
    const found = button(child, label); if (found) return found;
  }
  return null;
}
async function settle() { for (let step = 0; step < 8; step++) await Promise.resolve(); }
beforeEach(() => {
  vi.resetAllMocks(); h.effects = []; h.updates = []; cleanups = [];
  h.open.mockResolvedValue(undefined);
});
afterEach(() => cleanups.forEach(stop => stop()));

it("admits one Generate action before its disabled state renders and allows another later", async () => {
  let finish!: (value: { file_path: string; folder_path: string }) => void;
  h.report.mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const generate = button(mount(), "Generate");
  generate.props.onClick(); generate.props.onClick();
  const calls = h.report.mock.calls.length;
  finish({ file_path: "report.txt", folder_path: "reports" }); await settle();
  expect(calls).toBe(1);
  expect(h.open).toHaveBeenCalledOnce();
  h.report.mockResolvedValue({ file_path: "new.txt", folder_path: "reports" });
  generate.props.onClick(); await settle();
  expect(h.report).toHaveBeenCalledTimes(2);
});

it("admits one clipboard action and releases admission after failure", async () => {
  let fail!: (error: Error) => void;
  h.copy.mockReturnValueOnce(new Promise((_, reject) => { fail = reject; })).mockResolvedValue({ file_path: "log.txt" });
  const copy = button(mount(), "Copy");
  copy.props.onClick(); copy.props.onClick();
  const calls = h.copy.mock.calls.length;
  fail(new Error("clipboard busy")); await settle();
  expect(calls).toBe(1);
  copy.props.onClick(); await settle();
  expect(h.copy).toHaveBeenCalledTimes(2);
  expect(h.toast).toHaveBeenCalledOnce();
});

it("does not open a folder or publish a report reply after its panel closed", async () => {
  let finish!: (value: { file_path: string; folder_path: string }) => void;
  h.report.mockReturnValue(new Promise(resolve => { finish = resolve; }));
  button(mount(), "Generate").props.onClick();
  cleanups.forEach(stop => stop());
  const updates = h.updates.length;
  finish({ file_path: "report.txt", folder_path: "reports" }); await settle();
  expect(h.updates).toHaveLength(updates);
  expect(h.open).not.toHaveBeenCalled();
  expect(h.toast).not.toHaveBeenCalled();
});
