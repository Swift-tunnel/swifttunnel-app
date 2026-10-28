import { beforeEach, expect, it, vi } from "vitest";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import { DEFAULT_SETTINGS } from "../../lib/settings";

const h = vi.hoisted(() => ({ hooks: [] as unknown[], cursor: 0, metrics: vi.fn(), apply: vi.fn() }));
vi.mock("react", async () => ({
  ...await vi.importActual("react"),
  useEffect: () => {},
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
vi.mock("../../stores/settingsStore", () => ({ useSettingsStore: Object.assign(
  (select: (state: unknown) => unknown) => select({ settings: DEFAULT_SETTINGS }),
  { getState: () => ({ applyFastFlags: h.apply }) },
) }));
vi.mock("../../stores/deepLinkStore", () => ({ useDeepLinkStore: () => null }));
vi.mock("../../lib/commands", () => ({ boostGetMetrics: h.metrics, boostCloseRoblox: vi.fn(), systemOpenUrl: vi.fn() }));
vi.mock("./NvidiaPanel", () => ({ NvidiaPanel: () => null }));
import { FastFlagsPanel } from "./FastFlagsPanel";

type Node = ReactElement<{ children?: ReactNode; [key: string]: unknown }>;
function nodes(node: ReactNode): Node[] {
  if (Array.isArray(node)) return node.flatMap(nodes);
  if (!isValidElement(node)) return [];
  const value = node as Node;
  return [value, ...nodes(value.props.children)];
}
function render() { h.cursor = 0; return FastFlagsPanel(); }
function saveButton() {
  const tree = render();
  const button = nodes(tree).find(node => node.props.children === "Save & apply")!;
  return button.props as { onClick: () => void; loading: boolean };
}
function stage() {
  const manage = nodes(render()).find(node => node.props.ariaLabel === "Manage FastFlags")!;
  (manage.props.onChange as (value: boolean) => void)(true);
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(ok => { resolve = ok; });
  return { promise, resolve };
}
async function settle() { for (let i = 0; i < 15; i++) await Promise.resolve(); }
beforeEach(() => {
  h.hooks = []; h.cursor = 0;
  h.metrics.mockReset().mockResolvedValue({ roblox_running: false });
  h.apply.mockReset().mockResolvedValue({ warnings: [], applied_config: DEFAULT_SETTINGS.config });
});

it("admits one FastFlags save before React commits the busy state", async () => {
  const pending = deferred();
  h.metrics.mockImplementation(() => pending.promise.then(() => ({ roblox_running: false })));
  stage();
  const save = saveButton();
  save.onClick(); save.onClick();
  const metricsCalls = h.metrics.mock.calls.length;
  expect(saveButton().loading).toBe(true);
  pending.resolve(); await settle();
  expect(metricsCalls).toBe(1);
  expect(h.apply).toHaveBeenCalledTimes(1);
});

it("releases FastFlags save admission after failure so Retry works", async () => {
  h.apply.mockRejectedValueOnce(new Error("Could not apply FastFlags. Retry Save."));
  stage(); saveButton().onClick(); await settle();
  expect(saveButton().loading).toBe(false);
  saveButton().onClick(); await settle();
  expect(h.apply).toHaveBeenCalledTimes(2);
});
