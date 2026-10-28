import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import type { NvidiaDriverProfile } from "../../lib/types";

const h = vi.hoisted(() => ({ hooks: [] as unknown[], cursor: 0, effects: [] as Array<() => (() => void)>, read: vi.fn(), write: vi.fn() }));
vi.mock("react", async () => ({
  ...await vi.importActual("react"),
  useEffect: (effect: () => (() => void)) => h.effects.push(effect),
  useState: (initial: unknown) => {
    const index = h.cursor++;
    if (!(index in h.hooks)) h.hooks[index] = initial;
    return [h.hooks[index], (next: unknown) => { h.hooks[index] = typeof next === "function" ? next(h.hooks[index]) : next; }];
  },
  useRef: (current: unknown) => {
    const index = h.cursor++;
    if (!(index in h.hooks)) h.hooks[index] = { current };
    return h.hooks[index];
  },
}));
vi.mock("../../lib/commands", () => ({ gamesNvidiaProfile: h.read, gamesSaveNvidia: h.write }));
import { NvidiaPanel } from "./NvidiaPanel";

const power = 0x1057eb71;
const profile: NvidiaDriverProfile = { available: true, writable: true, reason: null, settings: [{ id: power, current: 0, override_value: 0 }] };
const saved: NvidiaDriverProfile = { ...profile, settings: [{ id: power, current: 1, override_value: 1 }] };
type Node = ReactElement<{ children?: ReactNode; actions?: ReactNode; [key: string]: unknown }>;
function nodes(node: ReactNode): Node[] {
  if (Array.isArray(node)) return node.flatMap(nodes);
  if (!isValidElement(node)) return [];
  const value = node as Node;
  return [value, ...nodes(value.props.children), ...nodes(value.props.actions)];
}
function render() { h.cursor = 0; return NvidiaPanel(); }
function button(label: string) {
  return nodes(render()).find(node => node.props.children === label)!.props as { onClick: () => void; loading: boolean };
}
async function settle() { for (let i = 0; i < 15; i++) await Promise.resolve(); }
let stop: (() => void) | undefined;
async function stage() {
  render(); stop = h.effects[0](); await settle();
  const control = nodes(render()).find(node => node.props["aria-label"] === "Power management")!;
  (control.props.onChange as (event: { target: { value: string } }) => void)({ target: { value: "1" } });
  button("Review changes").onClick();
}
beforeEach(() => {
  h.hooks = []; h.cursor = 0; h.effects = [];
  h.read.mockReset().mockResolvedValue(profile);
  h.write.mockReset().mockResolvedValue(saved);
});
afterEach(() => { stop?.(); stop = undefined; });

it("admits one NVIDIA Apply before React disables its confirmation button", async () => {
  let finish!: () => void;
  h.write.mockReturnValue(new Promise<NvidiaDriverProfile>(resolve => { finish = () => resolve(saved); }));
  await stage();
  const apply = button("Apply driver changes");
  apply.onClick(); apply.onClick();
  const writes = h.write.mock.calls.length;
  expect(button("Apply driver changes").loading).toBe(true);
  finish(); await settle();
  expect(writes).toBe(1);
});

it("releases NVIDIA Apply admission after failure so the unchanged draft can retry", async () => {
  h.write.mockRejectedValueOnce(new Error("Driver write failed. Retry Apply."));
  await stage();
  button("Apply driver changes").onClick(); await settle();
  expect(button("Apply driver changes").loading).toBe(false);
  button("Apply driver changes").onClick(); await settle();
  expect(h.write).toHaveBeenCalledTimes(2);
});
