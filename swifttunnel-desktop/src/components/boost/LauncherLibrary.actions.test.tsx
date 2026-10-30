import { beforeEach, expect, it, vi } from "vitest";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import type { GameLaunchPlan, RobloxLibrarySnapshot } from "../../lib/types";

// Drive the component's actual handlers without native IPC or a game launch.
const h = vi.hoisted(() => ({
  hooks: [] as unknown[], cursor: 0,
  library: null as RobloxLibrarySnapshot | null,
  actionBusy: false,
  actionError: null as string | null,
  refresh: vi.fn(), plan: vi.fn(), metrics: vi.fn(), launch: vi.fn(), dismiss: vi.fn(),
  installed: vi.fn(), add: vi.fn(),
  pendingAction: null as string | null, pendingEffect: null as (() => void) | null,
}));
vi.mock("react", async () => ({
  ...await vi.importActual("react"),
  useEffect: (effect: () => void, deps?: unknown[]) => { if (deps?.length === 3) h.pendingEffect = effect; },
  useState: (initial: unknown) => {
    const index = h.cursor++;
    const storage = h.hooks;
    if (!(index in storage)) storage[index] = initial;
    return [storage[index], (next: unknown) => { storage[index] = next; }];
  },
  useRef: (current: unknown) => {
    const index = h.cursor++;
    if (!(index in h.hooks)) h.hooks[index] = { current };
    return h.hooks[index];
  },
}));
vi.mock("../../stores/gameLibraryStore", () => ({
  useGameLibraryStore: Object.assign((select?: (state: unknown) => unknown) => {
    const state = { library: h.library, error: null, loading: false, refresh: h.refresh, pendingAction: h.pendingAction, actionBusy: h.actionBusy, actionError: h.actionError };
    return select ? select(state) : state;
  }, { getState: () => ({ requestAction: (action: string | null) => { h.pendingAction = action; }, actionBusy: h.actionBusy }), setState: (state: { actionBusy?: boolean; actionError?: string | null }) => { Object.assign(h, state); } }),
}));
vi.mock("../../stores/vpnStore", () => ({ useVpnStore: (select: (state: unknown) => unknown) => select({ gameRoute: null, state: "disconnected" }) }));
vi.mock("../../lib/commands", () => ({
  boostCloseRoblox: vi.fn(), boostGetMetrics: h.metrics, gamesAddFavourite: h.add, gamesInstalledClients: h.installed,
  gamesForget: vi.fn(), gamesLaunch: h.launch, gamesLaunchPlan: h.plan,
  gamesRefreshMetadata: vi.fn(), gamesSetNotifications: vi.fn(),
  gamesDismissRecovery: h.dismiss, gamesCreateShortcut: vi.fn(), gamesSuggestServer: vi.fn(),
}));
import { GameLibraryPanel } from "./LauncherLibrary";

type Node = ReactElement<{ children?: ReactNode; [key: string]: unknown }>;
function nodes(node: ReactNode): Node[] {
  if (Array.isArray(node)) return node.flatMap(nodes);
  if (!isValidElement(node)) return [];
  const element = node as Node;
  return [element, ...nodes(element.props.children)];
}
function render() { h.cursor = 0; return GameLibraryPanel(); }
function button(tree: ReactNode, label: string) {
  const found = nodes(tree).find(node => node.props.children === label && typeof node.props.onClick === "function");
  if (!found) throw new Error(`Missing ${label} control`);
  return found.props as { disabled?: boolean; onClick: () => void };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(ok => { resolve = ok; });
  return { promise, resolve };
}
async function settle() { for (let i = 0; i < 20; i++) await Promise.resolve(); }

beforeEach(() => {
  h.hooks = []; h.cursor = 0; h.actionBusy = false; h.actionError = null;
  h.pendingAction = null; h.pendingEffect = null;
  h.library = { current: null, warning: null, notify_joins: false, entries: [
    { place_id: "1818", name: "Crossroads", job_id: "old-job", client: "standard", last_played: 1, favourite: true },
  ] };
  h.refresh.mockReset().mockResolvedValue(undefined);
  h.metrics.mockReset().mockResolvedValue({ roblox_running: false });
  h.plan.mockReset().mockResolvedValue({
    job_id: null, datacenter: null, availability: "available", needs_close: false,
    relay_region: null, preferences: { datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false },
  } satisfies GameLaunchPlan);
  h.launch.mockReset().mockResolvedValue(undefined);
  h.dismiss.mockReset().mockResolvedValue(undefined);
  h.installed.mockReset().mockResolvedValue(["vng"]);
  h.add.mockReset().mockResolvedValue(undefined);
});

it("adds a standard Roblox link using the only installed VNG player", async () => {
  button(render(), "Add game").onClick(); await settle();
  const input = nodes(render()).find(node => node.props["aria-label"] === "Roblox game link or place ID")!;
  (input.props.onChange as (event: unknown) => void)({ target: { value: "https://www.roblox.com/games/1818" } });
  const form = nodes(render()).find(node => node.type === "form")!;
  (form.props.onSubmit as (event: unknown) => void)({ preventDefault() {} }); await settle();
  expect(h.add).toHaveBeenCalledWith("1818", "vng");
});

it("keeps a manual VNG choice when a standard link is pasted with both players installed", async () => {
  h.installed.mockResolvedValue(["standard", "vng"]);
  button(render(), "Add game").onClick(); await settle();
  const choice = nodes(render()).find(node => node.props.ariaLabel === "Roblox player")!;
  (choice.props.onChange as (client: string) => void)("vng");
  const input = nodes(render()).find(node => node.props["aria-label"] === "Roblox game link or place ID")!;
  (input.props.onChange as (event: unknown) => void)({ target: { value: "https://www.roblox.com/games/1818" } });
  const form = nodes(render()).find(node => node.type === "form")!;
  (form.props.onSubmit as (event: unknown) => void)({ preventDefault() {} }); await settle();
  expect(h.add).toHaveBeenCalledWith("1818", "vng");
});

it("offers a prefilled player correction for an old entry without launching or deleting it", async () => {
  h.plan.mockRejectedValueOnce(new Error("This game is set to Roblox, but only Roblox VNG was found. Use Change player to add it with Roblox VNG."));
  button(render(), "Play").onClick(); await settle();
  button(render(), "Change player").onClick(); await settle();
  const tree = nodes(render());
  expect(tree.find(node => node.props["aria-label"] === "Roblox game link or place ID")!.props.value).toBe("1818");
  expect(tree.find(node => node.props.ariaLabel === "Roblox player")!.props.value).toBe("vng");
  expect(h.launch).not.toHaveBeenCalled();
  expect(h.add).not.toHaveBeenCalled();
});

it("uses VNG for a queued Play request instead of forcing the standard player's entry", async () => {
  h.library!.entries.push({ ...h.library!.entries[0], client: "vng", name: "VNG Crossroads" });
  h.pendingAction = "play:1818";
  render(); h.pendingEffect!(); await settle();
  expect(h.pendingAction).toBeNull();
  expect(h.plan).toHaveBeenCalledWith("1818", "vng", null, null, true);
  expect(h.launch).toHaveBeenCalledWith("1818", "vng", null, null, false, false);
});

it("admits only one Play action even before React commits its busy state", async () => {
  const pending = deferred();
  h.plan.mockImplementation(() => pending.promise.then(() => { throw new Error("Server lookup cancelled. Try Play again."); }));
  const play = button(render(), "Play");
  play.onClick(); play.onClick();
  expect(h.plan).toHaveBeenCalledTimes(1);
  expect(button(render(), "Play").disabled).toBe(true);
  // Reject through the ordinary error path to release the admitted operation.
  pending.resolve(); await settle();
});

it("keeps recovery Rejoin busy through one final library refresh", async () => {
  h.library!.recovery = { place_id: "1818", job_id: "old-job", ip: "128.116.47.33", client: "standard", fresh_join: false, observed_at: 1 };
  const pending = deferred();
  h.refresh.mockReturnValue(pending.promise);
  const dialog = nodes(render()).find(node => node.props.title === "Roblox closed unexpectedly")!;
  button(dialog, "Rejoin").onClick(); await settle();
  expect(h.dismiss).toHaveBeenCalledTimes(1);
  expect(h.launch).toHaveBeenCalledTimes(1);
  expect(button(render(), "Play").disabled).toBe(true);
  expect(h.refresh).toHaveBeenCalledTimes(1);
  pending.resolve(); await settle();
  expect(h.refresh).toHaveBeenCalledTimes(1);
  expect(button(render(), "Play").disabled).toBe(false);
});

it("releases the action after failure and permits a later retry", async () => {
  h.plan.mockRejectedValueOnce(new Error("Server lookup timed out. Try Play again."));
  button(render(), "Play").onClick(); await settle();
  expect(button(render(), "Play").disabled).toBe(false);
  button(render(), "Play").onClick(); await settle();
  expect(h.launch).toHaveBeenCalledTimes(1);
});

it("retains the admitted Play action when Games unmounts and mounts again", async () => {
  const pending = deferred();
  h.plan.mockImplementation(() => pending.promise.then(() => { throw new Error("Server lookup timed out. Try Play again."); }));
  button(render(), "Play").onClick();
  // Fresh component hook state, with the same app-wide library store.
  h.hooks = [];
  const returnedPlay = button(render(), "Play");
  expect(returnedPlay.disabled).toBe(true);
  returnedPlay.onClick();
  expect(h.plan).toHaveBeenCalledTimes(1);
  pending.resolve(); await settle();
  expect(button(render(), "Play").disabled).toBe(false);
  expect(nodes(render()).some(node => node.props.children === "Server lookup timed out. Try Play again.")).toBe(true);
});
