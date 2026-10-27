import { afterEach, beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => void | (() => void)>,
  listener: null as null | ((event: { payload: string }) => void),
  startup: vi.fn(),
  request: vi.fn(),
  navigate: vi.fn(),
}));
vi.mock("react", () => ({
  useEffect: (effect: () => void | (() => void)) => h.effects.push(effect),
  useRef: (current: unknown) => ({ current }),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (event: string, listener: typeof h.listener) => {
    if (event === "games-open") h.listener = listener;
    return () => {};
  }),
}));
vi.mock("./commands", () => ({ gamesStartupTarget: h.startup }));
vi.mock("../stores/gameLibraryStore", () => ({
  useGameLibraryStore: Object.assign(() => null, { getState: () => ({ requestAction: h.request }) }),
}));
vi.mock("../stores/deepLinkStore", () => ({ useDeepLinkStore: { getState: () => ({ navigateTo: h.navigate }) } }));
vi.mock("../stores/vpnStore", () => ({ useVpnStore: {} }));
vi.mock("./notifications", () => ({ notify: vi.fn() }));
vi.mock("./errors", () => ({ reportError: vi.fn() }));
vi.mock("./robloxGames", () => ({ gameSessionDescription: vi.fn() }));

function deferred() {
  let resolve!: (place: string | null) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<string | null>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
const cleanups: Array<() => void> = [];
async function start() {
  const { useGameLibrary } = await import("./useGameLibrary");
  const index = h.effects.length;
  useGameLibrary();
  const stop = h.effects[index]() as () => void;
  cleanups.push(stop);
  await Promise.resolve();
  return stop;
}
async function settle() {
  await Promise.resolve();
  await Promise.resolve();
}
beforeEach(() => {
  vi.resetModules();
  h.effects.length = 0;
  h.listener = null;
  h.startup.mockReset().mockResolvedValue(null);
  h.request.mockReset();
  h.navigate.mockReset();
});
afterEach(() => cleanups.splice(0).forEach(stop => stop()));

it("keeps the latest Play request when an earlier shortcut lookup finishes late", async () => {
  await start();
  const first = deferred(), second = deferred();
  h.startup.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  h.listener!({ payload: "play:1818" });
  h.listener!({ payload: "play:1819" });
  second.resolve("1819"); await settle();
  first.resolve("1818"); await settle();
  expect(h.request).toHaveBeenCalledExactlyOnceWith("play:1819");
});

it("does not restore an old Play action after a newer tray choice and a failed lookup", async () => {
  await start();
  const pending = deferred();
  h.startup.mockReturnValueOnce(pending.promise);
  h.listener!({ payload: "play:1818" });
  h.listener!({ payload: "favourites" });
  pending.reject(new Error("IPC interrupted")); await settle();
  expect(h.request).toHaveBeenCalledExactlyOnceWith("favourites");
});

it("does not let the delayed startup shortcut replace a newer Play request", async () => {
  const pending = deferred();
  h.startup.mockReturnValueOnce(pending.promise);
  await start();
  h.startup.mockResolvedValueOnce("1819");
  h.listener!({ payload: "play:1819" }); await settle();
  pending.resolve("1818"); await settle();
  expect(h.request).toHaveBeenCalledExactlyOnceWith("play:1819");
});

it("keeps the initial shortcut through effect cleanup and replay", async () => {
  const pending = deferred();
  h.startup.mockReturnValueOnce(pending.promise);
  (await start())();
  await start();
  pending.resolve("1818"); await settle();
  expect(h.request).toHaveBeenCalledExactlyOnceWith("play:1818");
});

it("ignores pending shortcut replies after the listener unmounts", async () => {
  const stop = await start();
  const pending = deferred();
  h.startup.mockReturnValueOnce(pending.promise);
  h.listener!({ payload: "play:1818" });
  stop();
  pending.resolve("1818"); await settle();
  expect(h.request).not.toHaveBeenCalled();
});
