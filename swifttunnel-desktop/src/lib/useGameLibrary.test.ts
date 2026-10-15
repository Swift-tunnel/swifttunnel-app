import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { RobloxGameSession, RobloxLibrarySnapshot } from "./types";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => (() => void) | undefined>,
  ref: { current: null as string | null },
  library: null as RobloxLibrarySnapshot | null,
  fetchState: vi.fn(),
  notify: vi.fn(),
}));
vi.mock("react", () => ({
  useEffect: (effect: () => (() => void) | undefined) => h.effects.push(effect),
  useRef: () => h.ref,
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn().mockResolvedValue(() => {}) }));
vi.mock("../stores/gameLibraryStore", () => ({ useGameLibraryStore: Object.assign(
  (select: (state: { library: RobloxLibrarySnapshot | null }) => unknown) => select({ library: h.library }),
  { getState: () => ({ library: h.library }) },
) }));
vi.mock("../stores/vpnStore", () => ({ useVpnStore: { getState: () => ({ fetchState: h.fetchState, gameRoute: null }) } }));
vi.mock("./notifications", () => ({ notify: h.notify }));
vi.mock("./commands", () => ({ gamesStartupTarget: vi.fn() }));
vi.mock("../stores/deepLinkStore", () => ({ useDeepLinkStore: { getState: vi.fn() } }));
vi.mock("./errors", () => ({ reportError: vi.fn() }));
vi.mock("./robloxGames", () => ({ gameSessionDescription: (session: RobloxGameSession) => session.location }));
import { useGameLibrary } from "./useGameLibrary";

const join = (place = "1", observed = 100): RobloxGameSession => ({
  place_id: place, job_id: `job-${place}`, ip: "128.116.47.33", client: "standard",
  fresh_join: true, observed_at: observed, location: `Location ${place}`,
});
const cleanups: Array<() => void> = [];
function render() {
  useGameLibrary();
  const effect = h.effects[h.effects.length - 1];
  const stop = effect() ?? (() => {});
  cleanups.push(stop);
  return { effect, stop };
}
beforeEach(() => {
  vi.useFakeTimers();
  h.ref.current = null;
  h.effects.length = 0;
  h.library = { entries: [], current: join(), warning: null, notify_joins: true };
  h.fetchState.mockReset().mockResolvedValue(true);
  h.notify.mockReset().mockResolvedValue(undefined);
});
afterEach(() => {
  cleanups.splice(0).forEach(stop => stop());
  vi.useRealTimers();
});

it("survives effect replay before its first notification is sent", async () => {
  const first = render();
  first.stop();
  cleanups.push(first.effect() ?? (() => {}));
  await vi.advanceTimersByTimeAsync(2000);
  expect(h.notify).toHaveBeenCalledExactlyOnceWith("Roblox game joined", "Location 1");
});

it("does not announce a game closed while the route read was pending", async () => {
  let finish!: () => void;
  h.fetchState.mockImplementation(() => new Promise<void>(resolve => { finish = resolve; }));
  render();
  await vi.advanceTimersByTimeAsync(2000);
  h.library!.current = null;
  finish();
  await vi.advanceTimersByTimeAsync(0);
  expect(h.notify).not.toHaveBeenCalled();
});

it("does not label the next join with the previous game's notification", async () => {
  let finish!: () => void;
  h.fetchState.mockImplementationOnce(() => new Promise<void>(resolve => { finish = resolve; }));
  const first = render();
  await vi.advanceTimersByTimeAsync(2000);
  h.library!.current = join("2", 200);
  finish();
  await vi.advanceTimersByTimeAsync(0);
  expect(h.notify).not.toHaveBeenCalled();
  first.stop();
  render();
  await vi.advanceTimersByTimeAsync(2000);
  expect(h.notify).toHaveBeenCalledExactlyOnceWith("Roblox game joined", "Location 2");
});

it("does not repeat an already sent join notification", async () => {
  const first = render();
  await vi.advanceTimersByTimeAsync(2000);
  first.stop();
  render();
  await vi.advanceTimersByTimeAsync(20_000);
  expect(h.notify).toHaveBeenCalledOnce();
});

it("enabling notifications does not replay an opted-out join", async () => {
  h.library!.notify_joins = false;
  render().stop();
  h.library!.notify_joins = true;
  render().stop();
  await vi.advanceTimersByTimeAsync(2000);
  expect(h.notify).not.toHaveBeenCalled();
  h.library!.current = join("2", 200);
  render();
  await vi.advanceTimersByTimeAsync(2000);
  expect(h.notify).toHaveBeenCalledOnce();
});
