import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RobloxLibrarySnapshot } from "../lib/types";
vi.mock("../lib/commands", () => ({ gamesGetLibrary: vi.fn(), gamesSetFavourite: vi.fn() }));
import { gamesGetLibrary, gamesSetFavourite } from "../lib/commands";
import { useGameLibraryStore } from "./gameLibraryStore";

function snapshot(): RobloxLibrarySnapshot {
  return { current: null, warning: null, notify_joins: false, entries: [
    { place_id: "1819", client: "standard", name: "Newer game", favourite: false, job_id: null, last_played: 20 },
    { place_id: "1818", client: "standard", name: "Older game", favourite: false, job_id: null, last_played: 10 },
  ] };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
const favourite = () => useGameLibraryStore.getState().library!.entries[1].favourite;
beforeEach(() => {
  useGameLibraryStore.setState({ library: snapshot(), error: null, loading: false });
});
describe("game favourites", () => {
  it("retains an unstar while metadata discovers that both places are one experience", async () => {
    const original = snapshot();
    original.entries = original.entries.map(entry => ({ ...entry, favourite: true }));
    useGameLibraryStore.setState({ library: original });
    const save = deferred<void>();
    vi.mocked(gamesSetFavourite).mockReturnValue(save.promise);
    const pending = useGameLibraryStore.getState().setFavourite("1818", "standard", false);
    vi.mocked(gamesGetLibrary).mockResolvedValue({ ...original,
      entries: original.entries.map(entry => ({ ...entry, universe_id: "200" })),
    });
    await useGameLibraryStore.getState().refresh();
    expect(useGameLibraryStore.getState().library!.entries.every(entry => !entry.favourite)).toBe(true);
    vi.mocked(gamesSetFavourite).mockResolvedValueOnce(undefined);
    const next = useGameLibraryStore.getState().setFavourite("1819", "standard", true);
    expect(next).toBe(pending);
    expect(gamesSetFavourite).toHaveBeenCalledTimes(1);
    save.resolve(); await pending;
    expect(gamesSetFavourite).toHaveBeenCalledTimes(2);
    expect(useGameLibraryStore.getState().library!.entries.every(entry => entry.favourite)).toBe(true);
  });
  it("unstars the whole experience through stale reads without moving the latest card", async () => {
    const library = snapshot();
    library.entries = library.entries.map(entry => ({ ...entry, universe_id: "200", favourite: true }));
    useGameLibraryStore.setState({ library });
    const save = deferred<void>();
    vi.mocked(gamesSetFavourite).mockReturnValue(save.promise);
    vi.mocked(gamesGetLibrary).mockResolvedValue(library);
    const pending = useGameLibraryStore.getState().setFavourite("1819", "standard", false);
    expect(useGameLibraryStore.getState().library!.entries.every(entry => !entry.favourite)).toBe(true);
    await useGameLibraryStore.getState().refresh();
    expect(useGameLibraryStore.getState().library!.entries.every(entry => !entry.favourite)).toBe(true);
    save.resolve(); await pending;
  });
  it("updates the star immediately without loading, reordering or fetching the whole library", async () => {
    const save = deferred<void>();
    vi.mocked(gamesSetFavourite).mockReturnValue(save.promise);
    const pending = useGameLibraryStore.getState().setFavourite("1818", "standard", true);
    expect(favourite()).toBe(true);
    expect(useGameLibraryStore.getState().loading).toBe(false);
    expect(useGameLibraryStore.getState().library!.entries.map(e => e.place_id)).toEqual(["1819", "1818"]);
    expect(gamesGetLibrary).not.toHaveBeenCalled();
    save.resolve(); await pending;
  });
  it("serializes fast star/unstar clicks and saves the last choice", async () => {
    const first = deferred<void>();
    vi.mocked(gamesSetFavourite).mockReturnValueOnce(first.promise).mockResolvedValueOnce(undefined);
    const pending = useGameLibraryStore.getState().setFavourite("1818", "standard", true);
    const last = useGameLibraryStore.getState().setFavourite("1818", "standard", false);
    expect(favourite()).toBe(false);
    expect(gamesSetFavourite).toHaveBeenCalledTimes(1);
    first.resolve(); await Promise.all([pending, last]);
    expect(gamesSetFavourite).toHaveBeenNthCalledWith(2, "1818", "standard", false);
    expect(favourite()).toBe(false);
  });
  it("keeps a pending choice through background snapshots without disabling Refresh", async () => {
    const save = deferred<void>();
    vi.mocked(gamesSetFavourite).mockReturnValue(save.promise);
    vi.mocked(gamesGetLibrary).mockResolvedValue(snapshot());
    const pending = useGameLibraryStore.getState().setFavourite("1818", "standard", true);
    const refresh = useGameLibraryStore.getState().refresh();
    expect(useGameLibraryStore.getState().loading).toBe(false);
    await refresh;
    expect(favourite()).toBe(true);
    save.resolve(); await pending;
  });
  it("ignores a stale snapshot arriving after a favourite save", async () => {
    const read = deferred<RobloxLibrarySnapshot>();
    vi.mocked(gamesGetLibrary).mockReturnValue(read.promise);
    vi.mocked(gamesSetFavourite).mockResolvedValue(undefined);
    const refresh = useGameLibraryStore.getState().refresh();
    await useGameLibraryStore.getState().setFavourite("1818", "standard", true);
    read.resolve(snapshot()); await refresh;
    expect(favourite()).toBe(true);
  });
  it("keeps the close status from a snapshot that overlaps a favourite save", async () => {
    useGameLibraryStore.setState({ library: { ...snapshot(), launch_pending: true, status: "Roblox is opening." } });
    const read = deferred<RobloxLibrarySnapshot>();
    vi.mocked(gamesGetLibrary).mockReturnValue(read.promise);
    vi.mocked(gamesSetFavourite).mockResolvedValue(undefined);
    const refresh = useGameLibraryStore.getState().refresh();
    await useGameLibraryStore.getState().setFavourite("1818", "standard", true);
    read.resolve({ ...snapshot(), launch_pending: false, status: null }); await refresh;
    expect(favourite()).toBe(true);
    expect(useGameLibraryStore.getState().library!.launch_pending).toBe(false);
    expect(useGameLibraryStore.getState().library!.status).toBeNull();
  });
  it("restores the last saved choice when the final click cannot be saved", async () => {
    const first = deferred<void>();
    vi.mocked(gamesSetFavourite).mockReturnValueOnce(first.promise).mockRejectedValueOnce(new Error("Disk full"));
    const pending = useGameLibraryStore.getState().setFavourite("1818", "standard", true);
    useGameLibraryStore.getState().setFavourite("1818", "standard", false);
    const failed = expect(pending).rejects.toThrow("Disk full");
    first.resolve(); await failed;
    expect(favourite()).toBe(true);
    expect(useGameLibraryStore.getState().loading).toBe(false);
  });
  it("coalesces an event burst without losing the final game-close snapshot", async () => {
    const first = deferred<RobloxLibrarySnapshot>();
    const last = deferred<RobloxLibrarySnapshot>();
    vi.mocked(gamesGetLibrary).mockReturnValueOnce(first.promise).mockReturnValueOnce(last.promise);
    const task = useGameLibraryStore.getState().refresh();
    await Promise.resolve();
    const burst = Array.from({ length: 20 }, () => useGameLibraryStore.getState().refresh());
    expect(gamesGetLibrary).toHaveBeenCalledTimes(1);
    first.resolve({ ...snapshot(), launch_pending: true, status: "Roblox is opening." });
    await Promise.resolve();
    expect(gamesGetLibrary).toHaveBeenCalledTimes(2);
    last.resolve({ ...snapshot(), launch_pending: false, status: null });
    await Promise.all([task, ...burst]);
    expect(useGameLibraryStore.getState().library!.launch_pending).toBe(false);
    expect(useGameLibraryStore.getState().library!.status).toBeNull();
    expect(gamesGetLibrary).toHaveBeenCalledTimes(2);
  });
  it("allows a new refresh after a failed read", async () => {
    vi.mocked(gamesGetLibrary).mockRejectedValueOnce(new Error("Read failed")).mockResolvedValueOnce(snapshot());
    await useGameLibraryStore.getState().refresh();
    expect(useGameLibraryStore.getState().error).toBe("Read failed");
    await useGameLibraryStore.getState().refresh();
    expect(useGameLibraryStore.getState().error).toBeNull();
  });
});
