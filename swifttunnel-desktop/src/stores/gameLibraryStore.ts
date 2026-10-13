import { create } from "zustand";
import { gamesGetLibrary, gamesSetFavourite } from "../lib/commands";
import { formatErrorMessage } from "../lib/errors";
import { gameEntryKey } from "../lib/robloxGames";
import type { RobloxClient, RobloxLibrarySnapshot } from "../lib/types";

let refreshTask: Promise<void> | null = null;
let refreshRequested = false;
let favouriteRevision = 0;
const favouriteRevisions = new Map<string, number>();
interface FavouriteWrite {
  desired: boolean;
  confirmed: boolean;
  revision: number;
  task: Promise<void>;
}
const favourites = new Map<string, FavouriteWrite>();
interface GameLibraryStore {
  pendingAction: string | null;
  requestAction: (action: string | null) => void;
  library: RobloxLibrarySnapshot | null;
  error: string | null;
  loading: boolean;
  refresh: () => Promise<void>;
  setFavourite: (placeId: string, client: RobloxClient, favourite: boolean) => Promise<void>;
}
export const useGameLibraryStore = create<GameLibraryStore>((set, get) => ({
  pendingAction:null,requestAction:pendingAction=>set({pendingAction}),
  library: null, error: null, loading: false,
  refresh: () => {
    refreshRequested = true;
    if (refreshTask) return refreshTask;
    let observedFavourites = favouriteRevision;
    set(state => ({ loading: state.library === null }));
    // Events arriving during a read request one follow-up snapshot. Never run
    // overlapping IPC reads, and never lose a game-close event to coalescing.
    refreshTask = Promise.resolve().then(async () => {
      try {
        do {
          refreshRequested = false;
          try {
            const library = await gamesGetLibrary();
            set({
              library: { ...library, entries: library.entries.map(entry => {
                const key = gameEntryKey(entry);
                // Metadata can discover a universe while a place-based save
                // is pending. Carry that choice across the identity upgrade.
                const peers = entry.universe_id ? library.entries.filter(e => gameEntryKey(e) === key) : [entry];
                const keys = [key, ...peers.map(e => gameEntryKey({ ...e, universe_id: null }))];
                const write = keys.map(key => favourites.get(key)).find(Boolean);
                if (write) return { ...entry, favourite: write.desired };
                if (keys.some(key => (favouriteRevisions.get(key) ?? 0) > observedFavourites)) {
                  const latest = get().library?.entries.find(e => keys.includes(gameEntryKey(e)));
                  if (latest) return { ...entry, favourite: latest.favourite };
                }
                return entry;
              }) },
              loading: false, error: null,
            });
          } catch (error) {
            set({ loading: false, error: formatErrorMessage(error) });
          }
          observedFavourites = favouriteRevision;
        } while (refreshRequested);
      } finally {
        refreshTask = null;
      }
    });
    return refreshTask;
  },
  setFavourite: (placeId, client, favourite) => {
    const entry = get().library?.entries.find(e => e.place_id === placeId && e.client === client);
    if (!entry) return Promise.reject(new Error("Refresh your library before changing this favourite."));
    const groupKey = gameEntryKey(entry);
    const peers = get().library!.entries.filter(e => gameEntryKey(e) === groupKey);
    const keys = [groupKey, ...peers.map(e => gameEntryKey({ ...e, universe_id: null }))];
    const key = keys.find(key => favourites.has(key)) ?? groupKey;
    const update = (value: boolean) => set(state => ({
      library: state.library ? { ...state.library, entries: state.library.entries.map(e =>
        gameEntryKey(e) === gameEntryKey(state.library!.entries.find(e => e.place_id === placeId && e.client === client) ?? entry)
          ? { ...e, favourite: value } : e,
      ) } : null,
    }));
    // Merge just the star into old reads. New session/close metadata must still
    // arrive, even when a favourite save overlaps the event-driven refresh.
    favouriteRevisions.set(key, ++favouriteRevision);
    const existing = favourites.get(key);
    if (existing) {
      existing.desired = favourite;
      existing.revision++;
      update(favourite);
      return existing.task;
    }
    const write: FavouriteWrite = { desired: favourite, confirmed: entry.favourite, revision: 1, task: Promise.resolve() };
    favourites.set(key, write);
    update(favourite);
    write.task = (async () => {
      for (;;) {
        const revision = write.revision;
        const desired = write.desired;
        try {
          await gamesSetFavourite(placeId, client, desired);
          write.confirmed = desired;
        } catch (error) {
          if (write.revision === revision) {
            update(write.confirmed);
            throw error;
          }
        }
        if (write.revision === revision) break;
      }
    })().finally(() => {
      favouriteRevisions.set(key, ++favouriteRevision);
      favourites.delete(key);
      set({ loading: false });
    });
    return write.task;
  },
}));
