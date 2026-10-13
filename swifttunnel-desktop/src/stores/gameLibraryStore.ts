import { create } from "zustand";
import { gamesGetLibrary, gamesSetFavourite } from "../lib/commands";
import { formatErrorMessage } from "../lib/errors";
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
const favouriteKey = (placeId: string, client: RobloxClient) => `${client}:${placeId}`;
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
                const write = favourites.get(favouriteKey(entry.place_id, entry.client));
                if (write) return { ...entry, favourite: write.desired };
                if ((favouriteRevisions.get(favouriteKey(entry.place_id, entry.client)) ?? 0) > observedFavourites) {
                  const latest = get().library?.entries.find(e => e.place_id === entry.place_id && e.client === entry.client);
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
    const key = favouriteKey(placeId, client);
    const update = (value: boolean) => set(state => ({
      library: state.library ? { ...state.library, entries: state.library.entries.map(e =>
        e.place_id === placeId && e.client === client ? { ...e, favourite: value } : e,
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
