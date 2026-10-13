import { create } from "zustand";
import { gamesGetLibrary, gamesSetFavourite } from "../lib/commands";
import { formatErrorMessage } from "../lib/errors";
import type { RobloxClient, RobloxLibrarySnapshot } from "../lib/types";

let request = 0;
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
  refresh: async () => {
    const generation = ++request;
    set(state => ({ loading: state.library === null }));
    try {
      const library = await gamesGetLibrary();
      if (generation === request) set({
        library: { ...library, entries: library.entries.map(entry => {
          const write = favourites.get(favouriteKey(entry.place_id, entry.client));
          return write ? { ...entry, favourite: write.desired } : entry;
        }) },
        loading: false, error: null,
      });
    } catch (error) {
      if (generation === request) set({ loading: false, error: formatErrorMessage(error) });
    }
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
    ++request; // An older snapshot must not undo a click or a completed save.
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
      ++request;
      favourites.delete(key);
      set({ loading: false });
    });
    return write.task;
  },
}));
