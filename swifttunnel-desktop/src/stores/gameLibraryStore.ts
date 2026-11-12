import { create } from "zustand";
import { gamesGetLibrary, gamesSetFavourite } from "../lib/commands";
import { formatErrorMessage } from "../lib/errors";
import { gameEntryKey } from "../lib/robloxGames";
import type { RobloxClient, RobloxLibrarySnapshot } from "../lib/types";

let refreshTask: Promise<void> | null = null;
let refreshRequested = false;
let favouriteRevision = 0;
interface FavouriteRevision {
  revision: number;
  value: boolean;
}
const favouriteRevisions = new Map<string, FavouriteRevision>();
function noteFavouriteRevision(key: string, value: boolean) {
  const revision = ++favouriteRevision;
  // Only an older in-flight snapshot needs protection. Completed game keys
  // must not accumulate for the rest of a long-running app session.
  if (refreshTask) favouriteRevisions.set(key, { revision, value });
}
interface FavouriteWrite {
  desired: boolean;
  confirmed: boolean;
  revision: number;
  task: Promise<void>;
}
const favourites = new Map<string, FavouriteWrite>();
interface GameLibraryStore {
  actionBusy: boolean;
  actionError: string | null;
  pendingAction: string | null;
  requestAction: (action: string | null) => void;
  library: RobloxLibrarySnapshot | null;
  error: string | null;
  loading: boolean;
  refresh: () => Promise<void>;
  setFavourite: (placeId: string, client: RobloxClient, favourite: boolean) => Promise<void>;
}
export const useGameLibraryStore = create<GameLibraryStore>((set, get) => ({
  actionBusy: false,
  actionError: null,
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
                let latest: FavouriteRevision | undefined;
                for (const alias of keys) {
                  const change = favouriteRevisions.get(alias);
                  if (change && change.revision > (latest?.revision ?? observedFavourites)) {
                    latest = change;
                  }
                }
                return latest ? { ...entry, favourite: latest.value } : entry;
              }) },
              loading: false, error: null,
            });
          } catch (error) {
            set({ loading: false, error: formatErrorMessage(error) });
          }
          observedFavourites = favouriteRevision;
        } while (refreshRequested);
      } finally {
        favouriteRevisions.clear();
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
    const update = (value: boolean) => set(state => {
      const library = state.library;
      if (!library) return state;
      const target = library.entries.find(e => e.place_id === placeId && e.client === client) ?? entry;
      const targetKey = gameEntryKey(target);
      return { library: { ...library, entries: library.entries.map(e =>
        gameEntryKey(e) === targetKey && e.favourite !== value ? { ...e, favourite: value } : e,
      ) } };
    });
    // Merge just the star into old reads. New session/close metadata must still
    // arrive, even when a favourite save overlaps the event-driven refresh.
    noteFavouriteRevision(key, favourite);
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
      noteFavouriteRevision(key, write.confirmed);
      favourites.delete(key);
    });
    return write.task;
  },
}));
