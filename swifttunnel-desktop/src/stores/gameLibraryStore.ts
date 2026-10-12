import { create } from "zustand";
import { gamesGetLibrary } from "../lib/commands";
import { formatErrorMessage } from "../lib/errors";
import type { RobloxLibrarySnapshot } from "../lib/types";

let request = 0;
interface GameLibraryStore {
  library: RobloxLibrarySnapshot | null;
  error: string | null;
  loading: boolean;
  refresh: () => Promise<void>;
}
export const useGameLibraryStore = create<GameLibraryStore>((set) => ({
  library: null, error: null, loading: false,
  refresh: async () => {
    const generation = ++request;
    set({ loading: true });
    try {
      const library = await gamesGetLibrary();
      if (generation === request) set({ library, loading: false, error: null });
    } catch (error) {
      if (generation === request) set({ loading: false, error: formatErrorMessage(error) });
    }
  },
}));
