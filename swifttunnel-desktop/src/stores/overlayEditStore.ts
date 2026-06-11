import { create } from "zustand";

/**
 * Transient (non-persisted) "reposition the overlay" mode. Set from the In-Game
 * tab; the overlay driver reads it to show the overlay + make it draggable even
 * when no game is running, and the overlay window reads it (via the render
 * payload) to drop click-through.
 */
interface OverlayEditStore {
  editing: boolean;
  setEditing: (v: boolean) => void;
}

export const useOverlayEditStore = create<OverlayEditStore>((set) => ({
  editing: false,
  setEditing: (v) => set({ editing: v }),
}));
