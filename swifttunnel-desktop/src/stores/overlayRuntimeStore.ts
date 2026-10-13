import { create } from "zustand";

export const OVERLAY_HOTKEY = "Ctrl+Shift+O";
export const useOverlayRuntimeStore = create<{
  shortcutAvailable: boolean | null;
  error: string | null;
}>(() => ({ shortcutAvailable: null, error: null }));
