import { create } from "zustand";
import { useSettingsStore } from "./settingsStore";
import type { TabId } from "../lib/types";

export interface NavTarget {
  tab: TabId;
  /** Game to auto-open inside the Games tab (e.g. "roblox"). */
  game?: string;
  /** `data-search-anchor` to reveal, scroll to, and flash for 2s. */
  anchor?: string;
}

interface DeepLinkState {
  /** Game the Games tab should open (consumed + cleared by GamesTab). */
  game: string | null;
  /** Anchor a carousel should page to so the target card is on-screen. */
  anchor: string | null;
  navigateTo: (target: NavTarget) => void;
  clearGame: () => void;
}

/**
 * Scroll a search target into view and flash a highlight ring for ~2s. Polls,
 * because the element may mount a few frames after we switch tabs, open a game,
 * or a carousel pages to it.
 */
function flashAnchor(anchor: string) {
  const selector = `[data-search-anchor="${CSS.escape(anchor)}"]`;
  const deadline = Date.now() + 5000;
  const attempt = () => {
    const el = document.querySelector<HTMLElement>(selector);
    if (el) {
      // Give a paging carousel a beat to slide the card on-screen first.
      window.setTimeout(() => {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        el.classList.add("search-flash");
        window.setTimeout(() => el.classList.remove("search-flash"), 2000);
      }, 280);
      return;
    }
    if (Date.now() < deadline) window.setTimeout(attempt, 90);
  };
  attempt();
}

export const useDeepLinkStore = create<DeepLinkState>((set) => ({
  game: null,
  anchor: null,
  navigateTo: ({ tab, game, anchor }) => {
    useSettingsStore.getState().setTab(tab);
    set({ game: game ?? null, anchor: anchor ?? null });
    if (anchor) {
      flashAnchor(anchor);
      // Clear the anchor after the flash so a later re-render can't yank a
      // carousel back to this card.
      window.setTimeout(
        () => set((s) => (s.anchor === anchor ? { anchor: null } : {})),
        3200,
      );
    }
  },
  clearGame: () => set({ game: null }),
}));
