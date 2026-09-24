import { create } from "zustand";
import { useSettingsStore } from "./settingsStore";
import type { TabId } from "../lib/types";

export interface NavTarget {
  tab: TabId;
  /** `data-search-anchor` to reveal, scroll to, and flash for 2s. */
  anchor?: string;
}

interface DeepLinkState {
  /** Anchor a carousel should page to so the target card is on-screen. */
  anchor: string | null;
  navigateTo: (target: NavTarget) => void;
}

/**
 * Scroll a search target into view and flash a highlight ring for ~2s. Polls,
 * because the element may mount a few frames after we switch tabs or a
 * carousel pages to it.
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
  anchor: null,
  navigateTo: ({ tab, anchor }) => {
    useSettingsStore.getState().setTab(tab);
    set({ anchor: anchor ?? null });
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
}));
