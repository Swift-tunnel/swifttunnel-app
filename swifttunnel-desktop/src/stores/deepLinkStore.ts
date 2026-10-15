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
function flashAnchor(anchor: string, isCurrentTab: () => boolean, done: () => void): () => void {
  const selector = `[data-search-anchor="${CSS.escape(anchor)}"]`;
  const deadline = performance.now() + 5000;
  let cancelled = false;
  let highlighted: HTMLElement | null = null;
  const timers = new Set<number>();
  const retire = () => {
    cancelled = true;
    timers.forEach(timer => window.clearTimeout(timer));
    timers.clear();
    highlighted?.classList.remove("search-flash");
    highlighted = null;
  };
  const later = (callback: () => void, delay: number) => {
    const timer = window.setTimeout(() => {
      timers.delete(timer);
      if (cancelled) return;
      if (!isCurrentTab()) { retire(); done(); return; }
      callback();
    }, delay);
    timers.add(timer);
  };
  const attempt = () => {
    if (cancelled) return;
    const el = document.querySelector<HTMLElement>(selector);
    if (el) {
      // Give a paging carousel a beat to slide the card on-screen first.
      later(() => {
        if (!el.isConnected) { attempt(); return; }
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        el.classList.add("search-flash");
        highlighted = el;
        later(() => { el.classList.remove("search-flash"); highlighted = null; done(); }, 2000);
      }, 280);
      return;
    }
    if (performance.now() < deadline) later(attempt, 90);
    else done();
  };
  attempt();
  return retire;
}

export const useDeepLinkStore = create<DeepLinkState>((set) => {
  let cancelFlash: (() => void) | undefined;
  let generation = 0;
  return {
  anchor: null,
  navigateTo: ({ tab, anchor }) => {
    const request = ++generation;
    cancelFlash?.();
    cancelFlash = undefined;
    useSettingsStore.getState().setTab(tab);
    set({ anchor: anchor ?? null });
    if (anchor) {
      cancelFlash = flashAnchor(anchor, () => useSettingsStore.getState().activeTab === tab, () => {
        if (request === generation) set({ anchor: null });
      });
    }
  },
  };
});
