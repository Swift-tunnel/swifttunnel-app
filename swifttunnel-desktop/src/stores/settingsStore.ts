import { create } from "zustand";
import type { AppSettings, TabId } from "../lib/types";
import { settingsLoad, settingsSave } from "../lib/commands";
import { DEFAULT_SETTINGS, mergeAppSettings } from "../lib/settings";
import { reportError } from "../lib/errors";
import { IS_LITE, LITE_DEFAULT_TAB, LITE_TABS } from "../lib/lite";

/**
 * Keep the restored tab inside what this build actually has.
 *
 * Both clients share one settings file, so a Lite install can be handed a
 * persisted tab for a page it does not ship, and would otherwise open on a
 * blank content area with nothing selected in the sidebar.
 */
function sanitiseTab(tab: TabId | undefined): TabId {
  const fallback: TabId = IS_LITE ? LITE_DEFAULT_TAB : "home";
  if (!tab) return fallback;
  if (IS_LITE && !(LITE_TABS as readonly string[]).includes(tab)) {
    return fallback;
  }
  return tab;
}

interface SettingsStore {
  settings: AppSettings;
  activeTab: TabId;
  isLoaded: boolean;

  // Actions
  load: () => Promise<void>;
  save: () => Promise<void>;
  update: (partial: Partial<AppSettings>) => void;
  setTab: (tab: TabId) => void;
}

export const useSettingsStore = create<SettingsStore>((set, get) => ({
  settings: DEFAULT_SETTINGS,
  activeTab: IS_LITE ? LITE_DEFAULT_TAB : "home",
  isLoaded: false,

  load: async () => {
    try {
      const settings = mergeAppSettings(await settingsLoad());
      // Migration: the "Boost" tab was renamed to "Games" (it now hosts the
      // game library; the boost page lives behind the Roblox card). Map any
      // persisted "boost" tab onto "games" so old installs land somewhere real.
      const persistedTab =
        settings.current_tab === "boost" ? "games" : settings.current_tab;
      set({
        settings,
        // A build that dropped a page must not restore it from a settings
        // file written by the full app: both clients share one account and
        // one settings store.
        activeTab: sanitiseTab(persistedTab as TabId | undefined),
        isLoaded: true,
      });
    } catch (error) {
      reportError("Failed to load settings", error);
      set({ isLoaded: true });
    }
  },

  save: async () => {
    try {
      const { settings, activeTab } = get();
      await settingsSave({ ...settings, current_tab: activeTab });
    } catch (error) {
      reportError("Failed to save settings", error);
    }
  },

  update: (partial) => {
    set((state) => ({
      settings: { ...state.settings, ...partial },
    }));
    // Debounced save handled by the component layer
  },

  setTab: (tab) => {
    set({ activeTab: tab });
    // Persist tab selection
    const { settings } = get();
    set({ settings: { ...settings, current_tab: tab } });
  },
}));
