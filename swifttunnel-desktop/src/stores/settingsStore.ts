import { create } from "zustand";
import type { AppSettings, TabId } from "../lib/types";
import { settingsLoad, settingsSave } from "../lib/commands";
import { DEFAULT_SETTINGS, mergeAppSettings } from "../lib/settings";
import { reportError } from "../lib/errors";
import { NAV_ITEMS } from "../components/shell/nav";

// Native saves perform filesystem and system work on blocking workers. Keep
// one in flight so an older snapshot cannot finish after a newer preference.
let saveTail: Promise<void> = Promise.resolve();

/**
 * Keep the restored tab inside what this build actually has.
 *
 * Both clients share one settings file, so a Lite install can be handed a
 * persisted tab for a page it does not ship, and a settings file from before
 * the Home page was removed still names it. Either would otherwise open on a
 * blank content area with nothing selected in the sidebar.
 */
function sanitiseTab(tab: string | undefined): TabId {
  return NAV_ITEMS.some((item) => item.id === tab) ? (tab as TabId) : "connect";
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
  activeTab: "connect",
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
        activeTab: sanitiseTab(persistedTab),
        isLoaded: true,
      });
    } catch (error) {
      reportError("Failed to load settings", error);
      set({ isLoaded: true });
    }
  },

  save: async () => {
    const { settings, activeTab } = get();
    // Capture at request time, just as IPC serialization did before queueing.
    const snapshot = structuredClone({ ...settings, current_tab: activeTab });
    const write = saveTail.then(() => settingsSave(snapshot));
    // A failed write must not poison the queue or drop subsequent changes.
    saveTail = write.catch(() => {});
    try {
      await write;
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
