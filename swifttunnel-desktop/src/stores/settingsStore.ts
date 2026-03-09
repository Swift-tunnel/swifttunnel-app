import { create } from "zustand";
import type { AppSettings, TabId } from "../lib/types";
import { settingsLoad, settingsSave } from "../lib/commands";
import { DEFAULT_SETTINGS, mergeAppSettings } from "../lib/settings";
import { reportError } from "../lib/errors";

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
      set({
        settings,
        activeTab: (settings.current_tab as TabId) || "connect",
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
