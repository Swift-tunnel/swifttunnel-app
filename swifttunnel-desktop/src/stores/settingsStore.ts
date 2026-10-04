import { create } from "zustand";
import type { AppSettings, TabId } from "../lib/types";
import { boostResetRobloxSettings, settingsLoad, settingsSave } from "../lib/commands";
import { DEFAULT_SETTINGS, mergeAppSettings } from "../lib/settings";
import { formatErrorMessage, reportError } from "../lib/errors";
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
  saveError: string | null;

  // Actions
  load: () => Promise<void>;
  save: (propagateError?: boolean) => Promise<void>;
  resetRobloxSettings: () => Promise<void>;
  update: (partial: Partial<AppSettings>) => void;
  setTab: (tab: TabId) => void;
}

export const useSettingsStore = create<SettingsStore>((set, get) => ({
  settings: DEFAULT_SETTINGS,
  activeTab: "connect",
  isLoaded: false,
  saveError: null,

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

  save: async (propagateError = false) => {
    // Read after earlier writes and native resets finish. A queued save must
    // not restore the pre-reset config captured while Repair was still busy.
    const write = saveTail.then(async () => {
      try {
        const { settings, activeTab } = get();
        await settingsSave(structuredClone({ ...settings, current_tab: activeTab }));
        set({ saveError: null });
      } catch (error) {
        set({ saveError: formatErrorMessage(error) });
        throw error;
      }
    });
    // A failed write must not poison the queue or drop subsequent changes.
    saveTail = write.catch(() => {});
    try {
      await write;
    } catch (error) {
      reportError("Failed to save settings", error);
      if (propagateError) throw error;
    }
  },

  resetRobloxSettings: async () => {
    const reset = saveTail.then(async () => {
      const roblox_settings = await boostResetRobloxSettings();
      // Refresh only the reset section, preserving other edits and this tab.
      set((state) => ({ settings: {
        ...state.settings,
        config: { ...state.settings.config, roblox_settings },
      } }));
    });
    saveTail = reset.catch(() => {});
    // Repair must see a failed reset instead of reporting success.
    await reset;
  },

  update: (partial) => {
    if (partial.auto_routing_enabled === true ||
        (partial.selected_region !== undefined && partial.selected_region !== get().settings.selected_region)) {
      partial = { ...partial, manual_relay: null };
    }
    if (partial.manual_relay) partial = { ...partial, auto_routing_enabled: false };
    if (partial.auto_routing_enabled === true) {
      partial = { ...partial, enable_api_tunneling: false, enable_country_ban: false };
    } else if (partial.enable_api_tunneling === true || partial.enable_country_ban === true) {
      partial = { ...partial, auto_routing_enabled: false };
    }
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
