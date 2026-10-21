import { create } from "zustand";
import type { AppSettings, BoostUpdateResult, RobloxResetReportResponse, RobloxSettingsConfig, TabId } from "../lib/types";
import { boostResetRobloxClient, boostResetRobloxSettings, gamesSaveFlags, boostUpdateConfig, boostSyncEffectiveConfig, settingsLoad, settingsSave } from "../lib/commands";
import { DEFAULT_SETTINGS, mergeAppSettings } from "../lib/settings";
import { formatErrorMessage, reportError } from "../lib/errors";
import { mergeConfigChanges } from "../lib/configMerge";
import { NAV_ITEMS } from "../components/shell/nav";

// Native saves perform filesystem and system work on blocking workers. Keep
// one in flight so an older snapshot cannot finish after a newer preference.
let saveTail: Promise<void> = Promise.resolve();
let pendingSave: Promise<void> | null = null;
let pendingBoostSync: Promise<BoostUpdateResult> | null = null;

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
  resetRobloxClient: () => Promise<RobloxResetReportResponse>;
  applyBoostConfig: (configJson: string) => Promise<BoostUpdateResult>;
  syncBoostConfig: () => Promise<BoostUpdateResult>;
  applyFastFlags: (enabled: boolean, json: string, expected: RobloxSettingsConfig) => Promise<BoostUpdateResult>;
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
    // Share the not-yet-started save. Sliders and background counters can
    // otherwise queue dozens of identical full-file writes behind a slow disk.
    let write = pendingSave;
    if (!write) {
      const next = saveTail.then(async () => {
        if (pendingSave === next) pendingSave = null;
        try {
          const { settings, activeTab } = get();
          await settingsSave(structuredClone({ ...settings, current_tab: activeTab }));
          set({ saveError: null });
        } catch (error) {
          set({ saveError: formatErrorMessage(error) });
          reportError("Failed to save settings", error);
          throw error;
        }
      });
      pendingSave = next;
      write = next;
      // A failed write must not poison the queue or drop subsequent changes.
      saveTail = write.catch(() => {});
    }
    try {
      await write;
    } catch (error) {
      if (propagateError) throw error;
    }
  },

  syncBoostConfig: () => {
    if (pendingBoostSync) return pendingBoostSync;
    pendingSave = null;
    const syncing = saveTail.then(async () => {
      const observed = get().settings.config;
      const result = await boostSyncEffectiveConfig();
      set(state => ({ settings: { ...state.settings,
        config: mergeConfigChanges(state.settings.config, observed, result.applied_config),
      } }));
      return result;
    }).finally(() => { pendingBoostSync = null; });
    pendingBoostSync = syncing;
    saveTail = syncing.then(() => {}, () => {});
    return syncing;
  },

  applyBoostConfig: (configJson) => {
    const requested: AppSettings["config"] = JSON.parse(configJson);
    const observed = structuredClone(get().settings.config);
    pendingSave = null;
    const applying = saveTail.then(async () => {
      const before = get().settings.config;
      // Keep the user's draft changes, but carry forward fields confirmed by
      // an earlier queued apply instead of sending their older draft values.
      const rebased = mergeConfigChanges(requested, observed, before);
      const result = await boostUpdateConfig(JSON.stringify(rebased));
      const applied = result.applied_config ?? rebased;
      // Publish before a queued full save can start. Preserve edits made while
      // Windows was applying the config, including another view's overlay edits.
      set(state => ({ settings: { ...state.settings,
        config: mergeConfigChanges(state.settings.config, before, applied),
      } }));
      return { ...result, applied_config: applied };
    });
    saveTail = applying.then(() => {}, () => {});
    return applying;
  },

  applyFastFlags: (enabled, json, expected) => {
    // Like a native reset, this is an ordering barrier. Earlier full-settings
    // writes finish first; later writes read the confirmed flag fields after
    // this operation, rather than undoing them with a pre-apply snapshot.
    pendingSave = null;
    const applying = saveTail.then(async () => {
      const result = await gamesSaveFlags(enabled, json, expected);
      const flags = result.applied_config.roblox_settings;
      set(state => ({ settings: { ...state.settings, config: {
        ...state.settings.config,
        roblox_settings: {
          ...state.settings.config.roblox_settings,
          custom_fflags_enabled: flags.custom_fflags_enabled,
          custom_fflags_json: flags.custom_fflags_json,
          ultraboost: flags.ultraboost,
        },
      } } }));
      return result;
    });
    saveTail = applying.then(() => {}, () => {});
    return applying;
  },

  resetRobloxClient: () => {
    pendingSave = null;
    const reset = saveTail.then(async () => {
      const report = await boostResetRobloxClient();
      const confirmed = await settingsLoad();
      // Reload only the native reset's section. A whole-store load would lose
      // unsaved overlay/preferences and restore the previously persisted tab.
      set(state => ({ settings: { ...state.settings, config: {
        ...state.settings.config, roblox_settings: confirmed.config.roblox_settings,
      } } }));
      return report;
    });
    saveTail = reset.then(() => {}, () => {});
    return reset;
  },

  resetRobloxSettings: async () => {
    // A reset is an ordering barrier. Later saves must not share one queued
    // before the reset or resolve before the reset settings reach disk.
    pendingSave = null;
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
