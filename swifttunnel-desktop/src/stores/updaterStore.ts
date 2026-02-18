import { create } from "zustand";
import { notify } from "../lib/notifications";
import { updaterCheckChannel, updaterInstallChannel } from "../lib/commands";
import { useSettingsStore } from "./settingsStore";

declare const __APP_VERSION__: string;

type UpdaterStatus =
  | "idle"
  | "checking"
  | "up_to_date"
  | "update_available"
  | "installing"
  | "error";

interface PendingUpdate {
  version: string;
}

let pendingUpdate: PendingUpdate | null = null;

interface UpdaterStore {
  status: UpdaterStatus;
  currentVersion: string;
  availableVersion: string | null;
  progressPercent: number;
  lastChecked: number | null;
  error: string | null;

  checkForUpdates: (manual?: boolean) => Promise<void>;
  installUpdate: () => Promise<void>;
}

export const useUpdaterStore = create<UpdaterStore>((set, get) => ({
  status: "idle",
  currentVersion: __APP_VERSION__,
  availableVersion: null,
  progressPercent: 0,
  lastChecked: null,
  error: null,

  checkForUpdates: async (manual = false) => {
    try {
      set({ status: "checking", error: null });

      const settingsStore = useSettingsStore.getState();
      const channel = settingsStore.settings.update_channel;
      const update = await updaterCheckChannel(channel);
      const checkedAt = Math.floor(Date.now() / 1000);

      settingsStore.update({
        update_settings: {
          ...settingsStore.settings.update_settings,
          last_check: checkedAt,
        },
      });
      void settingsStore.save();

      if (!update.available_version) {
        pendingUpdate = null;
        set((prev) => ({
          status: "up_to_date",
          currentVersion: update.current_version || prev.currentVersion,
          availableVersion: null,
          progressPercent: 0,
          lastChecked: checkedAt,
        }));
        if (manual) {
          await notify("SwiftTunnel", "You are on the latest version.");
        }
        return;
      }

      pendingUpdate = {
        version: update.available_version,
      };
      set({
        status: "update_available",
        currentVersion: update.current_version,
        availableVersion: update.available_version,
        progressPercent: 0,
        lastChecked: checkedAt,
      });

      if (manual) {
        await notify(
          "Update Available",
          `Version ${update.available_version} is ready.`,
        );
        return;
      }

      // Startup/background checks should install immediately without extra clicks.
      await get().installUpdate();
    } catch (e) {
      set({
        status: "error",
        error: String(e),
      });
    }
  },

  installUpdate: async () => {
    if (!pendingUpdate) return;

    try {
      set({ status: "installing", progressPercent: 0, error: null });

      const settingsStore = useSettingsStore.getState();
      const channel = settingsStore.settings.update_channel;
      await updaterInstallChannel(channel, pendingUpdate.version);

      pendingUpdate = null;
      set({
        status: "up_to_date",
        availableVersion: null,
        progressPercent: 100,
      });

      await notify(
        "SwiftTunnel Update",
        "Update installed. Restarting application...",
      );
    } catch (e) {
      set({
        status: "error",
        error: String(e),
      });
    }
  },
}));
