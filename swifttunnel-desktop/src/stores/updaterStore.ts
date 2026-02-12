import { create } from "zustand";
import type { Update } from "@tauri-apps/plugin-updater";
import { check } from "@tauri-apps/plugin-updater";
import { notify } from "../lib/notifications";
import { useSettingsStore } from "./settingsStore";

declare const __APP_VERSION__: string;

type UpdaterStatus =
  | "idle"
  | "checking"
  | "up_to_date"
  | "update_available"
  | "installing"
  | "error";

let pendingUpdate: Update | null = null;
let totalBytes: number | undefined;
let downloadedBytes = 0;

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

export const useUpdaterStore = create<UpdaterStore>((set) => ({
  status: "idle",
  currentVersion: __APP_VERSION__,
  availableVersion: null,
  progressPercent: 0,
  lastChecked: null,
  error: null,

  checkForUpdates: async (manual = false) => {
    try {
      set({ status: "checking", error: null });

      const update = await check();
      const checkedAt = Math.floor(Date.now() / 1000);

      const settingsStore = useSettingsStore.getState();
      settingsStore.update({
        update_settings: {
          ...settingsStore.settings.update_settings,
          last_check: checkedAt,
        },
      });
      void settingsStore.save();

      if (!update) {
        pendingUpdate = null;
        set((prev) => ({
          status: "up_to_date",
          currentVersion: prev.currentVersion,
          availableVersion: null,
          progressPercent: 0,
          lastChecked: checkedAt,
        }));
        if (manual) {
          await notify("SwiftTunnel", "You are on the latest version.");
        }
        return;
      }

      pendingUpdate = update;
      set({
        status: "update_available",
        currentVersion: update.currentVersion,
        availableVersion: update.version,
        progressPercent: 0,
        lastChecked: checkedAt,
      });

      if (manual) {
        await notify("Update Available", `Version ${update.version} is ready.`);
      }
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
      totalBytes = undefined;
      downloadedBytes = 0;
      set({ status: "installing", progressPercent: 0, error: null });

      await pendingUpdate.downloadAndInstall((event) => {
        if (event.event === "Started") {
          totalBytes = event.data.contentLength;
          downloadedBytes = 0;
          set({ progressPercent: 0 });
          return;
        }

        if (event.event === "Progress") {
          downloadedBytes += event.data.chunkLength;
          if (totalBytes && totalBytes > 0) {
            set({
              progressPercent: Math.min(
                100,
                Math.round((downloadedBytes / totalBytes) * 100),
              ),
            });
          }
          return;
        }

        set({ progressPercent: 100 });
      });

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
