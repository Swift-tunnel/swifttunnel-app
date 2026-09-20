import { create } from "zustand";
import { notify } from "../lib/notifications";
import { updaterCheckChannel, updaterInstallChannel } from "../lib/commands";
import { useSettingsStore } from "./settingsStore";
import type { UpdaterProgressEvent } from "../lib/types";

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
  channel: "Stable" | "Live";
  releaseTag: string | null;
}

let pendingUpdate: PendingUpdate | null = null;
let updaterGeneration = 0;
const WHATS_NEW_DISMISSED_KEY = "swifttunnel:whats-new-dismissed-release";

function releaseId(version: string, tag: string | null) {
  return tag ?? `v${version}`;
}

function readDismissedRelease() {
  if (typeof globalThis.localStorage === "undefined") return null;
  try {
    return globalThis.localStorage.getItem(WHATS_NEW_DISMISSED_KEY);
  } catch {
    return null;
  }
}

function rememberDismissedRelease(version: string, tag: string | null) {
  if (typeof globalThis.localStorage === "undefined") return;
  try {
    globalThis.localStorage.setItem(
      WHATS_NEW_DISMISSED_KEY,
      releaseId(version, tag),
    );
  } catch {
    // Storage can be unavailable in privacy-restricted environments.
  }
}

interface UpdaterStore {
  status: UpdaterStatus;
  currentVersion: string;
  availableVersion: string | null;
  releaseTag: string | null;
  releaseNotes: string | null;
  showWhatsNew: boolean;
  progressPercent: number;
  lastChecked: number | null;
  error: string | null;

  checkForUpdates: (manual?: boolean, autoInstall?: boolean) => Promise<void>;
  installUpdate: () => Promise<void>;
  dismissWhatsNew: () => void;
  handleUpdaterProgress: (event: UpdaterProgressEvent) => void;
  handleUpdaterDone: () => void;
}

export const useUpdaterStore = create<UpdaterStore>((set, get) => ({
  status: "idle",
  currentVersion: __APP_VERSION__,
  availableVersion: null,
  releaseTag: null,
  releaseNotes: null,
  showWhatsNew: false,
  progressPercent: 0,
  lastChecked: null,
  error: null,

  checkForUpdates: async (manual = false, autoInstall = false) => {
    if (get().status === "installing") return;
    const generation = ++updaterGeneration;
    try {
      set({ status: "checking", error: null });

      const settingsStore = useSettingsStore.getState();
      const channel = settingsStore.settings.update_channel;
      const update = await updaterCheckChannel(channel);
      if (generation !== updaterGeneration) return;
      const checkedAt = Math.floor(Date.now() / 1000);

      // The request can outlive a preference edit. Only add the timestamp to
      // the current settings, not the snapshot captured before the request.
      const currentSettingsStore = useSettingsStore.getState();
      currentSettingsStore.update({
        update_settings: {
          ...currentSettingsStore.settings.update_settings,
          last_check: checkedAt,
        },
      });
      void currentSettingsStore.save();

      if (!update.available_version) {
        pendingUpdate = null;
        set((prev) => ({
          status: "up_to_date",
          currentVersion: update.current_version || prev.currentVersion,
          availableVersion: null,
          releaseTag: null,
          releaseNotes: null,
          showWhatsNew: false,
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
        channel,
        releaseTag: update.release_tag,
      };
      const updateReleaseId = releaseId(
        update.available_version,
        update.release_tag,
      );
      set({
        status: "update_available",
        currentVersion: update.current_version,
        availableVersion: update.available_version,
        releaseTag: update.release_tag,
        releaseNotes: update.release_notes,
        showWhatsNew:
          !autoInstall &&
          (manual || readDismissedRelease() !== updateReleaseId),
        progressPercent: 0,
        lastChecked: checkedAt,
      });

      if (autoInstall) {
        await notify(
          "SwiftTunnel Update",
          `Updating to v${update.available_version}, restarting...`,
        );
        if (generation !== updaterGeneration) return;
        await useUpdaterStore.getState().installUpdate();
        return;
      }

      if (manual) {
        await notify(
          "Update Available",
          `Version ${update.available_version} is ready.`,
        );
        return;
      }
    } catch (e) {
      if (generation !== updaterGeneration) return;
      set({
        status: "error",
        error: String(e),
      });
    }
  },

  installUpdate: async () => {
    if (!pendingUpdate || get().status === "installing") return;
    // Installing the offered version supersedes checks already in flight.
    // Keep its channel/version fixed and prevent a second native install.
    ++updaterGeneration;

    try {
      rememberDismissedRelease(pendingUpdate.version, pendingUpdate.releaseTag);
      set({
        status: "installing",
        showWhatsNew: false,
        progressPercent: 0,
        error: null,
      });

      const { channel, version } = pendingUpdate;
      const result = await updaterInstallChannel(channel, version);

      pendingUpdate = null;
      set({
        status: "up_to_date",
        availableVersion: null,
        releaseTag: null,
        releaseNotes: null,
        showWhatsNew: false,
        progressPercent: 100,
      });

      await notify(
        "SwiftTunnel Update",
        result.reboot_required
          ? "Update installed. Restart Windows to finish applying it."
          : "Update installed. Reopen SwiftTunnel if it does not restart.",
      );
    } catch (e) {
      set({
        status: "error",
        error: String(e),
      });
    }
  },

  dismissWhatsNew: () => {
    set((state) => {
      if (state.availableVersion) {
        rememberDismissedRelease(state.availableVersion, state.releaseTag);
      }
      return { showWhatsNew: false };
    });
  },

  handleUpdaterProgress: (event) => {
    let progressPercent: number | null = null;

    if (event.total && event.total > 0) {
      progressPercent = Math.max(
        0,
        Math.min(99, Math.round((event.downloaded / event.total) * 100)),
      );
    } else if (event.downloaded > 0) {
      progressPercent = 1;
    }

    if (progressPercent !== null) {
      set((state) =>
        state.status === "installing" ? { progressPercent } : {},
      );
    }
  },

  handleUpdaterDone: () => {
    set((state) =>
      state.status === "installing" ? { progressPercent: 100 } : {},
    );
  },
}));
