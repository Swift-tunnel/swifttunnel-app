import { reportError } from "./errors";

export type CloseRequestedEvent = {
  preventDefault: () => void;
};

type CloseToTrayDeps = {
  persistWindowState: () => Promise<void>;
  hide: () => Promise<void>;
  close: () => Promise<void>;
  shouldMinimizeToTray?: () => boolean;
  isDisposed?: () => boolean;
};

const EXIT_SAVE_TIMEOUT_MS = 2000;

async function waitForExitSave(saving: Promise<void>) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // Window placement is best effort. A stalled native settings command
    // must not trap the user in a window whose Close button never works.
    await Promise.race([
      saving,
      new Promise<void>(resolve => { timer = setTimeout(resolve, EXIT_SAVE_TIMEOUT_MS); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// Creates an onCloseRequested handler that:
// - If minimize_to_tray is enabled: prevents close, hides to tray
// - If minimize_to_tray is disabled: persists state, then closes normally
// - If no minimize preference is provided: defaults to hide-to-tray
// - Falls back to a real close if hide fails (without infinite recursion)
export function createCloseToTrayHandler(deps: CloseToTrayDeps) {
  let closing = false;
  let handling = false;
  let pendingSave: Promise<void> | null = null;

  const persist = async () => {
    try {
      await deps.persistWindowState();
    } catch (error) {
      reportError("Failed to persist window state before close", error, {
        dedupeKey: "close-to-tray-persist",
      });
    }
  };

  return async (event: CloseRequestedEvent) => {
    if (deps.isDisposed?.()) return;

    // If we're already in a programmatic close, allow it through.
    if (closing) return;

    // Must be synchronous: Tauri doesn't await async close handlers.
    event.preventDefault();
    if (handling) return;
    handling = true;

    // Begin capturing geometry before hiding, but do not wait for the settings
    // save. Native settings updates can wait behind an ongoing VPN connection.
    // Hiding keeps the process alive, so the save can finish in the background.
    const saving = pendingSave ?? persist().finally(() => { pendingSave = null; });
    pendingSave = saving;
    const shouldMinimizeToTray = deps.shouldMinimizeToTray?.() ?? true;
    try {
      if (shouldMinimizeToTray) {
        try {
          await deps.hide();
          return;
        } catch (error) {
          reportError("Failed to hide window to tray", error, {
            dedupeKey: "close-to-tray-hide",
          });
          // If hiding fails, fall back to a real close.
        }
      }

      // Give the save a chance to finish before a real exit, within a deadline.
      await waitForExitSave(saving);
      if (deps.isDisposed?.()) return;
      closing = true;
      try {
        await deps.close();
      } catch (closeError) {
        reportError("Failed to close window", closeError, {
          dedupeKey: "close-to-tray-close",
        });
        closing = false;
      }
    } finally {
      handling = false;
    }
  };
}
