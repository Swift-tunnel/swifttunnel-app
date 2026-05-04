import { reportError } from "./errors";

export type CloseRequestedEvent = {
  preventDefault: () => void;
};

type CloseToTrayDeps = {
  persistWindowState: () => Promise<void>;
  hide: () => Promise<void>;
  close: () => Promise<void>;
  onHiddenToTray?: () => void;
  shouldMinimizeToTray?: () => boolean;
  isDisposed?: () => boolean;
};

// Creates an onCloseRequested handler that:
// - If minimize_to_tray is enabled: prevents close, hides to tray
// - If minimize_to_tray is disabled: persists state, then closes normally
// - If no minimize preference is provided: defaults to hide-to-tray
// - Falls back to a real close if hide fails (without infinite recursion)
export function createCloseToTrayHandler(deps: CloseToTrayDeps) {
  let closing = false;

  return async (event: CloseRequestedEvent) => {
    if (deps.isDisposed?.()) return;

    // If we're already in a programmatic close, allow it through.
    if (closing) return;

    // Must be synchronous: Tauri doesn't await async close handlers.
    event.preventDefault();

    try {
      await deps.persistWindowState();
    } catch (error) {
      reportError("Failed to persist window state before close", error, {
        dedupeKey: "close-to-tray-persist",
      });
    }

    const shouldMinimizeToTray = deps.shouldMinimizeToTray?.() ?? true;
    if (!shouldMinimizeToTray) {
      // User wants X to actually close the app.
      closing = true;
      try {
        await deps.close();
      } catch (error) {
        reportError("Failed to close window", error, {
          dedupeKey: "close-to-tray-close",
        });
        closing = false;
      }
      return;
    }

    try {
      await deps.hide();
      deps.onHiddenToTray?.();
    } catch (error) {
      reportError("Failed to hide window to tray", error, {
        dedupeKey: "close-to-tray-hide",
      });
      // If we can't hide to tray, fall back to closing normally.
      closing = true;
      try {
        await deps.close();
      } catch (closeError) {
        reportError("Failed to close window after tray hide fallback", closeError, {
          dedupeKey: "close-to-tray-fallback-close",
        });
        // If close fails (rare), allow future close attempts to retry.
        closing = false;
      }
    }
  };
}
