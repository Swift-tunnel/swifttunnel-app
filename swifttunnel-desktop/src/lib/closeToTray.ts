export type CloseRequestedEvent = {
  preventDefault: () => void;
};

type CloseToTrayDeps = {
  persistWindowState: () => Promise<void>;
  hide: () => Promise<void>;
  close: () => Promise<void>;
  shouldMinimizeToTray: () => boolean;
  isDisposed?: () => boolean;
};

// Creates an onCloseRequested handler that:
// - If minimize_to_tray is enabled: prevents close, hides to tray
// - If minimize_to_tray is disabled: persists state, then closes normally
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
    } catch {
      // Persist failures shouldn't block close/hide.
    }

    if (!deps.shouldMinimizeToTray()) {
      // User wants X to actually close the app.
      closing = true;
      try {
        await deps.close();
      } catch {
        closing = false;
      }
      return;
    }

    try {
      await deps.hide();
    } catch {
      // If we can't hide to tray, fall back to closing normally.
      closing = true;
      try {
        await deps.close();
      } catch {
        // If close fails (rare), allow future close attempts to retry.
        closing = false;
      }
    }
  };
}
