export type CloseRequestedEvent = {
  preventDefault: () => void;
};

type CloseToTrayDeps = {
  persistWindowState: () => Promise<void>;
  hide: () => Promise<void>;
  close: () => Promise<void>;
  isDisposed?: () => boolean;
};

// Creates an onCloseRequested handler that:
// - Prevents close synchronously (avoids race with async work)
// - Hides to tray on success
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
      // Persist failures shouldn't block hide-to-tray.
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
