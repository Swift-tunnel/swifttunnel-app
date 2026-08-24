/**
 * Take the browser affordances out of the app window.
 *
 * The UI runs in WebView2, so out of the box it behaves like a browser tab:
 * right-click offers a page context menu with "Inspect element", and F12 or
 * Ctrl+Shift+I opens developer tools. That is fine for a web page and wrong
 * for a shipped desktop app. It invites people to poke at internals, and in a
 * product that installs a network driver and intercepts packets it reads as a
 * browser wearing an app costume, which is exactly the impression to avoid.
 *
 * Only production builds are locked down. Development keeps both, because
 * that is where they are actually needed.
 *
 * This is not a security boundary and is not meant to be one. Anyone
 * determined can still attach a debugger to their own machine. It is about the
 * app presenting as an app.
 */

/** Keystrokes WebView2 maps to developer tools. */
export function isDevToolsShortcut(event: {
  key: string;
  ctrlKey: boolean;
  shiftKey: boolean;
}): boolean {
  if (event.key === "F12") return true;

  // Ctrl+Shift+I opens the inspector, +J the console, +C the element picker.
  if (event.ctrlKey && event.shiftKey) {
    const key = event.key.toUpperCase();
    return key === "I" || key === "J" || key === "C";
  }

  return false;
}

/**
 * Whether the affordances should be removed.
 *
 * Split out from the listeners so the decision can be tested without a DOM,
 * and so a dev build is never accidentally locked down.
 */
export function shouldLockDown(isDev: boolean): boolean {
  return !isDev;
}

/**
 * Block the context menu and developer-tools shortcuts.
 *
 * Returns a function that removes the listeners again, which keeps this
 * testable and lets a caller undo it.
 */
export function installWebviewLockdown(
  target: Pick<Document, "addEventListener" | "removeEventListener"> = document,
): () => void {
  const onContextMenu = (event: Event) => {
    event.preventDefault();
  };

  const onKeyDown = (event: Event) => {
    const keyEvent = event as KeyboardEvent;
    if (isDevToolsShortcut(keyEvent)) {
      event.preventDefault();
    }
  };

  target.addEventListener("contextmenu", onContextMenu);
  // Capture phase: get there before anything in the page can act on it.
  target.addEventListener("keydown", onKeyDown, true);

  return () => {
    target.removeEventListener("contextmenu", onContextMenu);
    target.removeEventListener("keydown", onKeyDown, true);
  };
}
