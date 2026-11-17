import type { Window as NativeWindow } from "@tauri-apps/api/window";

let nativeHidden = false;
let revision = 0;
const listeners = new Set<() => void>();

export function isMainWindowHidden(
  doc: Pick<Document, "hidden"> | undefined = typeof document === "undefined" ? undefined : document,
): boolean {
  return nativeHidden || doc?.hidden === true;
}

export function subscribeMainWindowVisibility(
  listener: () => void,
  doc: Pick<Document, "addEventListener" | "removeEventListener"> = document,
): () => void {
  listeners.add(listener);
  doc.addEventListener("visibilitychange", listener);
  return () => {
    listeners.delete(listener);
    doc.removeEventListener("visibilitychange", listener);
  };
}

export function setNativeWindowHidden(hidden: boolean): void {
  // An older native read must not undo a completed show/hide.
  revision += 1;
  if (nativeHidden === hidden) return;
  nativeHidden = hidden;
  for (const listener of listeners) listener();
}

export async function refreshMainWindowVisibility(
  window: Pick<NativeWindow, "isVisible" | "isMinimized">,
  isDisposed: () => boolean,
): Promise<void> {
  const request = ++revision;
  try {
    const [visible, minimized] = await Promise.all([window.isVisible(), window.isMinimized()]);
    if (request === revision && !isDisposed()) setNativeWindowHidden(!visible || minimized);
  } catch {
    // Page visibility remains available in browser preview and if IPC fails.
  }
}
