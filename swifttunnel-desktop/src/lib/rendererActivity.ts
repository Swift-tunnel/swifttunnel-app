import { useEffect, useRef } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { create } from "zustand";
import { reportError } from "./errors";

export const WINDOW_VISIBILITY_CHANGED = "window-visibility-changed";

export type RendererActivitySnapshot = {
  documentVisible: boolean;
  windowVisible: boolean;
  windowMinimized: boolean;
  windowFocused: boolean;
};

type RendererActivityStore = RendererActivitySnapshot & {
  isActive: boolean;
  refresh: () => Promise<void>;
  setDocumentVisible: (visible: boolean) => void;
  setWindowVisible: (visible: boolean) => void;
  setWindowFocused: (focused: boolean) => void;
  setWindowMinimized: (minimized: boolean) => void;
};

export function computeRendererActive(
  snapshot: RendererActivitySnapshot,
): boolean {
  return (
    snapshot.documentVisible &&
    snapshot.windowVisible &&
    !snapshot.windowMinimized
  );
}

function documentIsVisible() {
  return typeof document === "undefined" || document.visibilityState !== "hidden";
}

function withActive(
  patch: Partial<RendererActivitySnapshot>,
  current: RendererActivitySnapshot,
) {
  const next = { ...current, ...patch };
  return { ...next, isActive: computeRendererActive(next) };
}

export const useRendererActivityStore = create<RendererActivityStore>(
  (set) => ({
    documentVisible: documentIsVisible(),
    windowVisible: true,
    windowMinimized: false,
    windowFocused: true,
    isActive: true,

    refresh: async () => {
      try {
        const appWindow = getCurrentWindow();
        const [windowVisible, windowMinimized, windowFocused] =
          await Promise.all([
            appWindow.isVisible(),
            appWindow.isMinimized(),
            appWindow.isFocused(),
          ]);
        set((current) =>
          withActive(
            {
              documentVisible: documentIsVisible(),
              windowVisible,
              windowMinimized,
              windowFocused,
            },
            current,
          ),
        );
      } catch (error) {
        reportError("Failed to refresh renderer activity", error, {
          dedupeKey: "renderer-activity-refresh",
        });
      }
    },

    setDocumentVisible: (documentVisible) =>
      set((current) => withActive({ documentVisible }, current)),
    setWindowVisible: (windowVisible) =>
      set((current) => withActive({ windowVisible }, current)),
    setWindowFocused: (windowFocused) =>
      set((current) => withActive({ windowFocused }, current)),
    setWindowMinimized: (windowMinimized) =>
      set((current) => withActive({ windowMinimized }, current)),
  }),
);

export function useActiveInterval(
  callback: () => void | Promise<void>,
  delayMs: number,
  active = true,
) {
  const rendererActive = useRendererActivityStore((s) => s.isActive);
  const callbackRef = useRef(callback);

  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  useEffect(() => {
    if (!active || !rendererActive) return;

    const id = window.setInterval(() => {
      void callbackRef.current();
    }, delayMs);
    return () => window.clearInterval(id);
  }, [active, delayMs, rendererActive]);
}

export function installRendererActivityListeners() {
  const unlisteners: UnlistenFn[] = [];
  let disposed = false;

  const refresh = () => {
    if (!disposed) {
      void useRendererActivityStore.getState().refresh();
    }
  };

  const onDocumentVisibilityChange = () => {
    useRendererActivityStore
      .getState()
      .setDocumentVisible(documentIsVisible());
    refresh();
  };

  document.addEventListener("visibilitychange", onDocumentVisibilityChange);
  window.addEventListener("focus", refresh);
  window.addEventListener("blur", refresh);

  void getCurrentWindow()
    .onFocusChanged(({ payload }) => {
      useRendererActivityStore.getState().setWindowFocused(payload);
      refresh();
    })
    .then((unlisten) => {
      if (disposed) {
        unlisten();
      } else {
        unlisteners.push(unlisten);
      }
    })
    .catch((error) => {
      reportError("Failed to listen for Tauri focus changes", error, {
        dedupeKey: "renderer-activity-focus-listen",
      });
    });

  void listen<boolean>(WINDOW_VISIBILITY_CHANGED, (event) => {
    useRendererActivityStore.getState().setWindowVisible(event.payload);
    refresh();
  })
    .then((unlisten) => {
      if (disposed) {
        unlisten();
      } else {
        unlisteners.push(unlisten);
      }
    })
    .catch((error) => {
      reportError("Failed to listen for Tauri visibility changes", error, {
        dedupeKey: "renderer-activity-visibility-listen",
      });
    });

  useRendererActivityStore.getState().setDocumentVisible(documentIsVisible());
  refresh();

  return () => {
    disposed = true;
    document.removeEventListener(
      "visibilitychange",
      onDocumentVisibilityChange,
    );
    window.removeEventListener("focus", refresh);
    window.removeEventListener("blur", refresh);
    for (const unlisten of unlisteners) {
      unlisten();
    }
  };
}
