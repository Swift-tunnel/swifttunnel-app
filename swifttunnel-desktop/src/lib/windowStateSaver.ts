import type { WindowState } from "./types";

export function createWindowStateSaver(options: {
  read: () => Promise<WindowState | null>;
  persist: (state: WindowState) => Promise<void>;
  onError: (error: unknown) => void;
}) {
  let disposed = false;
  let revision = 0;
  let requested = false;
  let task: Promise<void> | null = null;
  function save(): Promise<void> {
    if (disposed) return Promise.resolve();
    requested = true;
    if (task) return task;
    // Reserve admission before the read starts. Each completed round consumes
    // at most one newer request, rather than building a geometry IPC backlog.
    task = Promise.resolve().then(async () => {
      try {
        while (requested && !disposed) {
          requested = false;
          const observed = revision;
          try {
            const state = await options.read();
            if (!disposed && observed === revision && state) await options.persist(state);
          } catch (error) {
            if (!disposed) options.onError(error);
          }
        }
      } finally {
        // Clear inside this job, so a request arriving after the loop exits
        // cannot attach itself to a completed task and lose its follow-up.
        task = null;
      }
    });
    return task;
  }
  return {
    invalidate() { revision += 1; },
    dispose() { disposed = true; },
    save,
  };
}
