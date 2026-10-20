import { create } from "zustand";

export type ToastType = "success" | "error" | "info" | "warning";

export interface Toast {
  id: string;
  type: ToastType;
  message: string;
  action?: { label: string; onClick: () => void };
}

interface ToastStore {
  toasts: Toast[];
  addToast: (toast: Omit<Toast, "id">) => void;
  removeToast: (id: string) => void;
}

let nextId = 0;
const MAX_TOASTS = 4;
const TOAST_LIFETIME_MS = 4000;

export const useToastStore = create<ToastStore>((set, get) => {
  const timers = new Map<string, ReturnType<typeof setTimeout>>();

  function cancelExpiry(id: string) {
    clearTimeout(timers.get(id));
    timers.delete(id);
  }

  function removeToast(id: string) {
    cancelExpiry(id);
    const toasts = get().toasts;
    if (toasts.some(toast => toast.id === id)) {
      set({ toasts: toasts.filter(toast => toast.id !== id) });
    }
  }

  function expireLater(id: string) {
    cancelExpiry(id);
    timers.set(id, setTimeout(() => removeToast(id), TOAST_LIFETIME_MS));
  }

  return {
    toasts: [],
    addToast: (toast) => {
      const toasts = get().toasts;
      // Repeated status events should not multiply cards or animate the whole
      // stack again. Action notices stay distinct so callbacks are not lost.
      const duplicate = !toast.action && toasts.find(old =>
        !old.action && old.type === toast.type && old.message === toast.message);
      if (duplicate) {
        expireLater(duplicate.id);
        return;
      }
      const kept = toasts.slice(-(MAX_TOASTS - 1));
      for (const old of toasts.slice(0, toasts.length - kept.length)) cancelExpiry(old.id);
      const id = String(++nextId);
      expireLater(id);
      set({ toasts: [...kept, { ...toast, id }] });
    },
    removeToast,
  };
});
