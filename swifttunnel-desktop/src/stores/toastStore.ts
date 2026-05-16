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
const toastTimeouts = new Map<string, ReturnType<typeof setTimeout>>();

function clearToastTimeout(id: string) {
  const timeout = toastTimeouts.get(id);
  if (!timeout) return;

  clearTimeout(timeout);
  toastTimeouts.delete(id);
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],

  addToast: (toast) => {
    const id = String(++nextId);
    set((s) => ({ toasts: [...s.toasts, { ...toast, id }] }));
    const timeout = setTimeout(() => {
      toastTimeouts.delete(id);
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, 4000);
    toastTimeouts.set(id, timeout);
  },

  removeToast: (id) => {
    clearToastTimeout(id);
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  },
}));
