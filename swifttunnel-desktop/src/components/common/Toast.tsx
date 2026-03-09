import { motion, AnimatePresence } from "framer-motion";
import { useToastStore } from "../../stores/toastStore";
import type { ToastType } from "../../stores/toastStore";

const ICON_MAP: Record<ToastType, { color: string; path: string }> = {
  success: {
    color: "var(--color-status-connected)",
    path: "M20 6 9 17l-5-5",
  },
  error: {
    color: "var(--color-status-error)",
    path: "M18 6 6 18M6 6l12 12",
  },
  warning: {
    color: "var(--color-status-warning)",
    path: "M12 9v4M12 17h.01",
  },
  info: {
    color: "var(--color-accent-primary)",
    path: "M12 16v-4M12 8h.01",
  },
};

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);
  const removeToast = useToastStore((s) => s.removeToast);

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      <AnimatePresence>
        {toasts.map((toast) => {
          const icon = ICON_MAP[toast.type];
          return (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, x: 80, scale: 0.95 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 80, scale: 0.95 }}
              transition={{ duration: 0.25, ease: "easeOut" }}
              className="flex items-center gap-2.5 rounded-[var(--radius-card)] border border-border-subtle px-4 py-3 shadow-lg"
              style={{
                backgroundColor: "var(--color-bg-elevated)",
                minWidth: 240,
                maxWidth: 360,
              }}
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke={icon.color}
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="shrink-0"
              >
                <path d={icon.path} />
              </svg>
              <span className="flex-1 text-xs font-medium text-text-primary">
                {toast.message}
              </span>
              {toast.action && (
                <button
                  type="button"
                  onClick={toast.action.onClick}
                  className="shrink-0 text-[11px] font-semibold text-accent-secondary transition-opacity hover:opacity-80"
                >
                  {toast.action.label}
                </button>
              )}
              <button
                type="button"
                onClick={() => removeToast(toast.id)}
                className="shrink-0 text-text-dimmed transition-colors hover:text-text-muted"
              >
                <svg
                  width="12"
                  height="12"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M18 6 6 18M6 6l12 12" />
                </svg>
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
