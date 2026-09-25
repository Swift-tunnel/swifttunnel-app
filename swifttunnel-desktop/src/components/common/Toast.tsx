import { motion, AnimatePresence } from "framer-motion";
import { useToastStore } from "../../stores/toastStore";
import type { ToastType } from "../../stores/toastStore";
import { Icon, type IconName } from "../ui/Icon";

const ICON_MAP: Record<ToastType, { color: string; name: IconName }> = {
  success: { color: "var(--color-status-connected)", name: "check" },
  error: { color: "var(--color-status-error)", name: "close" },
  warning: { color: "var(--color-status-warning)", name: "warning" },
  info: { color: "var(--color-accent-primary)", name: "info" },
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
              <Icon
                name={icon.name}
                size={16}
                strokeWidth={2.2}
                className="shrink-0"
                style={{ color: icon.color }}
              />
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
                <Icon name="close" size={12} strokeWidth={2} />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
