import { useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Icon } from "./Icon";

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  maxWidth?: number;
}

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  maxWidth = 480,
}: DialogProps) {
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-6"
      style={{ backgroundColor: "rgba(0, 0, 0, 0.6)", backdropFilter: "blur(4px)" }}
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
        className="w-full rounded-[var(--radius-card)]"
        style={{
          maxWidth,
          backgroundColor: "var(--color-bg-elevated)",
          border: "1px solid var(--color-border-default)",
        }}
      >
        <div
          className="flex items-start justify-between gap-4 border-b px-5 py-4"
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          <div>
            <h2 className="text-[14px] font-semibold text-text-primary">
              {title}
            </h2>
            {description && (
              <p className="mt-0.5 text-[12px] text-text-muted">{description}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-[4px] p-1 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
          >
            <Icon name="close" size={14} strokeWidth={2} />
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
