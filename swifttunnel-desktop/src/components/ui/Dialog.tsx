import { useEffect, useRef, type ReactNode } from "react";
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
  const dialog = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const element = dialog.current;
    if (element && !element.contains(document.activeElement)) {
      const initial = element.querySelector<HTMLElement>("input:not([disabled]),select:not([disabled]),textarea:not([disabled]),button:not([disabled])");
      (initial ?? element).focus();
    }
    const handler = (e: KeyboardEvent) => {
      const active = dialog.current;
      const all = document.querySelectorAll('[role="dialog"][aria-modal="true"]');
      if (!active || all[all.length - 1] !== active) return;
      if (e.key === "Escape") close.current();
      if (e.key === "Tab") {
        const items = Array.from(active.querySelectorAll<HTMLElement>('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex="0"]')).filter(node => node.getClientRects().length > 0);
        const first = items[0]; const last = items[items.length - 1];
        if (!first) { e.preventDefault(); active.focus(); }
        else if (e.shiftKey && (document.activeElement === first || !active.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && (document.activeElement === last || !active.contains(document.activeElement))) { e.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener("keydown", handler);
    return () => { window.removeEventListener("keydown", handler); if (previous?.isConnected) previous.focus(); };
  }, [open]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-6"
      style={{ backgroundColor: "rgba(0, 0, 0, 0.6)", backdropFilter: "blur(4px)" }}
      onClick={onClose}
    >
      <div
        role="dialog"
        ref={dialog}
        tabIndex={-1}
        aria-modal
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
        className="max-h-[calc(100vh-3rem)] w-full overflow-y-auto rounded-[var(--radius-card)]"
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
