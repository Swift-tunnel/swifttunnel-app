import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Icon, type IconName } from "./Icon";

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  /** Context such as a game name, kept verbatim by UI translation. */
  titleSuffix?: string;
  description?: string;
  children: ReactNode;
  maxWidth?: number;
  /** Edge-to-edge body, for a dialog that lays out its own columns and footer. */
  flush?: boolean;
  icon?: IconName;
  tone?: "neutral" | "warning" | "danger";
  dismissible?: boolean;
}

export function Dialog({
  open,
  onClose,
  title,
  titleSuffix,
  description,
  children,
  maxWidth = 480,
  flush,
  icon,
  tone = "neutral",
  dismissible = true,
}: DialogProps) {
  const titleId = useId();
  const descriptionId = useId();
  const dialog = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = () => { if (dismissible) onClose(); };
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const element = dialog.current;
    if (element && !element.contains(document.activeElement)) {
      const initial = element.querySelector<HTMLElement>("[data-dialog-autofocus]:not([disabled])")
        ?? element.querySelector<HTMLElement>("input:not([disabled]),select:not([disabled]),textarea:not([disabled])")
        ?? element.querySelector<HTMLElement>("button:not([disabled])");
      (initial ?? element).focus();
    }
    const handler = (e: KeyboardEvent) => {
      const active = dialog.current;
      const all = document.querySelectorAll('[role="dialog"][aria-modal="true"]');
      if (!active || all[all.length - 1] !== active) return;
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close.current(); }
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
      className="fixed inset-0 z-[200] flex items-center justify-center p-4"
      style={{ backgroundColor: "rgba(0, 0, 0, 0.48)" }}
      onClick={() => close.current()}
    >
      <div
        role="dialog"
        ref={dialog}
        tabIndex={-1}
        aria-modal
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        onClick={(e) => e.stopPropagation()}
        className="relative max-h-[calc(100dvh-2rem)] w-full overflow-y-auto rounded-[16px] outline-none"
        style={{
          maxWidth,
          backgroundColor: "var(--color-bg-card)",
          border: "1px solid var(--color-border-default)",
          boxShadow: "0 24px 80px rgba(0,0,0,0.3), 0 2px 12px rgba(0,0,0,0.12)",
        }}
      >
        <div
          className={`flex items-start gap-3.5 px-6 pb-5 pt-6 ${flush ? "border-b" : ""}`}
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          {icon && <div aria-hidden="true" className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-[12px] border ${tone === "danger" ? "border-status-error/15 bg-status-error/10 text-status-error" : tone === "warning" ? "border-status-warning/15 bg-status-warning/10 text-status-warning" : "border-border-subtle bg-bg-elevated text-text-secondary"}`}>
            <Icon name={icon} size={21} strokeWidth={1.7} />
          </div>}
          <div className="min-w-0 flex-1 pr-5">
            <h2 id={titleId} className="text-[16px] font-semibold leading-snug tracking-[-0.025em] text-text-primary">
              {title}{titleSuffix && <> · <span data-no-translate>{titleSuffix}</span></>}
            </h2>
            {description && (
              <p id={descriptionId} className="mt-1.5 text-[12.5px] leading-[1.65] text-text-muted">{description}</p>
            )}
          </div>
          <button
            type="button"
            onClick={() => close.current()}
            disabled={!dismissible}
            aria-label="Close"
            className="absolute right-3 top-3 flex h-7 w-7 items-center justify-center rounded-lg text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text-secondary disabled:cursor-not-allowed disabled:opacity-30"
          >
            <Icon name="close" size={14} strokeWidth={2} />
          </button>
        </div>
        <div className={flush ? "" : "px-6 pb-6"}>{children}</div>
      </div>
    </div>,
    document.body,
  );
}
