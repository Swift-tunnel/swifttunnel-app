import type { ReactNode } from "react";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { ErrorBanner } from "./ErrorBanner";
import type { IconName } from "./Icon";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  onClose: () => void;
  onConfirm: () => void;
  busy?: boolean;
  error?: string | null;
  tone?: "neutral" | "warning" | "danger";
  icon?: IconName;
  children?: ReactNode;
}

/** One compact confirmation layout, including a safe initial keyboard focus. */
export function ConfirmDialog({
  open, title, description, confirmLabel, cancelLabel = "Cancel", onClose,
  onConfirm, busy = false, error, tone = "neutral", icon, children,
}: ConfirmDialogProps) {
  return <Dialog open={open} onClose={onClose} title={title} description={description}
    maxWidth={420} dismissible={!busy} tone={tone}
    icon={icon ?? (tone === "danger" ? "trash" : tone === "warning" ? "warning" : "info")}>
    <div className="flex flex-col gap-4">
      {children}
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] gap-2.5 pt-1">
        <Button type="button" variant="secondary" disabled={busy} data-dialog-autofocus
          className="h-auto min-h-10 px-3 py-2.5 [&>span]:leading-5" onClick={onClose}>{cancelLabel}</Button>
        <Button type="button" variant={tone === "danger" ? "destructive" : "primary"}
          loading={busy} className="h-auto min-h-10 px-3 py-2.5 [&>span]:leading-5"
          onClick={onConfirm}>{confirmLabel}</Button>
      </div>
    </div>
  </Dialog>;
}
