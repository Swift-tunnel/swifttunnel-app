import type { ReactNode } from "react";

interface ErrorBannerProps {
  children: ReactNode;
  tone?: "error" | "warning" | "info";
  action?: ReactNode;
}

export function ErrorBanner({
  children,
  tone = "error",
  action,
}: ErrorBannerProps) {
  const tones = {
    error: {
      bg: "var(--color-status-error-soft-10)",
      border: "var(--color-status-error-soft-20)",
      fg: "var(--color-status-error)",
    },
    warning: {
      bg: "var(--color-status-warning-soft-10)",
      border: "rgba(234, 179, 8, 0.2)",
      fg: "var(--color-status-warning)",
    },
    info: {
      bg: "var(--color-accent-primary-soft-10)",
      border: "var(--color-accent-primary-soft-20)",
      fg: "var(--color-text-primary)",
    },
  };
  const c = tones[tone];

  return (
    <div
      className="flex items-center justify-between gap-3 rounded-[var(--radius-card)] px-3.5 py-2.5 text-[12px]"
      style={{
        backgroundColor: c.bg,
        border: `1px solid ${c.border}`,
        color: c.fg,
      }}
    >
      <span className="flex-1">{children}</span>
      {action}
    </div>
  );
}
