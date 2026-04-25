import type { ReactNode } from "react";
import { Button } from "./Button";
import { Spinner } from "./Spinner";

interface EmptyStateProps {
  icon?: ReactNode;
  loading?: boolean;
  title: string;
  description?: string;
  action?: { label: string; onClick: () => void };
}

export function EmptyState({
  icon,
  loading,
  title,
  description,
  action,
}: EmptyStateProps) {
  return (
    <div
      className="flex flex-col items-center gap-3 rounded-[var(--radius-card)] px-6 py-10"
      style={{
        backgroundColor: "var(--color-bg-card)",
        border: "1px solid var(--color-border-subtle)",
      }}
    >
      <div
        className="flex h-10 w-10 items-center justify-center rounded-full"
        style={{ backgroundColor: "var(--color-bg-elevated)" }}
      >
        {loading ? (
          <Spinner size={18} color="var(--color-text-muted)" />
        ) : (
          icon || (
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="var(--color-text-muted)"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v4M12 16h.01" />
            </svg>
          )
        )}
      </div>
      <div className="text-center">
        <div className="text-[13px] font-medium text-text-primary">{title}</div>
        {description && (
          <div className="mt-1 text-[11px] text-text-muted">{description}</div>
        )}
      </div>
      {action && !loading && (
        <Button variant="secondary" size="sm" onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  );
}
