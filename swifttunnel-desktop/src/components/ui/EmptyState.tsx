import type { ReactNode } from "react";
import { Button } from "./Button";
import { Spinner } from "./Spinner";
import { Icon } from "./Icon";

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
      <div className="icon-orb flex h-10 w-10 items-center justify-center">
        {loading ? (
          <Spinner size={18} color="var(--color-text-muted)" />
        ) : (
          icon || (
            <Icon
              name="alert"
              size={18}
              strokeWidth={1.8}
              style={{ color: "var(--color-text-muted)" }}
            />
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
