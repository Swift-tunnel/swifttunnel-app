import type { ReactNode } from "react";

interface SectionHeaderProps {
  label: string;
  tag?: string;
  action?: ReactNode;
  description?: string;
  className?: string;
}

export function SectionHeader({
  label,
  tag,
  action,
  description,
  className,
}: SectionHeaderProps) {
  return (
    <div className={`mb-2.5 ${className ?? ""}`}>
      <div className="flex items-center gap-2">
        <h3 className="text-[10.5px] font-semibold uppercase tracking-[0.12em] text-text-secondary">
          {label}
        </h3>
        {tag && (
          <span
            className="rounded-[3px] px-1.5 py-0.5 text-[9.5px] font-medium uppercase tracking-[0.08em]"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              color: "var(--color-text-dimmed)",
            }}
          >
            {tag}
          </span>
        )}
        {action && <span className="ml-auto">{action}</span>}
      </div>
      {description && (
        <p className="mt-1 text-[11px] text-text-muted">{description}</p>
      )}
    </div>
  );
}
