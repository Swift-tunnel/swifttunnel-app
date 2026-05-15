import type { ReactNode } from "react";

interface SectionHeaderProps {
  label: string;
  tag?: string;
  action?: ReactNode;
  description?: string;
  className?: string;
  size?: "sm" | "md";
}

export function SectionHeader({
  label,
  tag,
  action,
  description,
  className,
  size = "md",
}: SectionHeaderProps) {
  const titleSize = size === "sm" ? "text-[11px]" : "text-[12.5px]";
  return (
    <div className={`mb-2.5 ${className ?? ""}`}>
      <div className="flex items-center gap-2">
        <h3
          className={`${titleSize} font-semibold text-text-primary`}
          style={{ letterSpacing: "-0.005em" }}
        >
          {label}
        </h3>
        {tag && (
          <span
            className="rounded-[4px] px-1.5 py-[2px] font-mono text-[9.5px] font-medium"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              color: "var(--color-text-muted)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            {tag}
          </span>
        )}
        {action && <span className="ml-auto">{action}</span>}
      </div>
      {description && (
        <p className="mt-1 text-[11.5px] leading-snug text-text-muted">
          {description}
        </p>
      )}
    </div>
  );
}
