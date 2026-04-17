import type { ReactNode } from "react";

interface MetricGridProps {
  cols: 2 | 3 | 4;
  children: ReactNode;
}

export function MetricGrid({ cols, children }: MetricGridProps) {
  const colClass = {
    2: "grid-cols-2",
    3: "grid-cols-3",
    4: "grid-cols-4",
  }[cols];

  return (
    <div
      className={`grid ${colClass} gap-px overflow-hidden rounded-[var(--radius-card)]`}
      style={{ backgroundColor: "var(--color-border-subtle)" }}
    >
      {children}
    </div>
  );
}

interface MetricCellProps {
  label: string;
  value: ReactNode;
  unit?: string;
  accent?: boolean;
  color?: string;
}

export function MetricCell({
  label,
  value,
  unit,
  accent,
  color,
}: MetricCellProps) {
  return (
    <div
      className="flex flex-col gap-0.5 px-3 py-2.5"
      style={{ backgroundColor: "var(--color-bg-card)" }}
    >
      <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <div className="flex items-baseline gap-1">
        <span
          className="font-mono text-[15px] font-semibold"
          style={{
            color: color || (accent ? "var(--color-status-warning)" : "var(--color-text-primary)"),
          }}
        >
          {value}
        </span>
        {unit && (
          <span className="text-[10px] font-medium text-text-muted">{unit}</span>
        )}
      </div>
    </div>
  );
}
