import type { ReactNode } from "react";

interface StatDisplayProps {
  label: string;
  value: ReactNode;
  unit?: string;
  color?: string;
  mono?: boolean;
  size?: "sm" | "md" | "lg" | "xl";
}

const sizes = {
  sm: "text-[13px]",
  md: "text-[15px]",
  lg: "text-[22px] leading-[1.1]",
  xl: "text-[42px] leading-[1] font-semibold",
} as const;

export function StatDisplay({
  label,
  value,
  unit,
  color,
  mono = true,
  size = "md",
}: StatDisplayProps) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <div className="flex items-baseline gap-1">
        <span
          className={`font-semibold ${sizes[size]} ${mono ? "font-mono" : ""}`}
          style={{ color: color || "var(--color-text-primary)" }}
        >
          {value}
        </span>
        {unit && (
          <span className="text-[11px] font-medium text-text-muted">
            {unit}
          </span>
        )}
      </div>
    </div>
  );
}
