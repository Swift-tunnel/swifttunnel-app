import { type ReactNode } from "react";

export function SectionHeader({
  label,
  tag,
  noMargin,
  action,
}: {
  label: string;
  tag?: string;
  noMargin?: boolean;
  action?: ReactNode;
}) {
  return (
    <div className={`${noMargin ? "" : "mb-2"} flex items-center gap-2`}>
      <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-secondary">
        {label}
      </h3>
      {tag && (
        <span className="text-[10px] font-medium text-text-dimmed">{tag}</span>
      )}
      {action && <span className="ml-auto">{action}</span>}
    </div>
  );
}
