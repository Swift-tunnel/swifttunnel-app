import type { ReactNode } from "react";

interface RowProps {
  label: string;
  desc?: string;
  tooltip?: ReactNode;
  children: ReactNode;
  dense?: boolean;
}

export function Row({ label, desc, tooltip, children, dense }: RowProps) {
  return (
    <div
      className={`flex items-center justify-between gap-4 ${dense ? "px-4 py-2.5" : "px-4 py-3"}`}
    >
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="flex items-center gap-1.5 text-[13px] font-medium text-text-primary">
          {label}
          {tooltip}
        </span>
        {desc && <span className="text-[11px] text-text-muted">{desc}</span>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}
