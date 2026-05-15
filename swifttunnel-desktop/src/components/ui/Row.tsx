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
      className={`group flex items-center justify-between gap-4 transition-colors duration-100 ${
        dense ? "px-3.5 py-2" : "px-3.5 py-2.5"
      }`}
    >
      <div className="flex min-w-0 flex-col gap-[3px]">
        <span className="flex items-center gap-1.5 text-[12.5px] font-medium leading-tight text-text-primary">
          {label}
          {tooltip}
        </span>
        {desc && (
          <span className="text-[11px] leading-tight text-text-muted">
            {desc}
          </span>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}
