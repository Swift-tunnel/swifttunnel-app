import type { ReactNode } from "react";
import { Icon, Spinner } from "../ui";

export const iconButtonClass =
  "grid h-[30px] w-[30px] shrink-0 place-items-center rounded-[var(--radius-button)] text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary focus-visible:outline focus-visible:outline-1 focus-visible:outline-border-focus disabled:cursor-not-allowed disabled:opacity-40";

/** A calm progress or confirmation line. Failures use ErrorBanner instead. */
export function Notice({ children, busy, inset }: { children: ReactNode; busy?: boolean; inset?: boolean }) {
  return <p role="status" className={`flex items-center gap-2.5 rounded-[var(--radius-card)] px-4 py-2.5 text-[12px] leading-snug text-text-secondary ${inset ? "bg-bg-base" : "bg-bg-card"}`}>
    {busy ? <Spinner size={12} /> : <Icon name="info" size={14} className="shrink-0 text-text-muted" />}
    <span className="min-w-0">{children}</span>
  </p>;
}
