import type { ReactNode, SelectHTMLAttributes } from "react";
import { Icon } from "./Icon";

/** Text boxes in a dialog form, matching the preset dialogs. */
export const fieldClass =
  "h-9 w-full rounded-[9px] border border-border-subtle bg-bg-base px-3 text-[12.5px] text-text-primary outline-none transition-colors placeholder:text-text-dimmed focus-visible:border-border-focus disabled:cursor-not-allowed disabled:opacity-50";

/** Small boxes that sit on a card: search, a flag's value, a frame limit. */
export const compactFieldClass =
  "h-[30px] rounded-[var(--radius-input)] border border-border-default bg-bg-elevated px-2.5 text-[11.5px] text-text-primary outline-none transition-colors placeholder:text-text-dimmed focus-visible:border-border-focus disabled:cursor-not-allowed disabled:opacity-50";

interface FieldProps {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}

/** A labelled control in a dialog form. */
export function Field({ label, hint, children, className }: FieldProps) {
  return (
    <label className={`flex min-w-0 flex-col gap-1.5 ${className ?? ""}`}>
      <span className="text-[11px] font-medium text-text-secondary">{label}</span>
      {children}
      {hint && (
        <span className="text-[11px] leading-snug text-text-muted">{hint}</span>
      )}
    </label>
  );
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  /** Fill the form's width. Without it every dropdown is the same width, so a column of them lines up. */
  block?: boolean;
  /** Only for a dropdown that shares its slot with a second control. */
  width?: number;
}

/**
 * The native dropdown, so the keyboard and screen readers work as usual,
 * wearing the app's own face instead of the browser's.
 */
export function Select({ block, width = 190, className, children, ...rest }: SelectProps) {
  return (
    <span
      className={`relative inline-flex ${block ? "w-full" : ""} ${className ?? ""}`}
      style={block ? undefined : { width }}
    >
      <select
        {...rest}
        className={`w-full cursor-pointer appearance-none truncate pr-8 [color-scheme:dark] ${
          block ? fieldClass : `${compactFieldClass} font-medium`
        }`}
      >
        {children}
      </select>
      <Icon
        name="chevron-down"
        size={12}
        strokeWidth={2.2}
        className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted"
      />
    </span>
  );
}
