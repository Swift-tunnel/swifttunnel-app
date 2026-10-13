interface SegmentedProps<T extends string> {
  options: T[] | { value: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
  size?: "sm" | "md";
  disabled?: boolean;
  /** Names the group for screen readers when no visible label sits beside it. */
  ariaLabel?: string;
  /** A fixed width, with the spare room shared between the choices. Without it the switch is as wide as its labels. */
  width?: number;
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  size = "md",
  disabled,
  ariaLabel,
  width,
}: SegmentedProps<T>) {
  const items = options.map((o) =>
    typeof o === "string" ? { value: o, label: o } : o,
  );
  const sizeClass = size === "sm" ? "h-5 text-[10px] px-2" : "h-6 text-[11px] px-2.5";

  return (
    <div
      role="group"
      aria-label={ariaLabel}
      className={`${width ? "flex" : "inline-flex"} shrink-0 rounded-[var(--radius-button)] p-0.5`}
      style={{
        width,
        backgroundColor: "var(--color-bg-elevated)",
        border: "1px solid var(--color-border-default)",
      }}
    >
      {items.map((item) => {
        const active = value === item.value;
        return (
          <button
            key={item.value}
            type="button"
            disabled={disabled}
            aria-pressed={active}
            onClick={() => onChange(item.value)}
            className={`${sizeClass} ${width ? "flex-auto" : ""} whitespace-nowrap rounded-[5px] font-medium transition-colors duration-100 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50`}
            style={{
              backgroundColor: active
                ? "var(--color-accent-primary)"
                : "transparent",
              color: active ? "#000000" : "var(--color-text-muted)",
            }}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}
