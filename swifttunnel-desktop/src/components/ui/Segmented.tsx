interface SegmentedProps<T extends string> {
  options: T[] | { value: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
  size?: "sm" | "md";
  disabled?: boolean;
  /** Names the group for screen readers when no visible label sits beside it. */
  ariaLabel?: string;
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  size = "md",
  disabled,
  ariaLabel,
}: SegmentedProps<T>) {
  const items = options.map((o) =>
    typeof o === "string" ? { value: o, label: o } : o,
  );
  const sizeClass = size === "sm" ? "h-6 text-[10px] px-2" : "h-7 text-[11px] px-2.5";

  return (
    <div
      role="group"
      aria-label={ariaLabel}
      className="inline-flex rounded-[var(--radius-button)] p-0.5"
      style={{
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
            className={`${sizeClass} whitespace-nowrap rounded-[3px] font-medium transition-colors duration-100 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50`}
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
