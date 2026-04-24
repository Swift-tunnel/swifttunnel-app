interface ToggleProps {
  enabled: boolean;
  onChange: (value: boolean) => void;
  size?: "sm" | "md";
  disabled?: boolean;
  ariaLabel?: string;
}

export function Toggle({
  enabled,
  onChange,
  size = "md",
  disabled,
  ariaLabel,
}: ToggleProps) {
  const track = size === "sm" ? { w: 26, h: 15 } : { w: 32, h: 18 };
  const thumb = size === "sm" ? 11 : 14;
  const pad = (track.h - thumb) / 2;

  return (
    <button
      role="switch"
      aria-checked={enabled}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!enabled)}
      className="relative shrink-0 rounded-full transition-colors duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-accent-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[color:var(--color-bg-base)] disabled:cursor-not-allowed disabled:opacity-50"
      style={{
        width: track.w,
        height: track.h,
        backgroundColor: enabled
          ? "var(--color-accent-primary)"
          : "var(--color-bg-elevated)",
        border: `1px solid ${enabled ? "var(--color-accent-primary)" : "var(--color-border-default)"}`,
      }}
    >
      <span
        className="absolute rounded-full transition-transform duration-150 ease-out"
        style={{
          width: thumb,
          height: thumb,
          top: pad - 1,
          left: pad - 1,
          backgroundColor: enabled ? "#000000" : "var(--color-text-muted)",
          transform: enabled
            ? `translateX(${track.w - thumb - pad * 2}px)`
            : "translateX(0)",
          boxShadow: "none",
        }}
      />
    </button>
  );
}
