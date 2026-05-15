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
  const track = size === "sm" ? { w: 26, h: 15 } : { w: 30, h: 17 };
  const thumb = size === "sm" ? 11 : 13;
  const pad = (track.h - thumb) / 2;

  return (
    <button
      role="switch"
      aria-checked={enabled}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!enabled)}
      className="relative shrink-0 rounded-full transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-accent-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[color:var(--color-bg-base)] disabled:cursor-not-allowed disabled:opacity-50"
      style={{
        width: track.w,
        height: track.h,
        backgroundColor: enabled
          ? "var(--color-accent-primary)"
          : "var(--color-bg-elevated)",
        boxShadow: enabled
          ? "inset 0 1px 0 rgba(255,255,255,0.5), 0 0 0 1px rgba(255,255,255,0.05)"
          : "inset 0 1px 0 rgba(255,255,255,0.03), inset 0 0 0 1px var(--color-border-default)",
      }}
    >
      <span
        className="absolute rounded-full transition-all duration-200 ease-out"
        style={{
          width: thumb,
          height: thumb,
          top: pad,
          left: pad,
          backgroundColor: enabled ? "#0a0a0a" : "var(--color-text-muted)",
          transform: enabled
            ? `translateX(${track.w - thumb - pad * 2}px)`
            : "translateX(0)",
          boxShadow: enabled
            ? "0 1px 2px rgba(0,0,0,0.5)"
            : "0 1px 1px rgba(0,0,0,0.3)",
        }}
      />
    </button>
  );
}
