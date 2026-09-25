interface ToggleProps {
  enabled: boolean;
  onChange: (value: boolean) => void;
  size?: "sm" | "md";
  disabled?: boolean;
  ariaLabel?: string;
}

/**
 * On/off switch in the ExitLag client's style: a wide pill that turns green
 * when on, so the state reads at a glance from across a settings list.
 */
export function Toggle({
  enabled,
  onChange,
  size = "md",
  disabled,
  ariaLabel,
}: ToggleProps) {
  const track = size === "sm" ? { w: 34, h: 19 } : { w: 40, h: 22 };
  const thumb = size === "sm" ? 13 : 16;
  const pad = (track.h - thumb) / 2;

  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!enabled)}
      className="relative shrink-0 rounded-full transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-accent-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[color:var(--color-bg-base)] disabled:cursor-not-allowed disabled:opacity-50"
      style={{
        width: track.w,
        height: track.h,
        backgroundColor: enabled ? "var(--color-status-connected)" : "#3a3a42",
      }}
    >
      <span
        className="absolute rounded-full transition-transform duration-200 ease-out"
        style={{
          width: thumb,
          height: thumb,
          top: pad,
          left: pad,
          backgroundColor: enabled ? "#ffffff" : "#d4d4d8",
          transform: enabled
            ? `translateX(${track.w - thumb - pad * 2}px)`
            : "translateX(0)",
          boxShadow: "0 1px 2px rgba(0,0,0,0.35)",
        }}
      />
    </button>
  );
}
